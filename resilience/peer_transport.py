"""mTLS-only JSON transport for independently running PBFT replicas."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import http.client
import json
import ssl

from .consensus import PBFTConsensus, PBFTMessage
from .replica import PBFTReplica, ProtocolError


class PeerRequestError(RuntimeError):
    """Base transport error returned when a peer answers an HTTP request."""


class PeerRejectedError(PeerRequestError):
    """The peer received the request but rejected its content or authorization."""


class PeerUnavailableError(PeerRequestError):
    """The peer endpoint is live but cannot currently service a request."""


def _message_from(body: dict) -> PBFTMessage:
    fields = {"sender", "phase", "view", "sequence", "digest", "signature"}
    if set(body) not in (fields, fields | {"prepared_digest"}):
        raise ValueError("invalid PBFT message fields")
    return PBFTMessage(**{**body, "prepared_digest": body.get("prepared_digest", "")})


def make_peer_handler(consensus: PBFTConsensus | None = None,
                      replica: PBFTReplica | None = None):
    class Handler(BaseHTTPRequestHandler):
        def _send(self, status: int, value: dict) -> None:
            payload = json.dumps(value, separators=(",", ":")).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(payload)

        def _body(self) -> dict:
            if self.headers.get("Content-Type", "").split(";")[0].strip().lower() != "application/json":
                raise ValueError("application/json required")
            size = int(self.headers.get("Content-Length", "0"))
            if size < 1 or size > 65536:
                raise ValueError("request must be between 1 and 65536 bytes")
            value = json.loads(self.rfile.read(size))
            if not isinstance(value, dict):
                raise ValueError("JSON object required")
            return value

        def _member_identity(self) -> str | None:
            cert = self.connection.getpeercert()
            names = [value for rdn in cert.get("subject", ())
                     for key, value in rdn if key == "commonName"]
            members = replica.node_ids if replica else (consensus.node_ids if consensus else [])
            return names[0] if len(names) == 1 and names[0] in members else None

        def do_POST(self) -> None:
            if replica and replica.faulted:
                self._send(503, {"error": "replica stopped after durable-state failure"})
                return
            member_identity = self._member_identity()
            if member_identity is None:
                self._send(403, {"error": "mTLS certificate is not a committee member"})
                return
            try:
                body = self._body()
                if replica:
                    self._post_replica(body, member_identity)
                elif self.path == "/v1/consensus" and consensus:
                    message = _message_from(body.get("message", body))
                    if not consensus.verify_message(message):
                        self._send(401, {"error": "invalid PBFT signature or message"})
                        return
                    received = getattr(self.server, "received_messages", None)
                    if received is not None:
                        received.append(message)
                    self._send(202, {"accepted": True, "phase": message.phase,
                                     "view": message.view, "sequence": message.sequence})
                else:
                    self._send(404, {"error": "not found"})
            except (ValueError, TypeError, KeyError, json.JSONDecodeError, ProtocolError) as exc:
                self._send(400, {"error": str(exc)})

        def _post_replica(self, body: dict, member_identity: str) -> None:
            assert replica is not None
            if self.path == "/v1/observe":
                if set(body) != {"scenario", "target", "sequence"}:
                    raise ValueError("scenario, target, and sequence required")
                if body["scenario"] not in {"genuine-compromise", "false-evidence", "silent-node", "block-vote", "two-compromised", "prepared-primary-failure", "healthy-window"}:
                    raise ValueError("unsupported safe simulation scenario")
                observation = replica.make_observation(body["scenario"], body["target"], body["sequence"])
                self._send(200, {"observation": observation})
                return
            if self.path == "/v1/proposal":
                if set(body) != {"sequence", "proposal"} or not isinstance(body["proposal"], dict):
                    raise ValueError("sequence and proposal required")
                state = replica.rounds.get(body["sequence"])
                view = state.view if state else 0
                primary = replica.node_ids[view % len(replica.node_ids)]
                if member_identity != primary:
                    raise ProtocolError("only the mTLS-authenticated primary may cache a proposal")
                self._send(200, replica.cache_proposal(body["sequence"], body["proposal"]))
                return
            if self.path == "/v1/checkpoint":
                self._send(200, replica.install_checkpoint(body))
                return
            if self.path == "/v1/pre-prepare":
                if set(body) != {"sequence"}:
                    raise ValueError("sequence required")
                message = replica.create_pre_prepare(body["sequence"])
                self._send(200, {"message": message.__dict__})
                return
            if self.path == "/v1/view-change":
                if set(body) != {"sequence", "view"}:
                    raise ValueError("sequence and view required")
                self._send(200, replica.create_view_change_bundle(
                    body["sequence"], body["view"]))
                return
            if self.path == "/v1/new-view":
                if set(body) != {"sequence", "view"}:
                    raise ValueError("sequence and view required")
                self._send(200, replica.create_new_view(body["sequence"], body["view"]))
                return
            if self.path == "/v1/consensus":
                allowed_fields = ({"message"}, {"message", "proposal"},
                                  {"message", "certificate"},
                                  {"message", "proposal", "certificate"},
                                  {"message", "prepared_certificate"},
                                  {"message", "proposal", "prepared_certificate"},
                                  {"message", "certificate", "prepared_certificate"},
                                  {"message", "proposal", "certificate", "prepared_certificate"})
                if set(body) not in allowed_fields:
                    raise ValueError("message and optional proposal/certificate required")
                message = _message_from(body["message"])
                result = replica.handle_message(message, body.get("proposal"),
                                                body.get("certificate"),
                                                body.get("prepared_certificate"))
                self._send(202, result)
                return
            self._send(404, {"error": "not found"})

        def do_GET(self) -> None:
            if replica and replica.faulted:
                self._send(503, {"error": "replica stopped after durable-state failure"})
                return
            if self._member_identity() is None:
                self._send(403, {"error": "mTLS certificate is not a committee member"})
            elif self.path == "/healthz":
                members = replica.node_ids if replica else consensus.node_ids
                self._send(200, {"status": "ready", "trusted_nodes": len(members)})
            elif self.path.startswith("/v1/state") and replica:
                sequence = 1
                if "?" in self.path:
                    from urllib.parse import parse_qs, urlsplit
                    sequence = int(parse_qs(urlsplit(self.path).query).get("sequence", ["1"])[0])
                self._send(200, replica.state_report(sequence))
            elif self.path == "/v1/checkpoint" and replica:
                self._send(200, {"checkpoint": replica.latest_checkpoint()})
            elif self.path.startswith("/v1/checkpoints") and replica:
                from urllib.parse import parse_qs, urlsplit
                after = int(parse_qs(urlsplit(self.path).query).get("after", ["0"])[0])
                self._send(200, {"checkpoints": replica.committed_checkpoints_after(after)})
            else:
                self._send(404, {"error": "not found"})

        def log_message(self, fmt: str, *args) -> None:
            pass

    return Handler


def create_mtls_server(host: str, port: int, cert_file: str, key_file: str,
                       ca_file: str, consensus: PBFTConsensus | None = None,
                       replica: PBFTReplica | None = None) -> ThreadingHTTPServer:
    """Create HTTPS server with mandatory CA-verified client certificates."""
    if (consensus is None) == (replica is None):
        raise ValueError("provide exactly one consensus model or replica")
    server = ThreadingHTTPServer((host, port), make_peer_handler(consensus, replica))
    server.received_messages = []
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=cert_file, keyfile=key_file)
    context.load_verify_locations(cafile=ca_file)
    context.verify_mode = ssl.CERT_REQUIRED
    server.socket = context.wrap_socket(server.socket, server_side=True)
    return server


def send_peer_json(host: str, port: int, ca_file: str, cert_file: str,
                   key_file: str, path: str, body: dict | None = None,
                   timeout: float = 5) -> dict:
    """Make one committee-member mTLS request; the signed message has its own identity."""
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ca_file)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=cert_file, keyfile=key_file)
    connection = http.client.HTTPSConnection(host, port, context=context, timeout=timeout)
    try:
        if body is None:
            connection.request("GET", path)
        else:
            connection.request("POST", path, body=json.dumps(body),
                               headers={"Content-Type": "application/json"})
        response = connection.getresponse()
        data = json.loads(response.read())
        if response.status not in {200, 202}:
            error_type = PeerUnavailableError if response.status >= 500 else PeerRejectedError
            raise error_type(f"peer rejected request ({response.status}): {data.get('error')}")
        return data
    finally:
        connection.close()


def send_mtls_message(host: str, port: int, ca_file: str,
                      cert_file: str, key_file: str,
                      message: PBFTMessage, timeout: float = 5) -> dict:
    return send_peer_json(host, port, ca_file, cert_file, key_file,
                          "/v1/consensus", {"message": message.__dict__}, timeout)
