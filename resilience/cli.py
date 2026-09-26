"""Command line entry point for the local resilience simulator."""

import argparse
import http.client
import json
import time

from .engine import ResilienceSimulator
from .experiments import SCENARIOS, run_experiment
from .dashboard import serve
from .dataset import download_dataset
from .health_records import import_public_encounters, health_summary
from .crypto_keys import NodeKeyring
from .consensus import PBFTConsensus
from .replica import PBFTReplica
from .cluster import NetworkPBFTCluster
from .engine import SERVICES, MAX_BYZANTINE_FAULTS
from .peer_transport import create_mtls_server
from .pki_tools import generate_dev_pki
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a contained cyber-resilience simulation")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("demo", help="run the synthetic application-compromise scenario")
    experiment = commands.add_parser("experiment", help="compare distributed and centralized models")
    experiment.add_argument("--repeats", type=int, default=3)
    experiment.add_argument("--scenario", choices=SCENARIOS, action="append")
    dashboard = commands.add_parser("serve", help="serve the loopback-only read-only dashboard")
    dashboard.add_argument("--port", type=int, default=8765)
    trigger = commands.add_parser("trigger", help="send a safe synthetic scenario to the local dashboard server")
    trigger.add_argument("scenario", choices=("genuine-compromise", "false-evidence",
                                                "silent-node", "block-vote", "two-compromised",
                                                "healthy-window"))
    trigger.add_argument("--port", type=int, default=8765)
    dataset = commands.add_parser("dataset", help="manage the local public clinical dataset")
    dataset.add_argument("action", choices=("fetch", "import", "summary"))
    keys = commands.add_parser("keys", help="generate local PBFT signing keys")
    keys.add_argument("action", choices=("generate",))
    keys.add_argument("--rotate", action="store_true", help="replace existing keys; all deployed public-key trust must be updated")
    peer = commands.add_parser("peer", help="run an mTLS-protected PBFT peer")
    peer.add_argument("action", choices=("serve",))
    peer.add_argument("--node-id", choices=tuple(SERVICES), required=True)
    peer.add_argument("--host", default="0.0.0.0")
    peer.add_argument("--port", type=int, default=8766)
    peer.add_argument("--pki-dir", default="work/pki")
    peer.add_argument("--key-dir", default="work/keys")
    peer.add_argument("--state-dir", default="work/replica-state",
                      help="durable directory; each node gets a separate SQLite state database")
    cluster = commands.add_parser("cluster", help="drive a round across running mTLS PBFT replicas")
    cluster.add_argument("action", choices=("simulate",))
    cluster.add_argument("scenario", choices=("genuine-compromise", "false-evidence",
                                                 "silent-node", "block-vote", "two-compromised",
                                                 "prepared-primary-failure", "healthy-window"))
    cluster.add_argument("--pki-dir", default="work/pki")
    cluster.add_argument("--key-dir", default="work/keys",
                         help="directory containing public/<node>.pub.pem verification keys")
    cluster.add_argument("--sequence", type=int, default=None,
                         help="positive unique request sequence (defaults to current epoch milliseconds)")
    cluster.add_argument("--ports", nargs=4, type=int,
                         default=[8766, 8767, 8768, 8769], metavar=("PORTAL", "IDENTITY", "RECORDS", "DATABASE"),
                         help="local peer ports in committee order; Kubernetes uses service port 8766")
    cluster.add_argument("--kubernetes", action="store_true",
                         help="use resilience-peer-<node> Kubernetes service DNS names")
    cluster.add_argument("--apply-kubernetes-response", action="store_true",
                         help="after a committed CONTAIN, control only the named synthetic workload in resilience-lab")
    cluster.add_argument("--trust-target", choices=tuple(SERVICES),
                         help="for healthy-window, name the member whose trust-gated Kubernetes recovery should advance")
    cluster.add_argument("--fail-check", choices=("integrity", "health", "behavior"),
                         action="append", default=[],
                         help="simulate a failed post-restore validation check; leaves target quarantined")
    pki = commands.add_parser("pki", help="create throwaway local development certificates")
    pki.add_argument("action", choices=("generate-dev",))
    pki.add_argument("--rotate", action="store_true", help="replace existing local development certificates")
    simulate = commands.add_parser("simulate", help="run one synthetic scenario")
    simulate.add_argument("scenario", choices=("genuine-compromise", "false-evidence",
                                                 "silent-node", "block-vote", "two-compromised",
                                                 "healthy-window"))
    args = parser.parse_args()
    if args.command == "serve":
        serve(args.port)
        return
    if args.command == "dataset":
        if args.action == "fetch":
            result = download_dataset()
        elif args.action == "import":
            result = import_public_encounters()
        else:
            result = health_summary()
    elif args.command == "keys":
        root = Path(__file__).resolve().parent.parent
        keyring = NodeKeyring.generate(list(SERVICES))
        private_dir = root / "work" / "keys" / "private"
        public_dir = root / "work" / "keys" / "public"
        existing = [private_dir / f"{node_id}.pem" for node_id in SERVICES]
        existing = [path for path in existing if path.exists()]
        if existing and not args.rotate:
            raise SystemExit("PBFT keys already exist. Use `keys generate --rotate` only when you intend to update every peer's trusted public key.")
        private_dir.mkdir(parents=True, exist_ok=True)
        public_dir.mkdir(parents=True, exist_ok=True)
        for node_id in SERVICES:
            (private_dir / f"{node_id}.pem").write_bytes(keyring.private_pem(node_id))
            (public_dir / f"{node_id}.pub.pem").write_bytes(keyring.public_pem(node_id))
        result = {"generated": list(SERVICES), "private_directory": str(private_dir),
                  "public_directory": str(public_dir),
                  "warning": "Development keys only. Keep private keys out of version control and use a managed KMS/HSM for production."}
    elif args.command == "pki":
        root = Path(__file__).resolve().parent.parent
        result = generate_dev_pki(root / "work" / "pki", force=args.rotate)
    elif args.command == "peer":
        root = Path(__file__).resolve().parent.parent
        key_dir = root / args.key_dir
        pki_dir = root / args.pki_dir
        private_path = key_dir / "private" / f"{args.node_id}.pem"
        public_paths = {node_id: key_dir / "public" / f"{node_id}.pub.pem" for node_id in SERVICES}
        keyring = NodeKeyring.load(args.node_id, private_path, public_paths)
        state_dir = Path(args.state_dir)
        if not state_dir.is_absolute():
            state_dir = root / state_dir
        replica = PBFTReplica(args.node_id, keyring, list(SERVICES), MAX_BYZANTINE_FAULTS,
                              state_db=state_dir / f"{args.node_id}.sqlite3")
        server = create_mtls_server(args.host, args.port,
                                    str(pki_dir / f"{args.node_id}.crt"),
                                    str(pki_dir / f"{args.node_id}.key"),
                                    str(pki_dir / "ca.crt"), replica=replica)
        print(f"PBFT peer {args.node_id} listening with mTLS on {args.host}:{args.port}")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("Stopping PBFT peer.")
        finally:
            server.server_close()
        return
    elif args.command == "cluster":
        if args.apply_kubernetes_response and not args.kubernetes:
            parser.error("--apply-kubernetes-response requires --kubernetes and in-cluster RBAC")
        if args.trust_target and args.scenario != "healthy-window":
            parser.error("--trust-target is only valid with healthy-window")
        root = Path(__file__).resolve().parent.parent
        pki_dir = Path(args.pki_dir)
        if not pki_dir.is_absolute():
            pki_dir = root / pki_dir
        key_dir = Path(args.key_dir)
        if not key_dir.is_absolute():
            key_dir = root / key_dir
        hosts = ({node: f"resilience-peer-{node}.resilience.svc" for node in SERVICES}
                 if args.kubernetes else None)
        ports = ({node: 8766 for node in SERVICES} if args.kubernetes
                 else dict(zip(SERVICES, args.ports)))
        sequence = args.sequence if args.sequence is not None else int(time.time() * 1000)
        validation = {name: name not in args.fail_check
                      for name in ("integrity", "health", "behavior")}
        result = NetworkPBFTCluster(pki_dir, hosts=hosts, ports=ports,
                                    public_key_dir=key_dir / "public",
                                    apply_kubernetes_response=args.apply_kubernetes_response).run(
                                        args.scenario, sequence, validation,
                                        trust_target=args.trust_target)
    elif args.command == "trigger":
        connection = http.client.HTTPConnection("127.0.0.1", args.port, timeout=5)
        try:
            body = json.dumps({"scenario": args.scenario})
            connection.request("POST", "/api/simulate", body=body,
                               headers={"Content-Type": "application/json"})
            response = connection.getresponse()
            result = json.loads(response.read())
            if response.status != 200:
                raise SystemExit(result.get("error", f"local simulator returned HTTP {response.status}"))
        except OSError as exc:
            raise SystemExit(f"Cannot reach local simulator at 127.0.0.1:{args.port}: {exc}") from exc
        finally:
            connection.close()
    elif args.command == "experiment":
        result = run_experiment(args.repeats, tuple(args.scenario) if args.scenario else SCENARIOS)
    else:
        scenario = "genuine-compromise" if args.command == "demo" else args.scenario
        result = ResilienceSimulator().run(scenario)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
