"""Loopback-only, read-only status dashboard for local simulation runs."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from urllib.parse import urlparse

from .boundary import run_boundary_sweep
from .engine import ResilienceSimulator
from .experiments import run_experiment
from .health_records import health_summary


PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Cyber-resilience simulator</title><style>
*{box-sizing:border-box}body{margin:0;background:#f3f6fa;color:#132238;font:15px/1.5 system-ui,Segoe UI,sans-serif}
main{max-width:1050px;margin:36px auto;padding:0 20px}h1{margin-bottom:4px}p{color:#526277}.badge{display:inline-block;border:1px solid #b9c8d9;border-radius:20px;padding:2px 10px;font-size:12px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:14px}.card,section{background:white;border:1px solid #dce4ed;border-radius:12px;padding:18px;box-shadow:0 2px 8px #12243a0b}.card h2{font-size:18px;margin:0}.muted{color:#617287;font-size:13px}.meter{height:7px;border-radius:8px;background:#e8edf3;margin:9px 0}.meter span{height:100%;display:block;border-radius:8px;background:#14836c}section{margin-top:18px}pre{white-space:pre-wrap;overflow-wrap:anywhere;margin:0;font-size:13px}table{width:100%;border-collapse:collapse}td,th{text-align:left;padding:9px;border-bottom:1px solid #e8edf3}footer{margin:18px 0;color:#617287;font-size:12px}
</style></head><body><main><h1>Cyber-resilience simulator</h1><p>Local synthetic environment <span class="badge">read-only dashboard</span></p>
<section><h2>Resilience nodes</h2><p class="muted">Refreshes automatically. Response actions are not available in this page.</p><div class="grid" id="nodes"></div></section>
<section><h2>Latest simulation</h2><div id="latest" class="muted">No simulation has been run in this server session.</div><pre id="events"></pre><h3>Recovery metrics</h3><pre id="metrics"></pre><h3>Trust recovery windows</h3><pre id="trajectory"></pre></section>
<section><h2>Voting parameters</h2><p class="muted">Parameters used by this weighted-evidence demonstration gate.</p><table><thead><tr><th>Parameter</th><th>Value</th></tr></thead><tbody id="parameters"></tbody></table></section>
<section><h2>Synthetic scenarios</h2><p class="muted">Run from a terminal with <code>python -m resilience.cli trigger SCENARIO</code>. This page does not launch them.</p><table><thead><tr><th>Scenario</th><th>Behavior exercised</th></tr></thead><tbody><tr><td>genuine-compromise</td><td>Diverse anomaly findings, quorum, restore and trust-gated reintegration</td></tr><tr><td>false-evidence</td><td>One unsupported anomaly claim contradicted by signed normal findings</td></tr><tr><td>healthy-window</td><td>Signed normal observations recover reporter trust by one increment, with NOOP</td></tr><tr><td>silent-node</td><td>One replica silent; remaining three should commit</td></tr><tr><td>block-vote</td><td>Primary refuses; signed view change elects a new primary</td></tr><tr><td>two-compromised</td><td>Two Byzantine replicas exceed f=1; expected no commit</td></tr></tbody></table></section>
<section><h2>Distributed vs centralized baseline</h2><p class="muted">Modeled ticks on synthetic evidence; the centralized controller is an executed minimal baseline.</p><div style="overflow-x:auto"><table><thead><tr><th>Scenario</th><th>Architecture</th><th>Containment rate</th><th>False isolation</th><th>Missed containment</th><th>Availability</th></tr></thead><tbody id="comparison"></tbody></table></div></section>
<section><h2>Fault-tolerance boundary (n = 4)</h2><p class="muted">First number of compromised nodes k at which each attack succeeds, versus the BFT bound f = 1.</p><div style="overflow-x:auto"><table><thead><tr><th>Attack</th><th>Correct through k</th><th>First failure</th><th>Theory</th></tr></thead><tbody id="boundary"></tbody></table></div><pre id="central-compromised"></pre></section>
<section><h2>Clinical demo dataset</h2><p class="muted">Aggregate-only view. No patient or encounter rows are shown.</p><div id="health" class="grid"></div></section>
<footer>All attack scenarios are synthetic. The local signature keys, timing, and quorum model are for demonstration only.</footer></main>
<script>
async function refresh(){try{const r=await fetch('/api/state',{cache:'no-store'});const s=await r.json();document.querySelector('#nodes').innerHTML='';for(const n of s.nodes){const d=document.createElement('article');d.className='card';const h=document.createElement('h2');h.textContent=n.service;const id=document.createElement('div');id.className='muted';id.textContent=n.node_id+' · '+n.stage;const m=document.createElement('div');m.className='meter';const b=document.createElement('span');b.style.width=n.trust+'%';m.append(b);const t=document.createElement('div');t.textContent='Trust '+n.trust+'/100 · '+(n.available?'available':'quarantined');d.append(h,id,m,t);document.querySelector('#nodes').append(d)}document.querySelector('#latest').textContent=s.latest?`${s.latest.scenario}: ${s.latest.decision} · evidence score ${s.latest.evidence_score} · corroboration ${s.latest.corroboration.verified_reporters}/${s.latest.corroboration.required_reporters}`:'No simulation has been run in this server session.';document.querySelector('#events').textContent=s.latest?s.latest.events.join('\\n'):'';const m=s.latest?s.latest.metrics:null;document.querySelector('#metrics').textContent=m?`Detect: ${m.time_to_detect_seconds}s · isolate: ${m.time_to_isolate_seconds ?? 'n/a'}s · recovery: ${m.recovery_time_seconds ?? 'n/a'}s · trust recovery: ${m.trust_recovery_windows} healthy windows (${m.trust_recovery_time_ticks} ticks) · final target: ${m.target_stage}, trust ${m.target_trust}/100 · trust changes ${JSON.stringify(s.latest.trust_updates)}`:'No recovery metrics yet.';document.querySelector('#trajectory').textContent=m&&m.trust_trajectory.length?m.trust_trajectory.map(x=>`window ${x.window}: trust ${x.trust}, stage ${x.stage}${x.promotion?' (promoted)':''}`).join('\\n'):'No trust recovery windows yet.';const pt=document.querySelector('#parameters');pt.innerHTML='';for(const [key,value] of Object.entries(s.decision_parameters)){const tr=document.createElement('tr');const a=document.createElement('td');a.textContent=key;const b=document.createElement('td');b.textContent=typeof value==='object'?JSON.stringify(value):value;tr.append(a,b);pt.append(tr)}const health=document.querySelector('#health');health.innerHTML='';const h=s.health;const cards=[['Encounter records',h.encounters],['Readmitted within 30 days',h.readmission['<30']||0],['Readmitted after 30 days',h.readmission['>30']||0],['No readmission',h.readmission['NO']||0]];for(const [label,value] of cards){const d=document.createElement('article');d.className='card';const n=document.createElement('h2');n.textContent=value;const l=document.createElement('div');l.className='muted';l.textContent=label;d.append(n,l);health.append(d)}}catch(e){document.querySelector('#latest').textContent='Waiting for local simulator…'}}
function row(body,vals){const tr=document.createElement('tr');for(const v of vals){const td=document.createElement('td');td.textContent=String(v);tr.append(td)}body.append(tr)}
async function loadComparison(){try{const r=await fetch('/api/comparison',{cache:'no-store'});const c=await r.json();const cb=document.querySelector('#comparison');cb.innerHTML='';for(const x of c.experiment.results){for(const a of ['distributed','centralized']){const m=x[a];row(cb,[x.scenario,a,m.containment_rate_percent+'%',m.false_isolation_rate_percent+'%',m.missed_containment_rate_percent+'%',m.mean_availability_percent+'%'])}}
const bb=document.querySelector('#boundary');bb.innerHTML='';const sw=c.boundary.sweeps[0];for(const [name,a] of Object.entries(sw.attacks)){row(bb,[name,a.largest_correct_k,a.first_failing_k===null?'none':a.first_failing_k,a.matches_theory?'liveness/safety limit as predicted':(a.exceeds_theory?'holds beyond f':'defect')])}
document.querySelector('#central-compromised').textContent='Compromised centralized controller: '+c.boundary.centralized_controller_compromised.map(x=>x.attack+' -> '+(x.correct?'correct':'FAILED')).join(' · ')}catch(e){document.querySelector('#comparison').textContent='Comparison unavailable'}}
refresh();loadComparison();setInterval(refresh,2000);
</script></body></html>"""


def _label(value: str) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")


def prometheus_metrics(simulator: ResilienceSimulator) -> str:
    """Prometheus text exposition for Grafana. Read-only view of simulator state."""
    lines = ["# HELP resilience_node_trust Continuous trust score (0-100) per node.",
             "# TYPE resilience_node_trust gauge"]
    nodes = list(simulator.nodes.values())
    for n in nodes:
        lines.append(f'resilience_node_trust{{node="{_label(n.node_id)}",service="{_label(n.service)}",stage="{_label(n.stage)}"}} {n.trust:.1f}')
    lines += ["# HELP resilience_node_available 1 if the node is serving traffic, 0 if quarantined.",
              "# TYPE resilience_node_available gauge"]
    for n in nodes:
        lines.append(f'resilience_node_available{{node="{_label(n.node_id)}"}} {1 if n.available else 0}')
    lines += ["# HELP resilience_incidents_total Incidents handled this server session.",
              "# TYPE resilience_incidents_total counter",
              f"resilience_incidents_total {len(simulator.incidents)}",
              "# HELP resilience_false_isolations_total Containments of a healthy target.",
              "# TYPE resilience_false_isolations_total counter",
              f"resilience_false_isolations_total {simulator.false_isolations}"]
    if simulator.incidents:
        m = simulator.report()["metrics"]
        for name, key, help_text in (
                ("resilience_time_to_detect_ticks", "time_to_detect_seconds", "Modeled ticks to detect (latest incident)."),
                ("resilience_time_to_isolate_ticks", "time_to_isolate_seconds", "Modeled ticks to isolate (latest incident)."),
                ("resilience_recovery_time_ticks", "recovery_time_seconds", "Modeled ticks to recover (latest incident)."),
                ("resilience_trust_recovery_ticks", "trust_recovery_time_ticks", "Modeled ticks of trust recovery (latest incident)."),
                ("resilience_availability_percent", "availability_percent", "Availability during the latest incident.")):
            if m.get(key) is not None:
                lines += [f"# HELP {name} {help_text}", f"# TYPE {name} gauge", f"{name} {m[key]}"]
    return "\n".join(lines) + "\n"


def make_handler(simulator: ResilienceSimulator):
    cache: dict = {}

    class Handler(BaseHTTPRequestHandler):
        def _send(self, status: int, body: bytes, content_type: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            path = urlparse(self.path).path
            if path == "/":
                self._send(200, PAGE.encode(), "text/html; charset=utf-8")
            elif path == "/api/state":
                nodes = [{"node_id": n.node_id, "service": n.service,
                          "trust": round(n.trust, 1), "stage": n.stage,
                          "available": n.available}
                         for n in simulator.nodes.values()]
                latest = simulator.report() if simulator.incidents else None
                body = json.dumps({"nodes": nodes, "latest": latest,
                                   "decision_parameters": simulator.voting_parameters(),
                                   "health": health_summary()}).encode()
                self._send(200, body, "application/json; charset=utf-8")
            elif path == "/api/comparison":
                if "comparison" not in cache:  # deterministic, so compute once per server run
                    cache["comparison"] = {"experiment": run_experiment(1),
                                           "boundary": run_boundary_sweep((4,))}
                self._send(200, json.dumps(cache["comparison"]).encode(), "application/json; charset=utf-8")
            elif path == "/metrics":
                self._send(200, prometheus_metrics(simulator).encode(), "text/plain; version=0.0.4; charset=utf-8")
            else:
                self._send(404, b"not found", "text/plain; charset=utf-8")

        def do_POST(self) -> None:
            # Command endpoint is intended for the local CLI, never exposed by the UI.
            if urlparse(self.path).path != "/api/simulate":
                self._send(404, b"not found", "text/plain; charset=utf-8")
                return
            if self.headers.get("Content-Type", "").split(";")[0].strip().lower() != "application/json":
                self._send(415, b"application/json required", "text/plain; charset=utf-8")
                return
            try:
                size = int(self.headers.get("Content-Length", "0"))
                if size < 1 or size > 2048:
                    raise ValueError("request body must be between 1 and 2048 bytes")
                payload = json.loads(self.rfile.read(size))
                if not isinstance(payload, dict) or set(payload) != {"scenario"}:
                    raise ValueError("expected JSON object with only a scenario field")
                result = simulator.run(payload["scenario"])
            except (ValueError, TypeError, json.JSONDecodeError) as exc:
                self._send(400, json.dumps({"error": str(exc)}).encode(), "application/json; charset=utf-8")
                return
            self._send(200, json.dumps(result).encode(), "application/json; charset=utf-8")

        def log_message(self, fmt: str, *args) -> None:
            pass

    return Handler


def serve(port: int = 8765) -> None:
    if not 1 <= port <= 65535:
        raise ValueError("port must be between 1 and 65535")
    server = ThreadingHTTPServer(("127.0.0.1", port), make_handler(ResilienceSimulator()))
    print(f"Read-only dashboard: http://127.0.0.1:{port}/")
    print("Trigger safe synthetic scenarios from another terminal with: python -m resilience.cli trigger SCENARIO")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Stopping dashboard server.")
    finally:
        server.server_close()
