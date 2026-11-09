"""PacketGuard dashboard server.

Serves the real-time monitoring UI and a small JSON API over a single shared
:class:`PacketGuardEngine`. To keep the project runnable on any machine with no
installs, this uses Python's standard-library HTTP server instead of Flask — the
planned ``templates/`` and ``static/`` layout is preserved and served from disk.

A background :class:`LiveDriver` generates mostly-normal traffic with attacks mixed
in, so the dashboard is alive the moment you open it. You can also trigger any
single attack on demand from the UI (``POST /api/inject``).

    python -m src.dashboard.app          # then open http://127.0.0.1:8000
"""

from __future__ import annotations

import json
import os
import random
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from ..engine import PacketGuardEngine

# scenarios live in the top-level simulations package; import defensively so the
# server still starts even if that package is missing.
try:
    from simulations import scenarios as scn
except Exception:  # pragma: no cover
    scn = None

HERE = os.path.dirname(__file__)
TEMPLATES = os.path.join(HERE, "templates")
STATIC = os.path.join(HERE, "static")

_CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".svg": "image/svg+xml",
    ".ico": "image/x-icon",
}

# Human-facing names for the inject buttons -> scenario callables.
SCENARIO_MAP = {
    "tampering": "scenario_tampering",
    "packet_drop": "scenario_packet_drop",
    "replay": "scenario_replay",
    "syn_flood": "scenario_syn_flood",
    "spam": "scenario_spam",
    "exfil": "scenario_exfil",
    "dns_tunnel": "scenario_dns_tunnel",
    "route_hijack": "scenario_route_hijack",
    "arp_spoof": "scenario_arp_spoof",
}

# The rule each scenario is expected to raise, so a manual inject can clear that
# rule's suppression window first and reliably surface a fresh detection.
SCENARIO_RULES = {
    "tampering": "R002", "packet_drop": "R001", "replay": "R003",
    "syn_flood": "R004", "spam": "R005", "exfil": "R006",
    "dns_tunnel": "R006", "route_hijack": "R007", "arp_spoof": "R008",
}


class LiveDriver(threading.Thread):
    """Continuously feed the engine so the dashboard shows live activity."""

    def __init__(self, engine: PacketGuardEngine, period: float = 0.6):
        super().__init__(name="packetguard-livedriver", daemon=True)
        self.engine = engine
        self.period = period
        self.running = True
        self._stop = threading.Event()
        self._rotation = [
            "scenario_tampering", "scenario_route_hijack", "scenario_replay",
            "scenario_packet_drop", "scenario_spam", "scenario_exfil",
            "scenario_dns_tunnel", "scenario_arp_spoof", "scenario_syn_flood",
        ]
        self._idx = 0
        self._tick = 0

    def run(self) -> None:  # pragma: no cover - timing loop
        if scn is None:
            return
        while not self._stop.is_set():
            if self.running:
                self._emit_normal(random.randint(3, 6))
                # Inject one attack roughly every ~9 ticks (~5s).
                if self._tick % 9 == 8:
                    self._inject(self._rotation[self._idx % len(self._rotation)])
                    self._idx += 1
                self._tick += 1
            self._stop.wait(self.period)

    def _emit_normal(self, n: int) -> None:
        for _ in range(n):
            src = random.choice([scn.SENDER, "10.0.0.3", "10.0.0.8"])
            self.engine.ingest(scn.make_packet(src=src))

    def _inject(self, name: str) -> list[str]:
        fn = getattr(scn, name, None)
        if fn is None:
            return []
        return fn(self.engine).fired_rules

    def inject_named(self, key: str) -> list[str]:
        name = SCENARIO_MAP.get(key)
        if not name:
            return []
        # A deliberate manual inject should always show a detection, even if the
        # live driver just fired the same rule — clear that rule's suppression.
        rule = SCENARIO_RULES.get(key)
        if rule:
            self.engine.reset_suppression(rule)
        return self._inject(name)

    def stop(self) -> None:
        self._stop.set()


class Handler(BaseHTTPRequestHandler):
    engine: PacketGuardEngine = None   # type: ignore[assignment]
    driver: LiveDriver = None          # type: ignore[assignment]

    # Quieter logging.
    def log_message(self, fmt, *args):  # noqa: A003 - stdlib signature
        return

    # -------------------------------------------------------------- #
    def _send(self, code: int, body: bytes, content_type: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, obj) -> None:
        self._send(200, json.dumps(obj).encode(), _CONTENT_TYPES[".json"])

    def _send_file(self, path: str) -> None:
        if not os.path.isfile(path):
            self._send(404, b"Not found", "text/plain; charset=utf-8")
            return
        ext = os.path.splitext(path)[1]
        with open(path, "rb") as fh:
            self._send(200, fh.read(), _CONTENT_TYPES.get(ext, "application/octet-stream"))

    # -------------------------------------------------------------- #
    def do_GET(self) -> None:  # noqa: N802 - stdlib signature
        route = urlparse(self.path).path
        if route == "/":
            self._send_file(os.path.join(TEMPLATES, "index.html"))
        elif route == "/api/snapshot":
            self._send_json(self.engine.snapshot())
        elif route == "/api/health":
            chain_ok, msg = self.engine.blockchain.is_valid()
            self._send_json({
                "status": "healthy" if chain_ok else "degraded",
                "chain_valid": chain_ok, "detail": msg,
                "demo_running": self.driver.running if self.driver else False,
                "suppressed_alerts": self.engine._suppressed,
            })
        elif route == "/api/proof":
            params = parse_qs(urlparse(self.path).query)
            try:
                seq = int(params.get("seq", ["-1"])[0])
            except ValueError:
                seq = -1
            proof = self.engine.export_proof(seq)
            if proof is None:
                self._send(404, b'{"error":"no proof for that sequence"}',
                           _CONTENT_TYPES[".json"])
                return
            body = json.dumps(proof, indent=2).encode()
            if params.get("download", ["0"])[0] == "1":
                self.send_response(200)
                self.send_header("Content-Type", _CONTENT_TYPES[".json"])
                self.send_header("Content-Disposition",
                                 f'attachment; filename="packetguard-proof-seq{seq}.json"')
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                self._send(200, body, _CONTENT_TYPES[".json"])
        elif route.startswith("/static/"):
            self._send_file(os.path.join(STATIC, route[len("/static/"):]))
        else:
            self._send(404, b"Not found", "text/plain; charset=utf-8")

    def do_POST(self) -> None:  # noqa: N802 - stdlib signature
        route = urlparse(self.path).path
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            payload = json.loads(raw or b"{}")
        except json.JSONDecodeError:
            payload = {}

        if route == "/api/inject":
            fired = self.driver.inject_named(payload.get("scenario", "")) \
                if self.driver else []
            self._send_json({"ok": bool(fired), "fired": fired})
        elif route == "/api/demo":
            if self.driver:
                self.driver.running = bool(payload.get("running", True))
            self._send_json({"running": self.driver.running if self.driver else False})
        elif route == "/api/tamper-witness":
            result = self.engine.demo_tamper_witness()
            self._send_json(result or {"error": "no quorum or nothing anchored yet"})
        else:
            self._send(404, b"Not found", "text/plain; charset=utf-8")


def create_server(host: str = "127.0.0.1", port: int = 8000,
                  demo: bool = True) -> ThreadingHTTPServer:
    # 2-of-3 witness quorum + Merkle batching (8 packets per block) — the full
    # ledger model the project pitches.
    engine = PacketGuardEngine(difficulty=2, witnesses=3, batch_size=8)
    # Seed an ARP baseline so the ARP-spoof scenario has something to diff against.
    engine.set_arp_baseline({
        "10.0.0.1": "aa:bb:cc:00:00:01",
        "10.0.0.2": "aa:bb:cc:00:00:02",
    })
    driver = LiveDriver(engine)
    if demo:
        driver.start()

    Handler.engine = engine
    Handler.driver = driver
    httpd = ThreadingHTTPServer((host, port), Handler)
    return httpd


def main() -> None:
    host = os.environ.get("PACKETGUARD_HOST", "127.0.0.1")
    port = int(os.environ.get("PACKETGUARD_PORT", "8000"))
    demo = os.environ.get("PACKETGUARD_DEMO", "1") != "0"
    httpd = create_server(host, port, demo=demo)
    print(f"🛡️  PacketGuard dashboard  →  http://{host}:{port}")
    print("    (Ctrl+C to stop; demo traffic is", "ON)" if demo else "OFF)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n   shutting down…")
        httpd.shutdown()


if __name__ == "__main__":
    main()
