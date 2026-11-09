"""Synthetic attack scenarios that exercise each PacketGuard detection rule.

Each ``scenario_*`` function takes a :class:`PacketGuardEngine`, injects crafted
traffic, and returns a :class:`ScenarioResult` describing what fired. All packet
data is fabricated in memory — these are detector tests, not network attacks.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from src.capture.packet import PacketRecord
from src.engine import PacketGuardEngine

SENDER = "10.0.0.1"
RECEIVER = "10.0.0.2"
ATTACKER = "10.0.0.47"
EXTERNAL = "203.0.113.66"   # TEST-NET-3, safe documentation range


@dataclass
class ScenarioResult:
    name: str
    expected_rule: str
    fired_rules: list[str] = field(default_factory=list)
    detail: str = ""

    @property
    def passed(self) -> bool:
        return self.expected_rule in self.fired_rules

    def __str__(self) -> str:
        mark = "✅ PASS" if self.passed else "❌ MISS"
        fired = ", ".join(sorted(set(self.fired_rules))) or "none"
        return (f"{mark}  {self.name:<24} expected {self.expected_rule} | "
                f"fired: {fired}")


# ---------------------------------------------------------------------- #
# Packet factory
# ---------------------------------------------------------------------- #
_SEQ = 0


def _next_seq() -> int:
    global _SEQ
    _SEQ += 1
    return _SEQ


def make_packet(
    src: str = SENDER,
    dst: str = RECEIVER,
    *,
    seq: int | None = None,
    payload: bytes | None = None,
    protocol: str = "TCP",
    size: int | None = None,
    ttl: int = 64,
    ts: float | None = None,
    **meta: Any,
) -> PacketRecord:
    seq = _next_seq() if seq is None else seq
    payload = payload if payload is not None else f"legit-{seq}".encode()
    return PacketRecord(
        seq=seq, src_ip=src, dst_ip=dst, protocol=protocol,
        src_port=40000 + (seq % 1000), dst_port=443,
        size=size if size is not None else len(payload),
        ttl=ttl, timestamp=ts if ts is not None else time.time(),
        payload=payload, meta=dict(meta),
    )


def _collect(engine: PacketGuardEngine, findings_before: int) -> list[str]:
    """Return rule ids raised since ``findings_before`` alerts existed."""
    recent = engine.alerts.recent(200)
    new = recent[: engine.alerts.stats()["total"] - findings_before]
    return [a["rule_id"] for a in new]


# ---------------------------------------------------------------------- #
# Baseline
# ---------------------------------------------------------------------- #
def scenario_normal(engine: PacketGuardEngine, n: int = 20) -> ScenarioResult:
    """Clean traffic — anchored and verified, nothing should fire."""
    before = engine.alerts.stats()["total"]
    for _ in range(n):
        engine.ingest(make_packet())
    fired = _collect(engine, before)
    return ScenarioResult("Normal traffic", "", fired,
                          f"{n} packets verified against the chain")


# ---------------------------------------------------------------------- #
# 1 & 2. Tampering (R002)
# ---------------------------------------------------------------------- #
def scenario_tampering(engine: PacketGuardEngine) -> ScenarioResult:
    """Sender anchors a pristine hash; the arriving copy was modified in transit."""
    before = engine.alerts.stats()["total"]
    legit = b"transfer 100 USD to account 12345"
    tampered = b"transfer 100 USD to account 99999"   # attacker swapped the account
    anchor_hash = hashlib.sha256(legit).hexdigest()
    pkt = make_packet(payload=tampered, anchor_hash=anchor_hash)
    engine.anchor(pkt)      # sender commits the legitimate hash
    engine.process(pkt)     # receiver sees the altered payload
    return ScenarioResult("Packet tampering (MitM)", "R002",
                          _collect(engine, before), "payload altered vs anchor")


# ---------------------------------------------------------------------- #
# 4. Packet dropping / theft (R001)
# ---------------------------------------------------------------------- #
def scenario_packet_drop(engine: PacketGuardEngine) -> ScenarioResult:
    """Sender anchors a contiguous run; several packets never arrive."""
    before = engine.alerts.stats()["total"]
    base = _next_seq()
    now = time.time()
    dropped = {base + 5, base + 6, base + 7, base + 8}   # 4 stolen > max_gap(3)
    for i in range(14):
        seq = base + i
        pkt = make_packet(seq=seq, ts=now)
        engine.anchor(pkt)                 # sender anchored all of them
        if seq not in dropped:
            engine.process(pkt)            # but these four never reach the receiver
    return ScenarioResult("Packet drop / theft", "R001",
                          _collect(engine, before),
                          f"dropped {sorted(dropped)}")


# ---------------------------------------------------------------------- #
# 5. Replay attack (R003)
# ---------------------------------------------------------------------- #
def scenario_replay(engine: PacketGuardEngine) -> ScenarioResult:
    """Attacker captures an authenticated packet and re-sends it under a new seq."""
    before = engine.alerts.stats()["total"]
    payload = b"auth-token:SESSION-ABCDEF"
    original = make_packet(payload=payload)
    engine.ingest(original)                              # legitimate send
    replay = make_packet(payload=payload, src=ATTACKER)  # same payload, new seq
    engine.process(replay)                               # attacker re-injects it
    return ScenarioResult("Replay attack", "R003",
                          _collect(engine, before), "same payload re-sent")


# ---------------------------------------------------------------------- #
# 6. SYN flood / DoS (R004)
# ---------------------------------------------------------------------- #
def scenario_syn_flood(engine: PacketGuardEngine, pps: int = 600) -> ScenarioResult:
    """One source emits > threshold packets within a single second."""
    before = engine.alerts.stats()["total"]
    now = time.time()
    for i in range(pps):
        pkt = make_packet(src=ATTACKER, seq=_next_seq(), ts=now,
                          payload=f"syn-{i}".encode())
        pkt.tcp_flags = "S"
        engine.process(pkt)     # attacker traffic is not anchored by the sender
    return ScenarioResult("SYN flood (DoS)", "R004",
                          _collect(engine, before), f"{pps} pkts in ~1s")


# ---------------------------------------------------------------------- #
# Spam — identical payloads (R005)
# ---------------------------------------------------------------------- #
def scenario_spam(engine: PacketGuardEngine, count: int = 60) -> ScenarioResult:
    """Same payload repeated many times in a short window — bot fingerprint."""
    before = engine.alerts.stats()["total"]
    now = time.time()
    spam_payload = b"BUY NOW!!! http://spam.example"
    for _ in range(count):
        engine.process(make_packet(src=ATTACKER, seq=_next_seq(),
                                   payload=spam_payload, ts=now))
    return ScenarioResult("Spam flood", "R005",
                          _collect(engine, before), f"{count} identical payloads")


# ---------------------------------------------------------------------- #
# 7. Data exfiltration (R006)
# ---------------------------------------------------------------------- #
def scenario_exfil(engine: PacketGuardEngine) -> ScenarioResult:
    """A large outbound burst leaves the network for an external IP."""
    before = engine.alerts.stats()["total"]
    now = time.time()
    chunk = 1_500_000   # ~1.5 MB per packet
    for i in range(8):  # ~12 MB > 10 MB threshold
        engine.process(make_packet(src=RECEIVER, dst=EXTERNAL, seq=_next_seq(),
                                   size=chunk, payload=b"x", ts=now))
    return ScenarioResult("Data exfiltration", "R006",
                          _collect(engine, before), "~12 MB to external IP")


def scenario_dns_tunnel(engine: PacketGuardEngine) -> ScenarioResult:
    """DNS tunneling: abnormally long query name smuggling data out."""
    before = engine.alerts.stats()["total"]
    pkt = make_packet(src=RECEIVER, dst=EXTERNAL, protocol="UDP",
                      seq=_next_seq(), dns_qname_len=180)
    pkt.dst_port = 53
    engine.process(pkt)
    return ScenarioResult("DNS tunneling", "R006",
                          _collect(engine, before), "180-byte DNS query name")


# ---------------------------------------------------------------------- #
# 3. Route hijack — TTL anomaly (R007)
# ---------------------------------------------------------------------- #
def scenario_route_hijack(engine: PacketGuardEngine) -> ScenarioResult:
    """An established flow's TTL suddenly collapses — a new hop is in the path."""
    before = engine.alerts.stats()["total"]
    flow_src, flow_dst = "10.0.0.5", "10.0.0.9"
    for _ in range(3):
        engine.process(make_packet(src=flow_src, dst=flow_dst, seq=_next_seq(),
                                   ttl=64))
    # Attacker inserts a hop; packets now arrive with a much lower TTL.
    engine.process(make_packet(src=flow_src, dst=flow_dst, seq=_next_seq(), ttl=12))
    return ScenarioResult("Route hijack (TTL)", "R007",
                          _collect(engine, before), "TTL 64 → 12")


# ---------------------------------------------------------------------- #
# 2. MitM via ARP spoofing (R008)
# ---------------------------------------------------------------------- #
def scenario_arp_spoof(engine: PacketGuardEngine) -> ScenarioResult:
    """The MAC bound to the gateway IP changes to the attacker's — classic ARP spoof."""
    before = engine.alerts.stats()["total"]
    baseline = {"10.0.0.1": "aa:bb:cc:00:00:01", "10.0.0.2": "aa:bb:cc:00:00:02"}
    engine.set_arp_baseline(baseline)
    poisoned = dict(baseline)
    poisoned["10.0.0.1"] = "de:ad:be:ef:00:47"   # attacker's MAC
    engine.check_arp(poisoned)
    return ScenarioResult("ARP spoof (MitM)", "R008",
                          _collect(engine, before), "gateway MAC changed")


# ---------------------------------------------------------------------- #
ALL_SCENARIOS: list[Callable[[PacketGuardEngine], ScenarioResult]] = [
    scenario_tampering,
    scenario_packet_drop,
    scenario_replay,
    scenario_syn_flood,
    scenario_spam,
    scenario_exfil,
    scenario_dns_tunnel,
    scenario_route_hijack,
    scenario_arp_spoof,
]
