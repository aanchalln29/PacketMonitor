"""PacketGuardEngine — the conductor that wires every layer together.

Flow for one packet:

1. **Anchor** (sender side): commit the legitimate payload hash to the blockchain.
2. **Verify + Detect** (receiver side): re-check the arrived packet against the
   chain and run every detector in :class:`AnomalyEngine`.
3. **Explain**: for each finding, build a weakness/trace report.
4. **Remediate**: suggest fixes and compose (dry-run) hardening commands.
5. **Alert**: raise an alert carrying all of the above, and update live stats.

The engine is deliberately source-agnostic: the same ``process`` path serves live
Scapy capture and the synthetic simulation harness.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Optional

from .blockchain.chain import Blockchain
from .blockchain.witness import WitnessQuorum
from .capture.packet import PacketRecord
from .detection.anomaly_engine import AnomalyEngine, Finding
from .response.alert_manager import AlertManager
from .response.auto_hardener import AutoHardener
from .response.fix_suggester import FixSuggester
from .tracer.arp_monitor import ARPMonitor
from .tracer.hop_tracer import HopTracer
from .tracer.weakness_report import build_report


@dataclass
class EngineStats:
    processed: int = 0
    verified: int = 0
    flagged: int = 0
    anchored: int = 0
    protocols: dict[str, int] = field(default_factory=dict)
    started_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        uptime = max(1e-6, time.time() - self.started_at)
        return {
            "processed": self.processed,
            "verified": self.verified,
            "flagged": self.flagged,
            "anchored": self.anchored,
            "protocols": dict(self.protocols),
            "uptime_seconds": round(uptime, 1),
            "throughput_pps": round(self.processed / uptime, 2),
        }


class PacketGuardEngine:
    def __init__(
        self,
        difficulty: int = 2,
        sender_id: str = "node-A",
        auto_harden_live: bool = False,
        feed_size: int = 60,
        witnesses: int = 1,
        batch_size: int = 1,
    ):
        # One chain, or a 2-of-3 witness quorum when witnesses > 1. Both expose
        # the same interface, so nothing downstream changes.
        if witnesses > 1:
            self.blockchain = WitnessQuorum(difficulty=difficulty,
                                            sender_id=sender_id,
                                            batch_size=batch_size, nodes=witnesses)
        else:
            self.blockchain = Blockchain(difficulty=difficulty, sender_id=sender_id,
                                         batch_size=batch_size)
        self.quorum = self.blockchain if isinstance(self.blockchain, WitnessQuorum) else None
        self.detector = AnomalyEngine(self.blockchain)
        self.alerts = AlertManager()
        self.fixer = FixSuggester()
        self.hardener = AutoHardener(live=auto_harden_live)
        self.tracer = HopTracer()
        self.arp = ARPMonitor()

        self.stats = EngineStats()
        self._feed: deque[dict[str, Any]] = deque(maxlen=feed_size)
        self._lock = threading.RLock()

        # Alert suppression: collapse repeats of the same (rule, source) within a
        # short window so a flood produces one actionable alert, not thousands.
        self._suppress_window = 2.0
        self._last_alert: dict[tuple[str, str], float] = {}
        self._suppressed = 0

    # ------------------------------------------------------------------ #
    # Sender side
    # ------------------------------------------------------------------ #
    def anchor(self, pkt: PacketRecord) -> None:
        """Commit a packet's *legitimate* hash to the chain before transmission.

        The scenario may carry the pristine hash in ``meta['anchor_hash']`` when the
        arriving copy is going to be tampered; otherwise the packet's own hash is
        the legitimate one.
        """
        anchor_hash = pkt.meta.get("anchor_hash", pkt.payload_hash)
        self.blockchain.anchor(pkt.seq, anchor_hash)
        with self._lock:
            self.stats.anchored += 1

    # ------------------------------------------------------------------ #
    # Receiver side
    # ------------------------------------------------------------------ #
    def process(self, pkt: PacketRecord) -> list[Finding]:
        """Verify + detect on an arrived packet; raise alerts; update stats."""
        findings = self.detector.inspect(pkt)
        verification = self.blockchain.verify_packet(pkt.seq, pkt.payload_hash)

        for finding in findings:
            self._handle_finding(finding)

        status = self._status(verification.status, findings)
        with self._lock:
            self.stats.processed += 1
            self.stats.protocols[pkt.protocol] = \
                self.stats.protocols.get(pkt.protocol, 0) + 1
            if status == "verified":
                self.stats.verified += 1
            if findings:
                self.stats.flagged += 1
            self._feed.append({
                **pkt.to_public_dict(),
                "status": status,
                "rules": [f.rule_id for f in findings],
            })
        return findings

    def ingest(self, pkt: PacketRecord, anchor: bool = True) -> list[Finding]:
        """Convenience: anchor (optional) then process a single packet."""
        if anchor:
            self.anchor(pkt)
        return self.process(pkt)

    # ------------------------------------------------------------------ #
    # ARP / MitM path (R008)
    # ------------------------------------------------------------------ #
    def set_arp_baseline(self, table: dict[str, str]) -> None:
        self.arp.set_baseline(table)

    def check_arp(self, current_table: dict[str, str]) -> list[Finding]:
        findings: list[Finding] = []
        for change in self.arp.diff(current_table):
            finding = self.detector.report_arp_change(
                change.ip, change.old_mac, change.new_mac)
            if finding:
                findings.append(finding)
                self._handle_finding(finding)
                with self._lock:
                    self.stats.flagged += 1
        return findings

    # ------------------------------------------------------------------ #
    def reset_suppression(self, rule_id: Optional[str] = None) -> None:
        """Clear the alert-suppression window (all, or one rule) so the next
        matching finding raises a fresh alert. Used so a manual demo inject always
        produces a visible detection even if the live driver just fired the rule."""
        with self._lock:
            if rule_id is None:
                self._last_alert.clear()
            else:
                self._last_alert = {k: v for k, v in self._last_alert.items()
                                    if k[0] != rule_id}

    def _handle_finding(self, finding: Finding) -> None:
        key = (finding.rule_id, finding.src_ip)
        last = self._last_alert.get(key, 0.0)
        if finding.timestamp - last < self._suppress_window:
            self._suppressed += 1
            return
        self._last_alert[key] = finding.timestamp

        report = build_report(finding, tracer=self.tracer)
        remediation = self.fixer.suggest(finding)
        hardening = None
        if remediation.auto_action:
            action = self.hardener.apply(remediation.auto_action, confirm=False)
            hardening = action.to_dict() if action else None
        self.alerts.raise_alert(
            finding,
            report=report.to_dict(),
            remediation=remediation.to_dict(),
            hardening=hardening,
        )

    @staticmethod
    def _status(verify_status: str, findings: list[Finding]) -> str:
        if any(f.rule_id == "R002" for f in findings) or verify_status == "tampered":
            return "tampered"
        if verify_status == "verified":
            return "verified"
        if findings:
            return "suspicious"
        return "ok"

    # ------------------------------------------------------------------ #
    # Incident proof export (for audits / compliance)
    # ------------------------------------------------------------------ #
    def export_proof(self, seq: int) -> Optional[dict[str, Any]]:
        """Produce a self-contained cryptographic proof for one packet.

        Shows exactly what the ledger holds for ``seq``: the anchored hash, the
        Merkle audit path to its block root, the block's position in the chain,
        the current verification verdict, and — under a quorum — each witness's
        vote. The proof re-verifies its own Merkle path, so an auditor can trust
        it without re-running PacketGuard.
        """
        proof = self.blockchain.merkle_proof(seq)
        if proof is None:
            return None
        anchored_hash = proof["leaf_hash"]
        merkle_ok = self.blockchain.verify_merkle_proof(
            anchored_hash, proof["proof"], proof["merkle_root"], proof["leaf_index"])
        chain_ok, chain_msg = self.blockchain.is_valid()
        verdict = self.blockchain.verify_packet(seq, anchored_hash)

        bundle: dict[str, Any] = {
            "seq": seq,
            "anchored_hash": anchored_hash,
            "merkle": {
                "leaf_index": proof["leaf_index"],
                "path": proof["proof"],
                "root": proof["merkle_root"],
                "self_check": merkle_ok,
            },
            "block": {
                "index": proof["block_index"],
                "hash": proof["block_hash"],
                "prev_hash": proof["prev_hash"],
                "timestamp": proof["timestamp"],
                "packets_in_block": proof["batch_size"],
            },
            "chain": {"valid": chain_ok, "status": chain_msg},
            "verification": verdict.status,
            "generated_at": time.time(),
        }
        if self.quorum is not None:
            vote = self.quorum.vote(seq, anchored_hash)
            bundle["quorum"] = {
                "scheme": f"{self.quorum.threshold}-of-{self.quorum.nodes}",
                "confirmed": vote.confirmed,
                "agree": vote.agree,
                "per_witness": vote.per_witness,
                "compromised": vote.compromised,
            }
        return bundle

    def demo_tamper_witness(self) -> Optional[dict[str, Any]]:
        """DEMO: compromise one witness's copy of a recently anchored packet and
        return the quorum's response, proving 2-of-3 still resolves correctly."""
        if self.quorum is None:
            return None
        primary = self.quorum.witnesses[0]
        primary.flush()
        if not primary._anchor_meta:
            return None
        seq = max(primary._anchor_meta)
        legit = primary._anchored[seq]
        self.quorum.tamper_witness(self.quorum.nodes - 1, seq, "deadbeef" + legit[8:])
        vote = self.quorum.vote(seq, legit)
        return {"seq": seq, "status": vote.status, "agree": vote.agree,
                "total": vote.total, "compromised": vote.compromised,
                "confirmed": vote.confirmed}

    # ------------------------------------------------------------------ #
    # Dashboard views
    # ------------------------------------------------------------------ #
    def snapshot(self) -> dict[str, Any]:
        chain_ok, chain_msg = self.blockchain.is_valid()
        with self._lock:
            feed = list(self._feed)[::-1]
            stats = self.stats.to_dict()
        bc: dict[str, Any] = {
            "length": len(self.blockchain),
            "valid": chain_ok,
            "status": chain_msg,
            "difficulty": self.blockchain.difficulty,
            "recent": self.blockchain.recent(12),
            "batch_size": getattr(self.blockchain, "batch_size", 1)
            if self.quorum is None else self.quorum.witnesses[0].batch_size,
        }
        if self.quorum is not None:
            bc["quorum"] = self.quorum.status()
        return {
            "stats": stats,
            "alerts": self.alerts.recent(50),
            "alert_stats": self.alerts.stats(),
            "blockchain": bc,
            "feed": feed,
            "timestamp": time.time(),
        }
