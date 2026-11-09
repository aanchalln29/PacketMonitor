# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

**Primary: the course demo audience.** Classmates and evaluating faculty watching a
live presentation of the prototype for *Blockchain & Cyber Security — Basics of
Ethical Hacking*. Their job in the moment is to **understand what PacketGuard does
and see it work within seconds** — trigger an attack, watch it get detected,
traced, and proven — then judge it. The design serves comprehension-at-a-glance
and a convincing live demo, not a daily operator workflow.

**Depicted (secondary) user:** a security / network operator monitoring
data-in-transit integrity. This is the product's *subject*, not the primary design
target; the synthetic demo stands in for that real deployment.

## Product Purpose

Real-time monitoring of data **in transit** that answers one question continuously:
*is the data arriving exactly as it was sent, and is the traffic pattern
legitimate?* It anchors a cryptographic fingerprint of every packet on a
tamper-evident blockchain, then detects loss, theft, tampering, replay, flooding,
and exfiltration — tracing each incident to a suspect hop, recommending a fix, and
exporting an audit proof. It exists as a working coursework prototype that makes
these blockchain + ethical-hacking concepts tangible. Success = the audience and
grader immediately grasp the idea and see detection happen live and convincingly.

## Positioning

**Not a vulnerability scanner.** Scanners (Nessus, OpenVAS, Nmap) probe hosts *at
rest* for known weaknesses. PacketGuard watches packets *in motion* across links
the owner doesn't control. Its differentiating mechanism is a hash-anchored,
append-only ledger **replicated across a 2-of-3 witness quorum** (plus Merkle
batching): a compromised node cannot silently rewrite history because the other
two outvote it — a property a plain database or single log cannot truthfully claim.
Especially relevant for industrial protocols (e.g. Modbus) with no built-in
encryption that can't be patched.

## Operating Context

- Run locally (`python -m src.dashboard.app`) and viewed in a desktop browser during
  a live class presentation, narrated slide-by-slide (see `docs/demo_script.md`).
- A **Simulate attack** panel triggers each of nine scenarios on cue; a
  **Compromise a witness** control demonstrates quorum resilience live.
- Also ships a headless `python -m simulations.run_demo` (11/11 checks) and a
  `unittest` suite for a no-browser fallback.
- All traffic shown is **synthetic, in-process** lab data — it attacks nothing real.

## Capabilities and Constraints

**Capabilities:** eight detection rules R001–R008, classed as four *ledger-enabled*
(tampering, loss/theft, replay, route hijack) and four *network-hygiene* (DoS,
spam, DNS-tunnel/exfiltration, ARP spoof); SHA-256 per-packet anchoring; Merkle
batching (8 packets/block); 2-of-3 witness quorum with majority verification;
hop-trace weakness reports; dry-run auto-hardening (iptables/ARP); self-verifying
incident proof export (Merkle path + quorum votes); a refined light/dark dashboard.

**Binding constraints (user-confirmed):**
- **Zero-install / standard-library only.** Runs on plain Python 3.9 with no
  third-party dependencies; the dashboard is served by the stdlib HTTP server.
- **Blockchain + 2-of-3 witness quorum is the core mechanism** — central to the
  product's identity, not swappable for a plain database.

**Terminology:** packet, sequence (seq), anchor, hash, Merkle root, block, witness,
quorum, hop tracer, rule IDs (Rxxx), dry-run.

**Accessibility:** AA text contrast, themed focus rings, reduced-motion honored,
keyboard-focusable controls, tabular numerals for aligned data.

**Open / not locked:**
- *Live packet capture* (real Scapy sniffing) exists as an optional path but is not
  part of the binding deliverable; synthetic traffic is the default. Not excluded —
  an allowed future extension.
- *Name and tagline* below are the current identity but were not declared immutable.

## Brand Commitments

- **Name:** PacketGuard. **Tagline:** "Every packet has a blockchain witness."
  (Current identity; changeable — not locked by the user.)
- **Voice:** precise, technical, and honest — no hype, with explicit
  synthetic-data / educational-use disclaimers. Controls name their exact action.

## Evidence on Hand

- 53 passing unit tests; `run_demo` reports 11/11 checks (all rules fire, chain
  intact); a working dashboard verified via the mechanical design detector and a
  server smoke test.
- Source docs: `PROJECT_PLAN.md`, `README.md`, `docs/architecture.md`,
  `docs/attack_scenarios.md`, `docs/demo_script.md`.
