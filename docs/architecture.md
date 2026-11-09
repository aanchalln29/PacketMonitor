# PacketGuard — Architecture

This document explains how PacketGuard is built and why, at a level useful to
someone reading the code for the first time. For the project brief and the
threat model, see [`../PROJECT_PLAN.md`](../PROJECT_PLAN.md).

## One model, four layers

Every layer speaks a single data structure — `PacketRecord`
([`src/capture/packet.py`](../src/capture/packet.py)). A record can be built from
a live Scapy packet or fabricated by the simulation harness; nothing downstream
can tell the difference. That is the key design decision that makes the system
both testable and runnable with no root and no capture hardware.

```
 CAPTURE                INTEGRITY              DETECTION              RESPONSE
 ───────                ─────────              ─────────              ────────
 PacketSniffer   ──▶    Blockchain      ──▶   AnomalyEngine   ──▶    AlertManager
 (scapy|synthetic)      (anchor/verify)       (R001–R008)            FixSuggester
                        MerkleTree            Sequence/Spam/Exfil    AutoHardener
                                              HopTracer/ARPMonitor   (dry-run)
                                 ▲                                        │
                                 └──────── PacketGuardEngine ◀────────────┘
                                           (the conductor)
```

The conductor is `PacketGuardEngine` ([`src/engine.py`](../src/engine.py)). For
each packet it: anchors the legitimate hash (sender side), verifies the arrival
against the chain, runs every detector, builds a weakness/trace report for each
finding, asks the fix suggester for remediation, composes a dry-run hardening
command, and raises an alert — all while keeping the live counters the dashboard
reads.

## Capture layer

- **`PacketRecord`** — normalized packet: 5-tuple, size, TTL, TCP flags, a
  monotonic application `seq`, and the SHA-256 `payload_hash` that the whole
  integrity story hangs on.
- **`PacketSniffer`** — wraps Scapy's `sniff` when available; otherwise exposes
  `feed()` so the simulator can inject records through the exact same callback.
- **`filters`** — `build_bpf()` pushes a Berkeley Packet Filter down into libpcap;
  `PacketFilter` does Python-side predicate filtering (CIDR, size, protocol).

## Integrity layer (the blockchain)

- **`Block`** commits to its contents *and* the previous block's hash, with a
  small proof-of-work. Rewriting any historical packet hash changes that block's
  hash and breaks every block after it — the cascade is the tamper-evidence.
- **`Blockchain`** plays two roles with one structure: `anchor()` (sender commits
  a hash before sending) and `verify_packet()` (receiver re-hashes the arrival and
  compares). It also answers `is_replay()` and validates its own integrity.
- **`MerkleTree`** batches many packet hashes under one root so a block can anchor
  a whole window of packets while still proving any single packet's inclusion.
  With `batch_size > 1` the chain seals one block per *N* packets (the dashboard
  uses 8); verification stays an O(1) hash lookup, and `merkle_proof(seq)` returns
  an audit path for any packet.
- **`WitnessQuorum`** replicates the ledger across three independent witness chains
  and resolves every verification by a **2-of-3 majority**. Compromising one node
  is not enough — the other two outvote it and the quorum flags the disagreeing
  witness. It duck-types `Blockchain`, so the engine uses one chain or a quorum
  interchangeably via the `witnesses` config.
- **`PacketRegistry.sol`** is the optional Ethereum variant of the same idea.

### Incident proof export

`PacketGuardEngine.export_proof(seq)` bundles everything an auditor needs for one
packet: the anchored hash, the Merkle audit path (with a self-check), the block it
lives in, chain validity, the verification verdict, and — under a quorum — each
witness's vote. The dashboard serves it at `GET /api/proof?seq=N` (add
`&download=1` for a file). The bundle re-verifies its own Merkle path, so it stands
on its own without re-running PacketGuard.

### Why a blockchain and not a database?

If the attacker who tampers with a packet can also edit the hash store, tampering
becomes undetectable. An append-only, hash-linked chain means the stored hash
cannot be quietly rewritten to match a forged packet without invalidating the
chain — which `is_valid()` will catch.

## Detection layer

`AnomalyEngine` ([`src/detection/anomaly_engine.py`](../src/detection/anomaly_engine.py))
loads `rules.json` and runs each enabled rule per packet, emitting `Finding`s:

| Rule | Signal | Detector |
|------|--------|----------|
| R001 | sequence gaps | `SequenceTracker` |
| R002 | hash ≠ anchor | `Blockchain.verify_packet` |
| R003 | repeated payload / duplicate seq | `Blockchain.is_replay` + tracker |
| R004 | per-IP packet rate | `SpamDetector` |
| R005 | identical payload repeats | `SpamDetector` |
| R006 | outbound volume / DNS tunneling | `ExfilDetector` |
| R007 | TTL collapse on a flow | engine TTL baseline |
| R008 | ARP binding change | `ARPMonitor` (via tracer) |

Thresholds live in `rules.json`, so tuning sensitivity never touches code.

## Response layer

- **`HopTracer` / `ARPMonitor` / `WeaknessReport`** answer *where* and *why*: the
  suspect hop, the evidence, the likely attack, and a confidence score.
- **`FixSuggester`** maps each rule to concrete, ranked remediation.
- **`AutoHardener`** composes the exact host command (iptables / static ARP). It
  is **dry-run by default** and only executes when constructed `live=True` *and*
  called with `confirm=True` — a deliberate safety gate.
- **`AlertManager`** bundles finding + report + fixes + command into one alert,
  keeps a ring buffer for the dashboard, and can push to webhook/console sinks.

The engine also **suppresses duplicate alerts** for the same `(rule, source)`
inside a short window, so a flood produces one actionable alert, not thousands.

## Dashboard

[`src/dashboard/app.py`](../src/dashboard/app.py) serves the UI and a small JSON
API over one shared engine, using the Python standard library (no Flask needed).
A background `LiveDriver` generates mostly-normal traffic with attacks mixed in,
and `POST /api/inject` lets the UI trigger any single attack on demand. The
front-end (`templates/` + `static/`) polls `/api/snapshot` and renders the feed,
alerts, blockchain ledger, attack distribution, and throughput — themed for light
and dark.

## Running it

```bash
python -m simulations.run_demo      # prove all 8 detections fire (CI-friendly)
python -m src.dashboard.app         # live dashboard at http://127.0.0.1:8000
python -m unittest discover -s tests
```
