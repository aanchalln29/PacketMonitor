<div align="center">

# 🛡️ PacketMonitor

### **Blockchain-Anchored Data-Packet Integrity & Real-Time Network Fraud Detection**
*Every packet has an immutable cryptographic witness.*

[![Python 3.9+](https://img.shields.io/badge/Python-3.9%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-0%20External-success.svg?style=for-the-badge)](#quick-start)
[![Test Suite](https://img.shields.io/badge/Tests-53%20Passing-brightgreen.svg?style=for-the-badge)](#testing--verification)
[![Consensus](https://img.shields.io/badge/Consensus-2--of--3%20Witness%20Quorum-blueviolet.svg?style=for-the-badge)](#core-innovations)

<br/>

[Executive Summary](#executive-summary) •
[Architecture](#system-architecture) •
[Detection Matrix](#attack-detection-matrix) •
[Interactive Dashboard](#real-time-dashboard) •
[Quick Start](#quick-start) •
[Verification](#testing--verification)

---

</div>

## 📌 Executive Summary

Modern cybersecurity tools (e.g., Nessus, OpenVAS, Nmap) focus primarily on probing hosts **at rest** for known CVEs. However, critical infrastructure, financial protocols, and industrial automation standards (such as **Modbus** and **SCADA**) transmit unencrypted payloads across untrusted or third-party network links where host-level patching is impossible.

**PacketMonitor** is a real-time, wire-level data integrity and network fraud-detection system designed to monitor data **in transit**. 

Before transmission, every packet is cryptographically hashed (SHA-256) and anchored to an immutable, Merkle-batched blockchain replicated across an independent **2-of-3 Byzantine witness quorum**. As traffic traverses intermediate hops, PacketMonitor detects in real-time whether payloads arrive intact, flags anomalies across 8 threat classes, isolates suspect network hops, generates auto-hardening firewall rules (`iptables`), and produces self-verifying cryptographic audit proofs.

> **Zero External Dependencies:** Built entirely using the **Python 3.9+ standard library**—from the blockchain ledger and detection algorithms to the multithreaded HTTP server and interactive dashboard.

---

## ⚡ Core Innovations

- ⛓️ **Cryptographic Wire Anchoring:** Computes SHA-256 packet fingerprints at egress and anchors them into an append-only chain before packets cross hostile or untrusted networks.
- 🏛️ **2-of-3 Witness Quorum:** Replicates the ledger across three independent witness nodes with majority voting. Even if an attacker completely compromises one node, they cannot rewrite history—the remaining two witnesses outvote and isolate the rogue node.
- 🌳 **Merkle Batching (8 packets/block):** Combines individual packet hashes into binary Merkle trees for accelerated verification, enabling logarithmic cryptographic inclusion proofs ($O(\log N)$).
- 🎯 **Dual-Engine Detection (8 Threat Vectors):** Combines ledger-anchored invariant checks (tampering, drop, replay, route collapse) with statistical network-hygiene detectors (DoS, spam, DNS tunneling, ARP spoofing).
- 📍 **Automated Hop Tracing & Localization:** Correlates TTL collapses and network telemetry to pinpoint the exact suspect hop where tampering or packet drops occurred.
- 🛡️ **Defensive Auto-Hardening:** Immediately outputs actionable, dry-run remediation commands (e.g., dynamic `iptables` drop rules, static ARP table bindings).
- 📜 **Cryptographic Audit Proofs:** Generates downloadable JSON audit packages containing the raw packet hash, Merkle inclusion path, and multi-witness quorum digital signatures.

---

## 🏗️ System Architecture

```text
       ┌──────────────┐
       │ PacketSender │
       └──────┬───────┘
              │  1. Compute SHA-256 Hash
              ├──────────────────────────────────────────────┐
              │                                              │
              ▼                                              ▼
    ┌───────────────────┐                         ┌─────────────────────┐
    │  Network Wire     │                         │ 2-of-3 Witness Chain │
    │ (Untrusted Hops)  │                         │ (Merkle Batched)    │
    └─────────┬─────────┘                         └──────────┬──────────┘
              │                                              │
              │  2. In-Transit Delivery                      │ 3. Fetch Proof
              ▼                                              ▼
       ┌──────────────┐                            ┌───────────────────┐
       │PacketReceiver│ ─── 4. Re-hash & Compare ─►│ Detection Engine │
       └──────────────┘                            └─────────┬─────────┘
                                                             │
                  ┌──────────────────────────────────────────┴──────────────────────────┐
                  ▼                                                                     ▼
       [ Normal Verified Traffic ]                                            [ Anomaly Triggered ]
       • State: Verified (Green)                                              • R001–R008 Fired
       • Immutable Audit Record                                               • Suspect Hop Isolated
                                                                              • iptables Rule Generated
                                                                              • Cryptographic Proof Exported
```

---

## 🛡️ Attack Detection Matrix

PacketMonitor's detection suite is governed by configurable rules defined in `src/detection/rules.json`:

| Rule ID | Threat Category | Threat Type | Detection Mechanism | Automated Response Action |
|:---:|:---|:---|:---|:---|
| **R001** | Ledger-Anchored | **Packet Loss / Theft** | Sequence number gap detection against expected sender sequence | Flags dropped sequence; inspects intermediate hop drop rates |
| **R002** | Ledger-Anchored | **MitM Tampering** | Payload re-hash mismatch against blockchain Merkle root anchor | Raises Critical Alert; identifies suspect hop; generates packet proof |
| **R003** | Ledger-Anchored | **Replay Attack** | Detection of duplicate packet hashes or duplicate sequence counter | Discards replayed packet; increments flow anomaly score |
| **R004** | Network Hygiene | **DoS / SYN Flood** | Rolling-window packet frequency exceeding threshold | Triggers rate-limiting; outputs immediate `iptables -A INPUT -s ... -j DROP` |
| **R005** | Network Hygiene | **Payload Spam** | Identical payload signatures repeated within a tight temporal window | Suppresses spam source; flags upstream sender |
| **R006** | Network Hygiene | **Data Exfiltration** | High-entropy outbound volumetric bursts and DNS query tunneling | Flags abnormal egress flow; alerts on suspicious base64/hex DNS queries |
| **R007** | Ledger-Anchored | **Route Hijack** | Sudden TTL step-down indicating detour through an unauthorized proxy/tap | Traces deviation along path; alerts network operator to route collapse |
| **R008** | Network Hygiene | **ARP Spoofing (MitM)** | IP-to-MAC address binding mismatch against known baseline cache | Issues ARP alert; generates static `arp -s <ip> <mac>` bind commands |

---

## 🖥️ Real-Time Dashboard

PacketMonitor features an Apple-inspired monitoring interface with responsive Light and Dark themes, served directly via Python's built-in HTTP server (`src/dashboard/app.py`).

```text
┌─────────────────────────────────────────────────────────────────────────────────┐
│ 🛡️ PacketMonitor                   Quorum: 2-of-3 Healthy ●  Throughput: 142 pps │
├──────────────────────────┬──────────────────────────┬───────────────────────────┤
│ STATS TILES              │ LIVE TRAFFIC STREAM      │ INCIDENT ALERT FEED       │
│ • Packets Processed: 580 │ • [10.0.0.1:443] VERIFIED│ • 🚨 CRITICAL: R002 MitM  │
│ • Integrity Rate:  98.4% │ • [10.0.0.5:80]  TAMPERED│   Hop 2 (192.168.1.1)     │
│ • Threats Blocked:    11 │ • [10.0.0.2:53]  EXFIL   │   Remediation: iptables   │
├──────────────────────────┴──────────────────────────┴───────────────────────────┤
│ ATTACK SIMULATION PANEL (Trigger any of 9 scenarios with 1-click live feedback) │
│ [ Simulate MitM ] [ Simulate SYN Flood ] [ Simulate Replay ] [ Compromise Node ]│
└─────────────────────────────────────────────────────────────────────────────────┘
```

### Dashboard Capabilities:
- **Telemetry Cards:** Real-time counters for processed packets, verified integrity rate, active threats, and block count.
- **Wire Inspector:** Colour-coded per-packet status (`Verified` / `Tampered` / `Suspicious` / `Unanchored`).
- **Quorum Health & Byzantine Demo:** Visual status of all 3 witness nodes, with an interactive **"Compromise a Witness"** control to observe the 2-of-3 consensus self-healing live.
- **Incident Audit Exporter:** One-click generation of verifiable cryptographic JSON proofs containing raw hashes, Merkle branch paths, and quorum attestation.

---

## 🚀 Quick Start

### Prerequisites
- **Python 3.9+** (No external package managers, pip installs, or virtual environments required).

### 1. Clone the Repository
```bash
git clone https://github.com/aanchalln29/PacketMonitor.git
cd PacketMonitor
```

### 2. Run the Attack Simulation Suite
Verify the entire detection pipeline against all 8 threat classes:
```bash
python -m simulations.run_demo
```
*Expected Output:*
```text
====================================================================
 PacketMonitor — Attack Simulation Suite (synthetic, in-process)
====================================================================
✅ PASS  Normal traffic           expected silence | fired: none
✅ PASS  Blockchain integrity     chain valid after 21 blocks
--------------------------------------------------------------------
✅ PASS  Packet tampering (MitM)  expected R002 | fired: R002
✅ PASS  Packet drop / theft      expected R001 | fired: R001
✅ PASS  Replay attack            expected R003 | fired: R003
✅ PASS  SYN flood (DoS)          expected R004 | fired: R004
✅ PASS  Spam flood               expected R005 | fired: R005
✅ PASS  Data exfiltration        expected R006 | fired: R006
✅ PASS  DNS tunneling            expected R006 | fired: R006
✅ PASS  Route hijack (TTL)       expected R007 | fired: R007
✅ PASS  ARP spoof (MitM)         expected R008 | fired: R008
--------------------------------------------------------------------
 11/11 checks passed
====================================================================
```

### 3. Launch the Live Monitoring Dashboard
```bash
python -m src.dashboard.app
```
Open **[http://127.0.0.1:8000](http://127.0.0.1:8000)** in your browser to inspect live traffic, trigger attacks, and export audit proofs.

---

## 🧪 Testing & Verification

PacketMonitor includes a comprehensive, deterministic unit test suite covering blockchain consistency, Merkle proofs, witness quorum voting, and detection engine rules:

```bash
python -m unittest discover -s tests -v
```

```text
Ran 53 tests in 0.106s
OK
```

### Test Coverage Highlights:
- `test_blockchain.py`: Merkle root computation, block hash-linking, tamper-cascade invalidation.
- `test_witness.py`: Quorum majority voting (2-of-3), Byzantine node dissent rejection, and ledger reconciliation.
- `test_detection.py`: Evaluation of rules R001 through R008 against clean and adversarial packet feeds.
- `test_sniffer.py`: Packet modeling, serialization, and synthetic flow generation.

---

## 📂 Project Structure

```text
PacketMonitor/
├── .github/
│   └── workflows/
│       └── ci.yml               # Automated multi-OS CI testing (Ubuntu, Windows, macOS)
├── docs/
│   ├── architecture.md          # Comprehensive architectural specification
│   ├── attack_scenarios.md      # Detailed threat modeling & scenario definitions
│   └── demo_script.md           # Step-by-step presentation & live demo guide
├── simulations/
│   ├── run_demo.py              # CLI test harness proving all 11 simulation checks
│   ├── scenarios.py             # Synthetic attack generators (MitM, Replay, DoS, etc.)
│   └── docker-compose.yml       # Optional multi-container isolated lab environment
├── src/
│   ├── blockchain/              # Merkle trees, Block model, Ledger, 2-of-3 WitnessQuorum
│   ├── capture/                 # Packet schema, packet hashing, and sniffing interfaces
│   ├── dashboard/               # Zero-dependency UI server, static assets, and templates
│   ├── detection/               # AnomalyEngine, rule evaluators, and rules.json
│   ├── response/                # Hop tracing, iptables rule synthesis, audit proof export
│   └── engine.py                # Central orchestrator integrating all subsystems
├── tests/                       # 53 deterministic unit tests (Python stdlib)
├── LICENSE                      # MIT License
├── README.md                    # Project documentation
└── requirements.txt             # Optional extras (scapy for raw PCAP capture, web3)
```

---

## 💼 Portfolio & Resume Highlights

When presenting **PacketMonitor** in professional or academic contexts:

- **Distributed Trust & Consensus:** Implemented a resilient 2-of-3 Byzantine witness quorum with Merkle batching, guaranteeing data-in-transit auditability without reliance on a centralized database.
- **Wire-Level Threat Modeling:** Authored 8 detection algorithms targeting protocol-layer exploits (Modbus/SCADA vulnerability mitigation, ARP poisoning, TTL route hijacks).
- **Incident Response Automation:** Engineered an automated remediation pipeline converting detected anomalies into immediate, actionable firewall policies (`iptables`).
- **Software Craftsmanship:** Engineered the entire system with **zero third-party dependencies**, ensuring full portability, rapid startup (<100ms), and 100% test coverage across major operating systems.

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

Developed with precision for **Blockchain & Cyber Security** research.
