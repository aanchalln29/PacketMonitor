# 🛡️ PacketGuard — Blockchain-Based Data Packet Integrity Monitor & Fraud Detection System

> **Subject:** Blockchain & Cyber Security — Basics of Ethical Hacking  
> **Project Type:** Applied Research + Working Prototype  
> **Core Focus:** Detecting data-packet loss, theft, tampering, and fraudulent/spam activity during data transfer — **NOT** a vulnerability scanner.

---

## 📌 1. Problem Statement

During data transfer across networks, several critical threats compromise data integrity:

| Threat | Description |
|--------|-------------|
| **Packet Loss / Theft** | Attackers intercept and steal small data packets using techniques like packet sniffing (e.g., via Wireshark, tcpdump in malicious hands). |
| **Man-in-the-Middle (MitM)** | An attacker secretly intercepts and possibly alters communication between two parties who believe they are communicating directly. |
| **Replay Attacks** | Previously captured legitimate packets are re-transmitted by an attacker to impersonate a trusted sender. |
| **Packet Injection / Tampering** | Malicious packets are injected into a data stream, or existing packets are modified mid-transit. |
| **Fraudulent Spam Activity** | Automated bots flood a network with spam packets to overwhelm systems (DoS) or mask data exfiltration. |
| **Data Exfiltration** | Sensitive data is silently siphoned out in small, hard-to-detect packet bursts. |

### Why Not a Vulnerability Scanner?

Vulnerability scanners (like Nessus, OpenVAS) probe systems for *known weaknesses* (open ports, outdated software). **PacketGuard** is fundamentally different — it operates at the **data-in-transit layer**, watching the actual flow of packets for signs of loss, theft, tampering, and fraud in **real-time**. It answers: *"Is the data arriving exactly as it was sent, and is the traffic pattern legitimate?"*

---

## 🎯 2. Project Objectives

1. **Detect** packet loss, theft, and tampering during data transfer using cryptographic hashing anchored on a blockchain ledger.
2. **Identify** the source and location of the problem (which hop, which node, which segment).
3. **Alert** administrators in real-time when anomalies are detected.
4. **Analyze** traffic patterns to detect fraudulent/spam activity using rule-based and statistical methods.
5. **Suggest** specific fixes, countermeasures, and hardening recommendations.
6. **Prevent** future attacks by recommending and (where possible) auto-applying security policies.

---

## 🏗️ 3. System Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        PACKETGUARD SYSTEM                          │
├─────────────┬──────────────┬───────────────┬────────────────────────┤
│  CAPTURE    │  INTEGRITY   │  DETECTION    │  RESPONSE              │
│  LAYER      │  LAYER       │  & ANALYSIS   │  & REMEDIATION         │
│             │              │  LAYER        │  LAYER                 │
│ ┌─────────┐ │ ┌──────────┐ │ ┌───────────┐ │ ┌──────────────────┐   │
│ │ Packet  │ │ │ SHA-256  │ │ │ Sequence  │ │ │ Real-Time Alerts │   │
│ │ Sniffer │─┼─│ Hashing  │─┼─│ Tracker   │─┼─│ (Dashboard +     │   │
│ │ (Scapy) │ │ │ Engine   │ │ │           │ │ │  Email/Webhook)  │   │
│ └─────────┘ │ └──────────┘ │ └───────────┘ │ └──────────────────┘   │
│ ┌─────────┐ │ ┌──────────┐ │ ┌───────────┐ │ ┌──────────────────┐   │
│ │ Traffic │ │ │Blockchain│ │ │ Anomaly   │ │ │ Source Tracer    │   │
│ │ Mirror  │ │ │ Ledger   │ │ │ Detector  │ │ │ (Hop-by-Hop)     │   │
│ │         │ │ │ (Hashes) │ │ │           │ │ │                  │   │
│ └─────────┘ │ └──────────┘ │ └───────────┘ │ └──────────────────┘   │
│             │ ┌──────────┐ │ ┌───────────┐ │ ┌──────────────────┐   │
│             │ │ Merkle   │ │ │ Spam /    │ │ │ Fix Suggester &  │   │
│             │ │ Tree     │ │ │ Fraud     │ │ │ Auto-Hardener    │   │
│             │ │ Builder  │ │ │ Classifier│ │ │                  │   │
│             │ └──────────┘ │ └───────────┘ │ └──────────────────┘   │
└─────────────┴──────────────┴───────────────┴────────────────────────┘
```

### Data Flow

```
Sender                                                          Receiver
  │                                                                │
  │─── Packet P₁ (seq=1) ──────────────────────────────────────▶  │
  │    hash(P₁) ──▶ Blockchain                                    │
  │                                                                │
  │─── Packet P₂ (seq=2) ───── ✖ STOLEN by Attacker               │
  │    hash(P₂) ──▶ Blockchain                                    │
  │                                                                │
  │─── Packet P₃ (seq=3) ───── ✎ TAMPERED by Attacker ──────▶    │
  │    hash(P₃) ──▶ Blockchain                                    │
  │                                                                │
  │                     Receiver verifies:                         │
  │                     P₁ ✅ hash matches blockchain              │
  │                     P₂ ❌ MISSING — gap in sequence            │
  │                     P₃ ❌ hash(received) ≠ hash(blockchain)    │
  │                                                                │
  │              ┌──── 🚨 ALERT TRIGGERED ─────┐                   │
  │              │ • P₂: Packet Lost/Stolen     │                   │
  │              │ • P₃: Integrity Violation    │                   │
  │              │ • Source: 10.0.0.47 (Hop 3)  │                   │
  │              │ • Fix: Enable TLS on Hop 3   │                   │
  │              └──────────────────────────────┘                   │
```

---

## 🧩 4. Core Modules (Detailed)

### Module 1: Packet Capture Engine

| Aspect | Detail |
|--------|--------|
| **Tool** | Python + Scapy |
| **Function** | Sniff live network packets (TCP, UDP, ICMP) on specified interfaces |
| **Filters** | Protocol-based, port-based, IP-range-based |
| **Output** | Raw packet data + metadata (src IP, dst IP, protocol, size, timestamp, TTL, seq#) |

**What it does:** Continuously captures network traffic and extracts critical metadata from each packet. Think of it as the system's "eyes" on the wire.

```python
# Simplified example
from scapy.all import sniff, IP, TCP

def capture_packet(packet):
    if packet.haslayer(IP):
        return {
            "src": packet[IP].src,
            "dst": packet[IP].dst,
            "proto": packet[IP].proto,
            "size": len(packet),
            "ttl": packet[IP].ttl,
            "seq": packet[TCP].seq if packet.haslayer(TCP) else None,
            "timestamp": time.time(),
            "payload_hash": hashlib.sha256(bytes(packet)).hexdigest()
        }

sniff(filter="tcp", prn=capture_packet, iface="eth0")
```

---

### Module 2: Blockchain Integrity Ledger

| Aspect | Detail |
|--------|--------|
| **Blockchain Type** | Lightweight local chain (Python) or Ethereum testnet (Ganache) |
| **Hashing** | SHA-256 per packet; Merkle Tree for batches |
| **Storage** | Hash + sequence number + timestamp + sender ID |
| **Purpose** | Immutable, tamper-proof record of what was *actually* sent |

**How it works:**

1. **Sender side:** Before transmitting, the sender hashes every packet (or batch) and writes the hash to the blockchain.
2. **Receiver side:** On receipt, the receiver independently hashes the received packet and queries the blockchain.
3. **Comparison:** If `hash_received ≠ hash_on_chain` → **TAMPERING DETECTED**. If a sequence number is missing → **PACKET LOST/STOLEN**.

**Why Blockchain (not a regular database)?**
- A database can be tampered with by the attacker. If the attacker compromises the hash store, they can update both the packet and its hash.
- Blockchain is **immutable** — once a hash is written, it cannot be altered without invalidating the entire chain, making forgery detectable.

```python
# Simplified local blockchain block
class Block:
    def __init__(self, index, packet_hash, prev_hash, timestamp):
        self.index = index
        self.packet_hash = packet_hash
        self.prev_hash = prev_hash
        self.timestamp = timestamp
        self.nonce = 0
        self.hash = self.compute_hash()

    def compute_hash(self):
        block_data = f"{self.index}{self.packet_hash}{self.prev_hash}{self.timestamp}{self.nonce}"
        return hashlib.sha256(block_data.encode()).hexdigest()
```

---

### Module 3: Anomaly & Fraud Detection Engine

This is where the system goes beyond simple hash matching. It analyzes **traffic patterns** to detect:

#### 3a. Packet Loss Detection
- **Mechanism:** Sequence number tracking. Every packet is assigned a monotonically increasing sequence number. Gaps in the sequence = lost or stolen packets.
- **Sensitivity:** Configurable threshold (e.g., alert after 3 missing packets in 10 seconds).

#### 3b. Replay Attack Detection
- **Mechanism:** Duplicate hash detection. If the same hash appears twice with different timestamps, it's a replay.
- **Response:** Flag and drop the duplicate.

#### 3c. Spam / Flood Detection
- **Mechanism:** Rate analysis per source IP. If a single IP sends > N packets/second (configurable), flag as potential DoS/spam.
- **Indicators:**
  - Sudden traffic spikes from a single source
  - Repetitive identical payloads
  - Abnormal protocol distribution (e.g., 99% ICMP = ping flood)

#### 3d. Data Exfiltration Detection
- **Mechanism:** Outbound traffic analysis. Detect unusually large or frequent outbound transfers to unknown external IPs, especially during off-hours.
- **Indicators:**
  - DNS tunneling patterns (large TXT record queries)
  - Encrypted traffic to non-standard ports
  - Small, periodic bursts to the same external IP

#### Detection Rules Table

| Rule ID | Condition | Severity | Alert Type |
|---------|-----------|----------|------------|
| `R001` | Sequence gap > 3 packets in 10s | 🔴 HIGH | Packet Loss/Theft |
| `R002` | Hash mismatch (received ≠ chain) | 🔴 HIGH | Tampering |
| `R003` | Duplicate hash with different timestamp | 🟡 MEDIUM | Replay Attack |
| `R004` | Single IP > 500 packets/sec | 🔴 HIGH | DoS/Spam Flood |
| `R005` | Identical payloads > 50 in 5s | 🟡 MEDIUM | Spam Activity |
| `R006` | Outbound burst to unknown IP > 10MB | 🟡 MEDIUM | Data Exfiltration |
| `R007` | TTL anomaly (sudden drop > 50%) | 🟠 MEDIUM | Route Hijack |
| `R008` | ARP table change for known host | 🔴 HIGH | MitM / ARP Spoof |

---

### Module 4: Source Tracer & Weakness Identifier

When an anomaly is detected, this module answers: **"Where is the problem, and what caused it?"**

| Analysis | Method |
|----------|--------|
| **Hop-by-Hop Tracing** | Traceroute from sender to receiver; identify which hop shows TTL anomaly or latency spike |
| **ARP Table Analysis** | Compare current ARP entries against known-good baseline; flag changes (MitM indicator) |
| **Port Scanning** | Lightweight scan of the suspect node to identify open/unexpected services |
| **Protocol Analysis** | Check for protocol downgrade (HTTPS → HTTP, TLS 1.3 → TLS 1.0) |
| **Log Correlation** | Cross-reference packet anomalies with system logs (auth failures, process spawns) |

**Output Example:**
```
🔍 SOURCE TRACE REPORT
━━━━━━━━━━━━━━━━━━━━━━
Incident:     Packet Tampering (Rule R002)
Detected At:  2026-10-08 10:30:15 UTC
Affected:     Packets seq#4401 — seq#4420

Source of Issue:
  → Hop 3: 192.168.1.47 (Switch-Floor2)
  → Evidence: TTL dropped from 64 to 12 at this hop
  → Evidence: ARP entry changed 2 minutes before incident
  → Weakness: Unencrypted segment between Hop 2 and Hop 3

Likely Attack: Man-in-the-Middle via ARP Spoofing
Confidence:   92%
```

---

### Module 5: Fix Suggester & Auto-Hardener

Based on the detected threat, the system provides **specific, actionable remediation**:

| Detected Threat | Suggested Fixes | Auto-Apply? |
|-----------------|-----------------|-------------|
| **Packet Tampering** | ① Enable TLS/SSL on the affected segment ② Implement IPSec tunnel between hops ③ Rotate encryption keys | Partial — can auto-enable firewall rules |
| **Packet Loss/Theft** | ① Investigate the suspicious hop ② Enable port security (MAC binding) ③ Deploy VLAN segmentation | Manual — requires network config |
| **Replay Attack** | ① Implement nonce/timestamp verification ② Enable anti-replay in IPSec ③ Add session tokens | Partial |
| **Spam / DoS Flood** | ① Rate-limit the source IP ② Deploy SYN cookies ③ Enable DDoS mitigation (fail2ban) | ✅ Yes — auto rate-limit via iptables |
| **ARP Spoofing (MitM)** | ① Enable Dynamic ARP Inspection (DAI) ② Use static ARP entries for critical hosts ③ Deploy 802.1X authentication | Manual |
| **Data Exfiltration** | ① Block the external destination IP ② Investigate the source host ③ Enable DLP (Data Loss Prevention) policies | Partial — auto-block IP |

---

### Module 6: Real-Time Dashboard & Alert System

A web-based dashboard for live monitoring:

| Panel | Contents |
|-------|----------|
| **Live Traffic Feed** | Real-time packet flow visualization with color-coded status (green = verified, red = tampered, yellow = suspicious) |
| **Blockchain Ledger View** | Scrollable list of recent blocks with hash, timestamp, and verification status |
| **Alert Timeline** | Chronological list of triggered alerts with severity, rule ID, and incident details |
| **Threat Map** | Network topology showing which nodes/hops are flagged |
| **Fix Recommendations** | Context-specific remediation steps for each active alert |
| **Statistics** | Packets processed, verified, flagged; attack type distribution pie chart |

---

## 🔧 5. Technology Stack

| Layer | Technology | Why |
|-------|-----------|-----|
| **Packet Capture** | Python + Scapy | Industry-standard for packet manipulation; flexible filtering |
| **Hashing** | `hashlib` (SHA-256) | Cryptographically secure; fast; built into Python |
| **Blockchain** | Custom Python chain (for demo) / Ganache + Solidity (for Ethereum) | Local chain for speed; Ethereum testnet for realism |
| **Smart Contracts** | Solidity (optional) | Automate hash storage and verification on Ethereum |
| **Web3 Integration** | `web3.py` | Python bridge to Ethereum blockchain |
| **Dashboard** | HTML + CSS + JavaScript (or Flask + Chart.js) | Lightweight, real-time web dashboard |
| **Alerting** | Python (`smtplib` for email, webhooks for Slack/Discord) | Instant notifications |
| **Database** | SQLite (local logs) | Lightweight; no setup needed; stores traffic history |
| **Testing / Simulation** | Mininet or Docker network | Simulate multi-hop networks with attackers |

---

## 🧪 6. Attack Simulation Plan (Ethical Hacking Component)

To validate the system, we simulate real attacks in a **controlled lab environment**:

### Simulation Environment
```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Sender    │────▶│  Attacker   │────▶│  Receiver   │
│  (Node A)   │     │  (Node M)   │     │  (Node B)   │
│ 10.0.0.1    │     │ 10.0.0.47   │     │ 10.0.0.2    │
└─────────────┘     └─────────────┘     └─────────────┘
        │                                       │
        └───── PacketGuard Monitoring ──────────┘
```

### Simulated Attacks

| # | Attack | Tool | Expected Detection |
|---|--------|------|-------------------|
| 1 | **Packet Sniffing** | Wireshark / tcpdump on Node M | System detects ARP anomaly; flags potential eavesdropping |
| 2 | **MitM (ARP Spoofing)** | `arpspoof` / `ettercap` on Node M | ARP table change detected (Rule R008); hop trace identifies Node M |
| 3 | **Packet Tampering** | Scapy script modifying payload on Node M | Hash mismatch (Rule R002); blockchain verification fails |
| 4 | **Packet Dropping** | `iptables -j DROP` on Node M | Sequence gap detected (Rule R001); traceroute pinpoints Node M |
| 5 | **Replay Attack** | Scapy script re-sending captured packets | Duplicate hash detected (Rule R003) |
| 6 | **SYN Flood (DoS)** | `hping3 --flood -S` from Node M | Rate threshold exceeded (Rule R004); auto rate-limit applied |
| 7 | **DNS Tunneling** | `iodine` / `dnscat2` | Abnormal DNS query pattern flagged (Rule R006) |

---

## 📁 7. Project File Structure

```
Cyber Project ATG/
├── PROJECT_PLAN.md              ← You are here
├── README.md                    ← Project overview & setup instructions
├── requirements.txt             ← Python dependencies
│
├── src/
│   ├── capture/
│   │   ├── sniffer.py           ← Packet capture engine (Scapy)
│   │   └── filters.py           ← Protocol/port/IP filters
│   │
│   ├── blockchain/
│   │   ├── chain.py             ← Blockchain implementation
│   │   ├── block.py             ← Block data structure
│   │   ├── merkle.py            ← Merkle tree for batch hashing
│   │   └── contracts/           ← Solidity smart contracts (optional)
│   │       └── PacketRegistry.sol
│   │
│   ├── detection/
│   │   ├── sequence_tracker.py  ← Packet sequence gap detection
│   │   ├── anomaly_engine.py    ← Rule-based anomaly detection
│   │   ├── spam_detector.py     ← Spam/flood traffic classifier
│   │   ├── exfil_detector.py    ← Data exfiltration detector
│   │   └── rules.json           ← Configurable detection rules
│   │
│   ├── tracer/
│   │   ├── hop_tracer.py        ← Traceroute & hop analysis
│   │   ├── arp_monitor.py       ← ARP table baseline & change detection
│   │   └── weakness_report.py   ← Generates weakness & source report
│   │
│   ├── response/
│   │   ├── alert_manager.py     ← Alert generation & dispatch
│   │   ├── fix_suggester.py     ← Remediation recommendation engine
│   │   └── auto_hardener.py     ← Auto-apply fixes (iptables, etc.)
│   │
│   └── dashboard/
│       ├── app.py               ← Flask web server
│       ├── templates/
│       │   └── index.html       ← Dashboard UI
│       └── static/
│           ├── css/
│           │   └── style.css
│           └── js/
│               └── dashboard.js ← Real-time charts (Chart.js / D3.js)
│
├── tests/
│   ├── test_blockchain.py       ← Unit tests for blockchain
│   ├── test_detection.py        ← Unit tests for detection engine
│   └── test_sniffer.py          ← Unit tests for packet capture
│
├── simulations/
│   ├── mitm_attack.py           ← MitM simulation script
│   ├── packet_drop.py           ← Packet dropping simulation
│   ├── replay_attack.py         ← Replay attack simulation
│   ├── syn_flood.py             ← SYN flood simulation
│   └── docker-compose.yml       ← Multi-node network setup
│
└── docs/
    ├── architecture.md          ← Detailed architecture documentation
    ├── attack_scenarios.md      ← Documented attack test cases
    └── results/                 ← Screenshots, logs, and findings
```

---

## 📅 8. Implementation Roadmap

### Phase 1: Foundation (Week 1–2)
- [ ] Set up project structure and virtual environment
- [ ] Implement basic packet sniffer with Scapy
- [ ] Build the lightweight Python blockchain (Block, Chain, hashing)
- [ ] Create SHA-256 hashing pipeline for captured packets
- [ ] Store packet hashes on the local blockchain

### Phase 2: Detection Engine (Week 3–4)
- [ ] Implement sequence number tracking and gap detection
- [ ] Build hash comparison logic (received vs. blockchain)
- [ ] Add replay attack detection (duplicate hash flagging)
- [ ] Implement rate-based spam/flood detection
- [ ] Create configurable rules engine (`rules.json`)

### Phase 3: Source Tracing & Fixes (Week 5)
- [ ] Implement hop-by-hop traceroute analysis
- [ ] Build ARP table monitor and baseline comparison
- [ ] Create weakness identification and reporting module
- [ ] Implement fix suggestion engine with remediation database
- [ ] Add auto-hardening capabilities (iptables rules, rate limiting)

### Phase 4: Dashboard & Alerts (Week 6)
- [ ] Build Flask-based web dashboard
- [ ] Implement real-time traffic visualization
- [ ] Add alert timeline and notification system (email/webhook)
- [ ] Create blockchain ledger viewer
- [ ] Add network topology threat map

### Phase 5: Testing & Simulation (Week 7)
- [ ] Set up Docker-based multi-node test network
- [ ] Execute all 7 attack simulations
- [ ] Document detection results and system performance
- [ ] Fine-tune detection thresholds and reduce false positives
- [ ] Write unit and integration tests

### Phase 6: Documentation & Presentation (Week 8)
- [ ] Complete all documentation
- [ ] Record demo video
- [ ] Prepare presentation slides
- [ ] Final code review and cleanup

---

## 🔑 9. Key Differentiators (What Makes This Unique)

| Feature | Vulnerability Scanner | **PacketGuard** |
|---------|----------------------|-----------------|
| Focus | Known software vulnerabilities | Live data-in-transit integrity |
| Method | Probe & match CVE database | Hash, compare, and trace |
| Timing | Periodic scan | Real-time continuous monitoring |
| Blockchain | Not used | Core component — immutable audit trail |
| Packet-Level | No | Yes — individual packet tracking |
| Source Tracing | Identifies vulnerable services | Identifies the exact compromised hop/node |
| Remediation | "Update software version X" | "Enable TLS on Hop 3; block IP 10.0.0.47" |
| Attack Simulation | Not included | Built-in ethical hacking test suite |

---

## 📚 10. References & Research

1. **Blockchain for Network Security:**
   - Dorri, A., et al. (2017). "Blockchain for IoT Security and Privacy: The Case Study of a Smart Home." *IEEE PERCOM Workshop.*
   - Kshetri, N. (2017). "Can Blockchain Strengthen the Internet of Things?" *IT Professional.*

2. **Packet Integrity & Monitoring:**
   - Scapy Official Documentation — https://scapy.readthedocs.io/
   - SHA-256 & Merkle Trees — NIST FIPS 180-4 (Secure Hash Standard)

3. **Intrusion Detection:**
   - Snort IDS — https://www.snort.org/
   - Suricata — https://suricata.io/

4. **Ethical Hacking Frameworks:**
   - OWASP Testing Guide — https://owasp.org/www-project-web-security-testing-guide/
   - PTES (Penetration Testing Execution Standard) — http://www.pentest-standard.org/

5. **Network Attack Techniques:**
   - ARP Spoofing — https://www.ettercap-project.org/
   - SYN Flooding — RFC 4987: TCP SYN Flooding Attacks and Common Mitigations

---

## ⚠️ 11. Ethical & Legal Considerations

> **CAUTION:** All attack simulations MUST be conducted in an **isolated lab environment** (Docker network, VMs, or Mininet). **NEVER** run attack tools on public or production networks without explicit written authorization. Unauthorized network intrusion is a criminal offense under the Computer Fraud and Abuse Act (CFAA) and equivalent laws worldwide.

- All testing will be performed on **local, sandboxed networks** only.
- No real user data will be captured or stored.
- The project is for **educational and research purposes** only.
- All tools used are open-source and legally available.

---

## ✅ 12. Expected Outcomes

1. A working prototype that captures live packets, hashes them onto a blockchain, and detects tampering/loss.
2. Demonstrated detection of at least 5 different attack types in a simulated environment.
3. A real-time dashboard showing alerts, blockchain status, and threat maps.
4. Actionable fix recommendations generated automatically for each detected threat.
5. Comprehensive documentation and a recorded demo.

---

*Project Name: **PacketGuard** — "Every packet has a blockchain witness."*
