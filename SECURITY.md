# Security Policy

## Supported Versions

PacketMonitor is an educational and research prototype demonstrating data-in-transit integrity anchoring and network fraud detection.

| Version | Supported |
| ------- | --------- |
| 1.0.x   | Yes       |
| < 1.0   | No        |

## Scope & Responsible Disclosure

PacketMonitor is designed to monitor packet streams and detect adversarial manipulations (such as packet loss, MitM tampering, replays, SYN floods, and DNS tunneling).

If you discover a potential vulnerability in PacketMonitor's cryptographic anchoring, consensus logic, or detection engines:

1. **Do not create a public GitHub issue.**
2. Send an email to [aanchal.nasre@gmail.com](mailto:aanchal.nasre@gmail.com) with:
   - Description of the vulnerability.
   - Steps to reproduce or proof-of-concept script.
   - Potential impact on the 2-of-3 quorum or detection rules.
3. You will receive an acknowledgment within 48 hours.

## Ethical Testing & Research Notice

All attack simulations included in `simulations/` run in-process or within an isolated Docker lab network (`internal: true`). They should only ever be evaluated in authorized, sandboxed test environments.

