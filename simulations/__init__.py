"""PacketGuard attack-simulation harness.

Every scenario here is a **synthetic, in-process** generator: it crafts packet
streams in memory and feeds them to the detection engine to prove a rule fires. No
scenario touches a real network, needs root, or attacks any host — it is a
reproducible test bench for the detector, safe to run on any machine.

In a real ethical-hacking lab you would reproduce these with the tools named in
PROJECT_PLAN.md (ettercap, hping3, scapy, …) between isolated nodes; this harness
is the deterministic equivalent for coursework and CI.
"""
