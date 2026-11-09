# Contributing to PacketMonitor

Thank you for your interest in contributing to **PacketMonitor**! We welcome improvements, bug reports, and new detection rule proposals.

---

## Guiding Architectural Principles

Before writing code or opening a pull request, please keep the following design constraints in mind:

1. **Zero External Dependencies for Core Engine:**
   - The core packet integrity verifier, blockchain ledger, 2-of-3 witness consensus, threat detection engine, and dashboard must run strictly on the **Python 3.9+ standard library**.
   - Optional third-party packages (such as `scapy` for raw packet capture or `web3` for external EVM anchoring) must remain strictly optional and isolated behind guards.

2. **Deterministic & Self-Contained Testing:**
   - All tests in `tests/` must be runnable with Python's built-in `unittest` runner without network access.
   - Attack simulations in `simulations/` must run in-process against synthetic packet models.

---

## Development Setup

Clone your fork and navigate into the repository root:

```bash
git clone https://github.com/aanchalln29/PacketMonitor.git
cd PacketMonitor
```

### Running Tests
Make sure the baseline test suite passes:
```bash
python -m unittest discover -s tests -v
```

### Running Attack Simulations
Run the full 11-check simulation suite:
```bash
python -m simulations.run_demo
```

### Launching the Dashboard Locally
```bash
python -m src.dashboard.app
```
Then navigate to `http://127.0.0.1:8000`.

---

## Adding a New Detection Rule

To propose or add a new threat detection rule:
1. Register the rule schema and default thresholds in `src/detection/rules.json`.
2. Add the evaluation logic into `src/detection/anomaly_engine.py` or a dedicated detector module.
3. Write a synthetic attack scenario function in `simulations/scenarios.py`.
4. Add unit test coverage in `tests/test_detection.py`.
5. Ensure `simulations/run_demo.py` and `tests/` both execute with a 100% pass rate.

---

## Submitting a Pull Request

1. Create a feature branch: `git checkout -b feature/your-feature-name`.
2. Commit your changes with clear, descriptive commit messages:
   ```bash
   git commit -m "feat(detection): add ICMP rate anomaly rule"
   ```
3. Push to your fork: `git push origin feature/your-feature-name`.
4. Open a Pull Request against the `main` branch using the provided PR template.
