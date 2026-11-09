"""Run every attack scenario against a fresh engine and report detection results.

    python -m simulations.run_demo

Each scenario gets its own :class:`PacketGuardEngine` so results are independent
and reproducible. Exit code is non-zero if any expected rule failed to fire, which
makes this usable as a CI smoke test for the detector.
"""

from __future__ import annotations

import sys

from src.engine import PacketGuardEngine
from simulations.scenarios import ALL_SCENARIOS, scenario_normal


def main() -> int:
    print("=" * 68)
    print(" PacketMonitor — Attack Simulation Suite (synthetic, in-process)")
    print("=" * 68)

    # Baseline sanity check: clean traffic must stay quiet.
    baseline_engine = PacketGuardEngine(difficulty=1)
    baseline = scenario_normal(baseline_engine)
    quiet = not baseline.fired_rules
    print(f"{'[PASS]' if quiet else '[FAIL]'}  {'Normal traffic':<24} "
          f"expected silence | fired: {baseline.fired_rules or 'none'}")
    ok = baseline_engine.blockchain.is_valid()[0]
    print(f"{'[PASS]' if ok else '[FAIL]'}  {'Blockchain integrity':<24} "
          f"chain valid after {len(baseline_engine.blockchain)} blocks")
    print("-" * 68)

    results = []
    for scenario in ALL_SCENARIOS:
        engine = PacketGuardEngine(difficulty=1)   # fresh, isolated per scenario
        result = scenario(engine)
        results.append(result)
        print(result)

    print("-" * 68)
    passed = sum(1 for r in results if r.passed) + (1 if quiet else 0) + (1 if ok else 0)
    total = len(results) + 2
    print(f" {passed}/{total} checks passed")
    print("=" * 68)

    all_pass = passed == total
    if not all_pass:
        print(" Some detections did not fire — see misses above.", file=sys.stderr)
    return 0 if all_pass else 1


if __name__ == "__main__":
    raise SystemExit(main())
