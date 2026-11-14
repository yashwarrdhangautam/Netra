"""Eval harness for the protection detector: precision and recall over labelled header cases.

Run on its own with: pytest tests/eval -q. The thresholds guard against regressions; raise them
as the detector improves, never lower them to make a change pass.
"""

import json
from pathlib import Path

from netra.intel.bypass_checklist import detect_protections

FIXTURE = Path(__file__).with_name("protections_eval.json")
MIN_PRECISION = 0.95
MIN_RECALL = 0.95


def _score() -> dict[str, float]:
    cases = json.loads(FIXTURE.read_text(encoding="utf-8"))["cases"]
    tp = fp = fn = 0
    misses: list[str] = []
    for case in cases:
        found = set(detect_protections(case["headers"], case["status"]))
        expected = set(case["expected"])
        tp += len(found & expected)
        fp += len(found - expected)
        fn += len(expected - found)
        if found != expected:
            misses.append(f"{case['name']}: expected {sorted(expected)}, got {sorted(found)}")
    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    return {"precision": precision, "recall": recall, "cases": len(cases), "misses": misses}


def test_fixture_is_populated():
    cases = json.loads(FIXTURE.read_text(encoding="utf-8"))["cases"]
    assert len(cases) >= 10
    assert all({"name", "headers", "status", "expected"} <= set(c) for c in cases)


def test_detector_meets_precision_and_recall_thresholds():
    result = _score()
    detail = "\n".join(result["misses"])
    assert result["precision"] >= MIN_PRECISION, detail
    assert result["recall"] >= MIN_RECALL, detail
