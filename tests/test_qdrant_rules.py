"""Rules and import hygiene of scripts/qdrant_*.py. Needs neither numpy nor a server."""

import subprocess
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

import qdrant_rules as rules

TOL = rules.SCORE_TOLERANCE
SCORES = {"a": 0.9, "b": 0.8, "c": 0.7, "d": 0.7 - TOL / 2, "e": 0.5}
EXPECTED_3 = [("a", 0.9), ("b", 0.8), ("c", 0.7)]


@pytest.mark.parametrize(
    ("name", "result", "problem_fragment"),
    [
        ("exact match", [("a", 0.9), ("b", 0.8), ("c", 0.7)], None),
        ("score drift inside tolerance", [("a", 0.9 + TOL / 2), ("b", 0.8), ("c", 0.7)], None),
        ("tie at cutoff, other tied id", [("a", 0.9), ("b", 0.8), ("d", 0.7 - TOL / 2)], None),
        ("score drift beyond tolerance", [("a", 0.9 + 2 * TOL), ("b", 0.8), ("c", 0.7)], "rank 1"),
        ("clear member replaced", [("a", 0.9), ("c", 0.7), ("d", 0.7 - TOL / 2)], "missing"),
        ("id below the cutoff", [("a", 0.9), ("b", 0.8), ("e", 0.5)], "below the cutoff"),
        ("order violation", [("a", 0.9), ("c", 0.8), ("b", 0.7)], "order"),
        ("too short", [("a", 0.9), ("b", 0.8)], "length"),
        ("too long", [("a", 0.9), ("b", 0.8), ("c", 0.7), ("d", 0.7)], "length"),
        ("duplicate id", [("a", 0.9), ("b", 0.8), ("b", 0.8)], "duplicate"),
    ],
)
def test_compare_topk_matrix(name, result, problem_fragment):
    problems = rules.compare_topk(SCORES, EXPECTED_3, result)
    if problem_fragment is None:
        assert problems == [], name
    else:
        assert any(problem_fragment in problem for problem in problems), (name, problems)


def test_numpy_order_breaks_ties_by_id():
    ranking = rules.numpy_order({"z": 0.5, "a": 0.5, "m": 0.9})
    assert [item for item, _ in ranking] == ["m", "a", "z"]


def test_empty_expected_is_a_match_only_for_empty_result():
    assert rules.compare_topk(SCORES, [], []) == []
    assert rules.compare_topk(SCORES, [], [("a", 0.9)])


@pytest.mark.parametrize(
    ("result_ids", "expected_recall"),
    [
        (["a", "b", "c"], 1.0),
        (["a", "b", "d"], 1.0),  # d is tied with c inside the tolerance
        (["a", "b", "e"], 2 / 3),
        (["e"], 0.0),
        (["a", "a", "a"], 1 / 3),  # duplicates are not counted twice
    ],
)
def test_recall_at_k_is_tie_aware(result_ids, expected_recall):
    assert rules.recall_at_k(SCORES, 0.7, result_ids, 3) == pytest.approx(expected_recall)


@pytest.mark.parametrize(
    ("samples", "median", "p95"),
    [
        ([5.0], 5.0, 5.0),
        ([1.0, 2.0, 3.0, 4.0], 2.5, 4.0),
        (list(map(float, range(1, 101))), 50.5, 95.0),
    ],
)
def test_latency_summary(samples, median, p95):
    assert rules.latency_summary(samples) == {"median_ms": median, "p95_ms": p95}


@pytest.mark.parametrize("script", sorted(SCRIPTS.glob("qdrant_*.py")), ids=lambda p: p.name)
def test_script_imports_without_numpy_or_qdrant_client(script):
    # Block both packages even where they are installed (uv sync --group qdrant).
    code = (
        "import sys\n"
        "sys.modules['numpy'] = None\n"
        "sys.modules['qdrant_client'] = None\n"
        f"sys.path.insert(0, {str(SCRIPTS)!r})\n"
        f"import {script.stem}\n"
    )
    done = subprocess.run([sys.executable, "-c", code], check=False, capture_output=True, text=True)
    assert done.returncode == 0, done.stderr
