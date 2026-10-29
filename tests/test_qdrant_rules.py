"""Rules and import hygiene of scripts/qdrant_*.py. Needs neither numpy nor a server."""

import subprocess
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

import qdrant_common as common
import qdrant_exact
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
        ("scores swapped between ids", [("a", 0.8), ("b", 0.9), ("c", 0.7)], "returned score"),
        ("duplicate id", [("a", 0.9), ("b", 0.8), ("b", 0.8)], "duplicate"),
    ],
)
def test_compare_topk_matrix(name, result, problem_fragment):
    problems = rules.compare_topk(SCORES, EXPECTED_3, result)
    if problem_fragment is None:
        assert problems == [], name
    else:
        assert any(problem_fragment in problem for problem in problems), (name, problems)


def test_order_check_catches_sub_tolerance_steps_that_add_up():
    scores = {"x": 0.7, "y": 0.7 + 0.8 * TOL, "z": 0.7 + 1.6 * TOL}
    expected = rules.numpy_order(scores)
    ascending = [(item, scores[item]) for item in ("x", "y", "z")]  # each step <= tol, total > tol
    assert any("order" in problem for problem in rules.compare_topk(scores, expected, ascending))
    assert rules.compare_topk(scores, expected, expected) == []


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


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("http://127.0.0.1:16333", ("127.0.0.1", 16333, False, None)),
        ("http://[::1]:16333", ("[::1]", 16333, False, None)),
        ("http://[::1]", ("[::1]", 80, False, None)),
        ("https://qdrant.example", ("qdrant.example", 443, True, None)),
        ("http://host/qdrant/", ("host", 80, False, "qdrant")),
    ],
)
def test_client_endpoint_matches_the_http_endpoint(url, expected):
    endpoint = common.client_endpoint(url)
    assert (endpoint["host"], endpoint["port"], endpoint["https"], endpoint["prefix"]) == expected


@pytest.mark.parametrize("k", [1, 3])
def test_empty_result_is_a_length_violation_not_a_crash(k):
    scores = {"a": 0.9, "b": 0.8, "c": 0.7}
    expected = rules.numpy_order(scores)[:k]
    case = qdrant_exact.build_case("q", k, scores, expected, [])
    assert case["ok"] is False
    assert any("length" in problem for problem in case["problems"])
    assert case["max_abs_score_diff"] == 0.0
    assert case["qdrant_top"] == []
