"""Matching rules for the Qdrant comparison (issue #6), pure Python.

The rules are fixed before any run and written out in docs/qdrant-comparison.md.
This module imports neither numpy nor qdrant_client, so the CI test environment
(``uv sync --locked --dev``) can exercise it.

Rules
-----
* Score tolerance ``SCORE_TOLERANCE``: two scores that differ by at most this are equal.
  float32 dot products over 1024 dims drift about 1e-7; 1e-5 leaves two orders of headroom
  without hiding a real ranking change (the demo query's smallest adjacent gap is ~1.9e-3).
* Tie: scores within tolerance are tied. Tied ids may come back in any order, and the ids
  tied at the top-k cutoff may be any of the tied candidates.
* NumPy order (the reference): score descending, then ``doc_id``/id ascending.
"""

from __future__ import annotations

import statistics
from collections.abc import Mapping, Sequence

SCORE_TOLERANCE = 1e-5

Hit = tuple[object, float]  # (id, score)


def numpy_order(scores: Mapping[object, float]) -> list[Hit]:
    """Reference ranking: score descending, ties broken by id ascending."""
    return sorted(scores.items(), key=lambda item: (-item[1], item[0]))


def compare_topk(
    score_of: Mapping[object, float] | Sequence[float],
    expected: Sequence[Hit],
    result: Sequence[Hit],
    tol: float = SCORE_TOLERANCE,
) -> list[str]:
    """Return the rule violations of ``result`` against the NumPy top-k ``expected``.

    ``score_of[id]`` is the NumPy score of any id. ``expected`` is the NumPy top-k in
    NumPy order. ``result`` is what the engine returned, in its own order. An empty list
    means the result matches under the tie and tolerance rules.
    """
    problems: list[str] = []
    k = len(expected)
    if len(result) != k:
        problems.append(f"length {len(result)} != {k}")
    ids = [hit[0] for hit in result]
    if len(set(ids)) != len(ids):
        problems.append("duplicate ids in result")
    if not expected:
        return problems
    kth = expected[-1][1]

    returned = sorted((hit[1] for hit in result), reverse=True)
    for rank, (want, got) in enumerate(zip((hit[1] for hit in expected), returned), 1):
        if abs(want - got) > tol:
            problems.append(f"rank {rank}: score {got:.8f} vs NumPy {want:.8f} (> tol)")

    for item in ids:
        if score_of[item] < kth - tol:
            problems.append(f"id {item!r} scores below the cutoff {kth:.8f} - tol")
    present = set(ids)
    for item, score in expected:
        if score > kth + tol and item not in present:
            problems.append(f"id {item!r} is clearly inside top-{k} but missing")

    previous = None
    for item in ids:
        current = score_of[item]
        if previous is not None and current > previous + tol:
            problems.append(f"id {item!r} is ranked below a lower NumPy score (order)")
        previous = current
    return problems


def recall_at_k(
    score_of: Mapping[object, float] | Sequence[float],
    kth_score: float,
    result_ids: Sequence[object],
    k: int,
    tol: float = SCORE_TOLERANCE,
) -> float:
    """Tie-aware recall@k: an id is a hit when its NumPy score reaches the k-th NumPy score."""
    hits = sum(1 for item in set(result_ids) if score_of[item] >= kth_score - tol)
    return hits / k


def latency_summary(samples_ms: Sequence[float]) -> dict[str, float]:
    """Median and nearest-rank p95 of per-query latencies in milliseconds."""
    ordered = sorted(samples_ms)
    p95_index = max(0, -(-95 * len(ordered) // 100) - 1)
    return {
        "median_ms": round(statistics.median(ordered), 3),
        "p95_ms": round(ordered[p95_index], 3),
    }
