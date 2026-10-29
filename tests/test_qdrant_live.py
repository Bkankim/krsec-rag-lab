"""Opt-in checks against a real Qdrant server and numpy (issue #6).

Skipped by default (CI runs ``uv sync --locked --dev`` with no numpy, no Docker). To run:

    docker run -d --name krsec-qdrant-6 --label krsec-run=1 -p 16333:6333 qdrant/qdrant:v1.19.2
    uv sync --group qdrant
    KRSEC_QDRANT_URL=http://127.0.0.1:16333 uv run --no-sync pytest -q tests/test_qdrant_live.py
"""

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import qdrant_common as common

pytestmark = pytest.mark.skipif(
    not os.environ.get(common.URL_ENV), reason=f"opt-in: set {common.URL_ENV} to a live Qdrant"
)

ANN_N = 30_000  # 30000 x 128 x 4 B = 15000 KB, above the 10000 KB indexing threshold
ANN_QUERIES = 50
ANN_EFS = (16, 128, 1024)


@pytest.fixture(scope="module")
def url():
    pytest.importorskip("numpy")
    pytest.importorskip("qdrant_client")
    return common.resolve_url(None)


@pytest.fixture(scope="module")
def exact_report(url):
    import qdrant_exact

    return qdrant_exact.run(url)


@pytest.fixture(scope="module")
def ann_report(url):
    import qdrant_ann

    return qdrant_ann.run(url, n=ANN_N, n_queries=ANN_QUERIES, ef_values=ANN_EFS)


@pytest.mark.parametrize("k", [1, 3, 5, 10])
def test_exact_matches_numpy_for_every_query(exact_report, k):
    cases = [case for case in exact_report["cases"] if case["k"] == k]
    assert len(cases) == 11  # fixture query + 10 self-searches
    assert [(c["query"], c["problems"]) for c in cases if not c["ok"]] == []


def test_exact_fixture_query_reproduces_the_baseline(exact_report):
    assert exact_report["exact_top1_id"] == exact_report["expected_doc_id"]
    assert exact_report["baseline_top3_ids_match"]
    assert exact_report["baseline_json_vs_recomputed_max_diff"] < 1e-6


def test_demo_collection_builds_no_hnsw(exact_report):
    # Ten vectors stay far below the indexing threshold: Qdrant answers by scanning.
    result = exact_report["collection_info_raw"]["result"]
    assert result["points_count"] == 10
    assert result["indexed_vectors_count"] == 0


def test_ann_collection_really_has_an_hnsw_index(ann_report):
    result = ann_report["collection_info_raw"]["result"]
    assert result["points_count"] == ANN_N
    assert result["indexed_vectors_count"] == ANN_N
    assert result["status"] == "green"


def test_ann_exact_search_equals_numpy_and_hnsw_recall_grows_with_ef(ann_report):
    rows = {row["search"]: row for row in ann_report["table"]}
    assert rows["qdrant exact=True"]["queries_not_matching_numpy"] == 0
    recalls = [rows[f"hnsw ef={ef}"]["recall_at_k_mean"] for ef in ANN_EFS]
    assert recalls == sorted(recalls)
    assert recalls[0] < 0.5
    assert recalls[-1] > 0.9
