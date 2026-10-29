"""Exact-search comparison: NumPy full scan vs Qdrant ``exact=True`` (issue #6).

Reuses the vectors in fixtures/embeddings_demo/ untouched (read-only). Prints one JSON
report; the exit status is non-zero when any rule from qdrant_rules.py is violated.

    uv sync --group qdrant
    uv run --no-sync python scripts/qdrant_exact.py
"""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import sys
from pathlib import Path

import qdrant_common as common
import qdrant_rules as rules

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "embeddings_demo"
COLLECTION = "krsec6_demo"
KS = (1, 3, 5, 10)
# payload keys that get a keyword index (filter targets); text stays unindexed.
INDEXED_PAYLOAD = ("doc_id", "cve", "product")


def load_fixture() -> dict:
    import numpy as np

    documents = json.loads((FIXTURE / "documents.json").read_text(encoding="utf-8"))
    manifest = json.loads((FIXTURE / "manifest.json").read_text(encoding="utf-8"))
    digest = hashlib.sha256((FIXTURE / "documents.json").read_bytes()).hexdigest()
    if digest != manifest["corpus"]["documents_sha256"]:
        raise SystemExit("documents.json differs from manifest sha256: fixture was modified")
    return {
        "documents": documents,
        "doc_vectors": np.load(FIXTURE / "doc_embeddings.npy"),
        "query_vector": np.load(FIXTURE / "query_embedding.npy"),
        "baseline": json.loads((FIXTURE / "baseline_scores.json").read_text(encoding="utf-8")),
        "documents_sha256": digest,
    }


def numpy_scores(doc_vectors, query_vector, doc_ids: list[str]) -> dict[str, float]:
    """Cosine = dot product, because the fixture vectors are L2-normalized."""
    return {doc_id: float(s) for doc_id, s in zip(doc_ids, doc_vectors @ query_vector)}


def load_points(client, fixture: dict) -> None:
    from qdrant_client import models

    docs = fixture["documents"]["documents"]
    vectors = fixture["doc_vectors"]
    common.recreate_collection(
        client,
        COLLECTION,
        vectors_config=models.VectorParams(size=vectors.shape[1], distance=models.Distance.COSINE),
    )
    for field in INDEXED_PAYLOAD:
        client.create_payload_index(COLLECTION, field, models.PayloadSchemaType.KEYWORD)
    client.upsert(
        COLLECTION,
        points=[
            models.PointStruct(
                id=index,
                vector=vectors[index].tolist(),
                payload={key: doc[key] for key in ("doc_id", "cve", "product", "text")},
            )
            for index, doc in enumerate(docs)
        ],
        wait=True,
    )


def exact_hits(client, query_vector, k: int) -> list[rules.Hit]:
    from qdrant_client import models

    response = client.query_points(
        COLLECTION,
        query=query_vector.tolist(),
        limit=k,
        search_params=models.SearchParams(exact=True),
        with_payload=["doc_id"],
    )
    return [(point.payload["doc_id"], float(point.score)) for point in response.points]


def run(url: str) -> dict:
    fixture = load_fixture()
    doc_ids = [doc["doc_id"] for doc in fixture["documents"]["documents"]]
    client = common.make_client(url)
    load_points(client, fixture)
    info = common.wait_until_indexed(url, COLLECTION)

    # Query 0 is the fixture query; 1..10 reuse each document vector as a query (self-search).
    queries = [("fixture-query", fixture["query_vector"])]
    queries += [(f"self:{doc_id}", vec) for doc_id, vec in zip(doc_ids, fixture["doc_vectors"])]

    cases = []
    for label, vector in queries:
        scores = numpy_scores(fixture["doc_vectors"], vector, doc_ids)
        ranking = rules.numpy_order(scores)
        for k in KS:
            expected = ranking[:k]
            result = exact_hits(client, vector, k)
            problems = rules.compare_topk(scores, expected, result)
            cases.append(
                {
                    "query": label,
                    "k": k,
                    "ok": not problems,
                    "strict_id_order_equal": [h[0] for h in expected] == [h[0] for h in result],
                    "max_abs_score_diff": max(
                        abs(want[1] - got[1])
                        for want, got in zip(expected, sorted(result, key=lambda h: -h[1]))
                    ),
                    "problems": problems,
                    "numpy_top": expected,
                    "qdrant_top": result,
                }
            )

    main_scores = numpy_scores(fixture["doc_vectors"], fixture["query_vector"], doc_ids)
    baseline = fixture["baseline"]["scores"]
    baseline_drift = max(abs(main_scores[d] - baseline[d]) for d in doc_ids)
    ordered = [score for _, score in rules.numpy_order(main_scores)]
    return {
        "server": common.server_info(url),
        "collection": COLLECTION,
        "collection_info_raw": info,
        "documents_sha256": fixture["documents_sha256"],
        "rules": {"score_tolerance": rules.SCORE_TOLERANCE, "ks": list(KS)},
        "fixture_query_min_adjacent_gap": min(a - b for a, b in itertools.pairwise(ordered)),
        "baseline_json_vs_recomputed_max_diff": baseline_drift,
        "baseline_top3_ids_match": [h["doc_id"] for h in fixture["baseline"]["top_k"]]
        == [h[0] for h in rules.numpy_order(main_scores)[:3]],
        "expected_doc_id": fixture["documents"]["expected_doc_id"],
        "exact_top1_id": next(c for c in cases if c["query"] == "fixture-query" and c["k"] == 1)[
            "qdrant_top"
        ][0][0],
        "cases_total": len(cases),
        "cases_ok": sum(c["ok"] for c in cases),
        "cases": cases,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--url", help=f"Qdrant REST URL (env {common.URL_ENV}, else default)")
    args = parser.parse_args(argv)
    report = run(common.resolve_url(args.url))
    json.dump(report, sys.stdout, ensure_ascii=False, indent=2)
    sys.stdout.write("\n")
    return 0 if report["cases_ok"] == report["cases_total"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
