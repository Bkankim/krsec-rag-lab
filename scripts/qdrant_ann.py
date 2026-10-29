"""HNSW vs exact on seeded synthetic vectors: recall@k and latency per ef (issue #6).

The collection holds N_VECTORS vectors (above Qdrant's default indexing threshold of
20000 KB), so the optimizer really builds an HNSW graph. The evidence is the raw
``GET /collections/{name}`` response, including ``indexed_vectors_count``.

    uv sync --group qdrant
    uv run --no-sync python scripts/qdrant_ann.py
"""

from __future__ import annotations

import argparse
import json
import sys
import time

import qdrant_common as common
import qdrant_rules as rules
import qdrant_synth as synth

COLLECTION = "krsec6_ann"
K = 10
EF_VALUES = (10, 16, 32, 64, 128, 256, 512, 1024)
HNSW_M = 16
HNSW_EF_CONSTRUCT = 128
WARMUP_QUERIES = 20


INDEXING_THRESHOLD_KB = 10_000  # Qdrant v1.19 default, recorded in the raw collection info


def build_collection(client, url: str, base) -> dict:
    """Bulk-load with indexing off, then switch the threshold on.

    Leaving the optimizer on during upload indexes whatever has accumulated when the
    threshold is crossed and leaves the tail unindexed (timing dependent: 20000 of 30000
    vectors in one observed run). Loading first and enabling indexing afterwards makes the
    outcome deterministic: one segment holding every vector, fully indexed.
    """
    from qdrant_client import models

    common.recreate_collection(
        client,
        COLLECTION,
        vectors_config=models.VectorParams(size=base.shape[1], distance=models.Distance.COSINE),
        hnsw_config=models.HnswConfigDiff(m=HNSW_M, ef_construct=HNSW_EF_CONSTRUCT),
        # one segment, so the whole vector set is a single indexing candidate
        optimizers_config=models.OptimizersConfigDiff(
            default_segment_number=1, indexing_threshold=0
        ),
    )
    client.upload_collection(
        COLLECTION, vectors=base, ids=range(len(base)), batch_size=1000, parallel=1, wait=True
    )
    client.update_collection(
        COLLECTION,
        optimizers_config=models.OptimizersConfigDiff(indexing_threshold=INDEXING_THRESHOLD_KB),
    )
    return common.wait_until_indexed(url, COLLECTION, min_indexed=len(base), timeout_s=300)


def numpy_truth(base, queries, k: int):
    """Per query: the NumPy score row and the NumPy top-k in NumPy order (score desc, id asc)."""
    import numpy as np

    scores = queries @ base.T
    rows, tops = [], []
    for row in scores:
        order = np.lexsort((np.arange(len(row)), -row))[:k]
        rows.append(row)
        tops.append([(int(i), float(row[i])) for i in order])
    return rows, tops


def timed_search(client, vector, k: int, params) -> tuple[list[rules.Hit], float]:
    start = time.perf_counter()
    response = client.query_points(
        COLLECTION, query=vector, limit=k, search_params=params, with_payload=False
    )
    elapsed_ms = (time.perf_counter() - start) * 1000
    return [(int(p.id), float(p.score)) for p in response.points], elapsed_ms


def measure(client, queries, rows, tops, k: int, params) -> dict:
    vectors = [q.tolist() for q in queries]
    for vector in vectors[:WARMUP_QUERIES]:
        timed_search(client, vector, k, params)
    recalls, latencies, violations = [], [], 0
    for vector, row, top in zip(vectors, rows, tops):
        hits, elapsed_ms = timed_search(client, vector, k, params)
        recalls.append(rules.recall_at_k(row, top[-1][1], [h[0] for h in hits], k))
        latencies.append(elapsed_ms)
        violations += bool(rules.compare_topk(row, top, hits))
    return {
        "recall_at_k_mean": round(sum(recalls) / len(recalls), 4),
        "recall_at_k_min": round(min(recalls), 4),
        "queries_not_matching_numpy": violations,
        **rules.latency_summary(latencies),
    }


def numpy_latency(base, queries, k: int) -> dict:
    import numpy as np

    samples = []
    for query in queries:
        start = time.perf_counter()
        scores = base @ query
        np.lexsort((np.arange(len(scores)), -scores))[:k]
        samples.append((time.perf_counter() - start) * 1000)
    return rules.latency_summary(samples)


def markdown_table(rows: list[dict], k: int) -> str:
    lines = [
        f"| search | recall@{k} mean | recall@{k} min | queries with top-k != NumPy | median ms | p95 ms |",
        "|---|---|---|---|---|---|",
    ]
    for row in rows:
        lines.append(
            f"| {row['search']} | {row['recall_at_k_mean']:.4f} | {row['recall_at_k_min']:.2f} "
            f"| {row['queries_not_matching_numpy']} | {row['median_ms']} | {row['p95_ms']} |"
        )
    return "\n".join(lines)


def run(
    url: str,
    n: int = synth.N_VECTORS,
    n_queries: int = synth.N_QUERIES,
    k: int = K,
    ef_values: tuple[int, ...] = EF_VALUES,
) -> dict:
    from qdrant_client import models

    base, queries = synth.make_fixture(n, synth.DIM, n_queries, synth.SEED)
    client = common.make_client(url)
    info = build_collection(client, url, base)
    rows, tops = numpy_truth(base, queries, k)

    table = []
    for ef in ef_values:
        result = measure(client, queries, rows, tops, k, models.SearchParams(hnsw_ef=ef))
        table.append({"search": f"hnsw ef={ef}", "ef": ef, **result})
    exact = measure(client, queries, rows, tops, k, models.SearchParams(exact=True))
    table.append({"search": "qdrant exact=True", "ef": None, **exact})
    table.append(
        {
            "search": "numpy full scan (in-process)",
            "ef": None,
            "recall_at_k_mean": 1.0,
            "recall_at_k_min": 1.0,
            "queries_not_matching_numpy": 0,
            **numpy_latency(base, queries, k),
        }
    )
    markdown = markdown_table(table, k)
    print(markdown, file=sys.stderr)
    return {
        "server": common.server_info(url),
        "collection": COLLECTION,
        "collection_info_raw": info,
        "fixture": {
            "seed": synth.SEED,
            "n_vectors": n,
            "dim": synth.DIM,
            "n_queries": n_queries,
            "k": k,
            "base_sha256": synth.fingerprint(base),
            "query_sha256": synth.fingerprint(queries),
            "hnsw": {"m": HNSW_M, "ef_construct": HNSW_EF_CONSTRUCT},
        },
        "rules": {"score_tolerance": rules.SCORE_TOLERANCE},
        "table": table,
        "table_markdown": markdown,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--url", help=f"Qdrant REST URL (env {common.URL_ENV}, else default)")
    args = parser.parse_args(argv)
    report = run(common.resolve_url(args.url))
    json.dump(report, sys.stdout, ensure_ascii=False, indent=2)
    sys.stdout.write("\n")
    exact_row = next(r for r in report["table"] if r["search"] == "qdrant exact=True")
    return 0 if exact_row["queries_not_matching_numpy"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
