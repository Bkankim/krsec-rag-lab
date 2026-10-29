"""Seeded synthetic vectors for the HNSW experiment (issue #6).

Nothing is written to disk: the vectors are regenerated from (seed, n, dim) on every run,
so no large vector file is committed. numpy is imported inside functions only.

    uv run --no-sync python scripts/qdrant_synth.py
"""

from __future__ import annotations

import argparse
import hashlib
import json

SEED = 20261029
N_VECTORS = 50_000
DIM = 128
N_QUERIES = 200


def make_vectors(n: int, dim: int, seed: int):
    """``n`` L2-normalized float32 Gaussian vectors of ``dim`` dims, deterministic in ``seed``."""
    import numpy as np

    rng = np.random.default_rng(seed)
    raw = rng.standard_normal((n, dim), dtype=np.float32)
    return raw / np.linalg.norm(raw, axis=1, keepdims=True)


def make_fixture(n: int = N_VECTORS, dim: int = DIM, n_queries: int = N_QUERIES, seed: int = SEED):
    """Base vectors and queries come from independent seeds (``seed`` and ``seed + 1``)."""
    return make_vectors(n, dim, seed), make_vectors(n_queries, dim, seed + 1)


def fingerprint(array) -> str:
    return hashlib.sha256(array.tobytes()).hexdigest()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--n", type=int, default=N_VECTORS)
    parser.add_argument("--dim", type=int, default=DIM)
    parser.add_argument("--queries", type=int, default=N_QUERIES)
    parser.add_argument("--seed", type=int, default=SEED)
    args = parser.parse_args(argv)
    base, queries = make_fixture(args.n, args.dim, args.queries, args.seed)
    print(
        json.dumps(
            {
                "seed": args.seed,
                "base_shape": list(base.shape),
                "query_shape": list(queries.shape),
                "base_sha256": fingerprint(base),
                "query_sha256": fingerprint(queries),
                "base_megabytes": round(base.nbytes / 1e6, 2),
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
