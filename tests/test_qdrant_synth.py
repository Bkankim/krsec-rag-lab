"""Seeded synthetic vector generator. numpy is imported inside the tests (skipped in CI)."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import qdrant_synth as synth


@pytest.fixture
def np():
    return pytest.importorskip("numpy")


def test_same_seed_gives_identical_bytes(np):
    first = synth.make_vectors(100, 16, seed=7)
    second = synth.make_vectors(100, 16, seed=7)
    assert synth.fingerprint(first) == synth.fingerprint(second)


def test_different_seed_changes_vectors(np):
    assert synth.fingerprint(synth.make_vectors(100, 16, 7)) != synth.fingerprint(
        synth.make_vectors(100, 16, 8)
    )


def test_vectors_are_float32_and_unit_length(np):
    vectors = synth.make_vectors(200, 32, seed=1)
    assert vectors.dtype == np.float32
    assert np.allclose(np.linalg.norm(vectors, axis=1), 1.0, atol=1e-6)


def test_base_and_query_use_independent_seeds(np):
    base, queries = synth.make_fixture(n=50, dim=16, n_queries=5, seed=3)
    assert base.shape == (50, 16)
    assert queries.shape == (5, 16)
    assert not np.array_equal(base[:5], queries)
