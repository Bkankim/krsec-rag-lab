"""하이브리드 실험 `hybrid` - BM25와 dense(bge-m3)를 RRF로 합친다.

가설(사전 등록, test 실행 전에 고정): BM25와 dense를 RRF로 합친 순위는 BM25 단독보다 test macro
nDCG@10이 높다. 주 트랙은 공개 트랙(기준 = results/baselines/public/bm25.jsonl)이고, KISA 트랙은 같은 규칙의
보조 판정이다.

구성: BM25는 기준선 manifest(`results/baselines/manifest.json`)에 확정된 트랙별 k1·b와 `bm25-tok-v1`
토큰화를 그대로 쓰고, dense는 기준선과 같은 bge-m3 표현(`baselines.dense.build_dense_index`)이다.
RRF 점수 = sum over 검색기 1 / (k + rank). 순위는 각 검색기의 전체 순위(unjudged 제거 전, BM25는 일치
문서만)이고, 한 검색기에 없는 문서는 그 검색기 항이 없다. k는 {10, 30, 60, 100}에서 dev macro nDCG@10이
가장 큰 값이고, 최댓값이 여럿이면 60, 60이 없으면 그중 가장 작은 값이다. 기권 τ는 기준선과 같은 규칙으로
dev에서 고른다(점수는 RRF 점수의 원래 1위 점수).

numpy·torch·sentence-transformers는 이 모듈이 읽지 않는다. dense 인덱스는 하네스 문맥의
`dense_factory`(기본 `baselines.dense.build_dense_index`)가 함수 안에서만 읽는다.
"""

import math
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass

from krsec_rag_lab.baselines import data, dense
from krsec_rag_lab.baselines.bm25 import BM25Index
from krsec_rag_lab.baselines.tokens import TOKENIZER_ID
from krsec_rag_lab.experiments import ContractError
from krsec_rag_lab.experiments.harness import Context
from krsec_rag_lab.metrics import sort_by_score

NAME = "hybrid"
HYPOTHESIS = "BM25와 dense(bge-m3)를 RRF로 합친 순위는 BM25 단독보다 test macro nDCG@10이 높다."
PRIMARY = ("public", "rrf")
VARIANTS = {"public": ("rrf",), "kisa": ("rrf",)}
BASELINES = {"public": "bm25", "kisa": "bm25"}

K_GRID = (10, 30, 60, 100)
DEFAULT_K = 60
TIE_TOLERANCE = 1e-12  # dev macro가 이 안이면 같은 값으로 본다(부동소수점 합산 순서 차이)
SELECTION_RULE = (
    "트랙마다 dev macro nDCG@10 최대인 k. 최댓값이 여럿(abs 1e-12 이내)이면 60, 60이 그중에 없으면 "
    "그중 가장 작은 k"
)
FUSION = (
    "RRF: score(d) = sum over {BM25, dense} 1 / (k + rank), rank는 각 검색기의 전체 순위(1부터)"
)


def grid(track: str, variant: str) -> list[dict]:
    return [{"k": k} for k in K_GRID]


def rrf_fuse(rankings: Sequence[Sequence[str]], k: int) -> dict[str, float]:
    """RRF 점수. `rankings`의 각 목록은 한 검색기의 순위(1위부터)이고, 목록에 없는 문서는 그 항이 없다."""
    scores: dict[str, float] = {}
    for ranking in rankings:
        for rank, doc_id in enumerate(ranking, start=1):
            scores[doc_id] = scores.get(doc_id, 0.0) + 1.0 / (k + rank)
    return scores


def select(rows: Sequence[Mapping]) -> int:
    """dev macro 최댓값이 여럿이면 k=60, 60이 그중에 없으면 가장 작은 k의 행 인덱스."""
    best = max(row["dev_macro_ndcg@10"] for row in rows)
    tied = [
        index
        for index, row in enumerate(rows)
        if math.isclose(row["dev_macro_ndcg@10"], best, rel_tol=0.0, abs_tol=TIE_TOLERANCE)
    ]
    if len(tied) == 1:
        return tied[0]
    for index in tied:
        if rows[index]["config"]["k"] == DEFAULT_K:
            return index
    return min(tied, key=lambda index: rows[index]["config"]["k"])


def _baseline_bm25(track: str, baselines_manifest: Mapping) -> Mapping:
    entry = baselines_manifest["runs"][f"{track}/{BASELINES[track]}"]
    tokenizer = entry["config"]["tokenizer"]["id"]
    if tokenizer != TOKENIZER_ID:
        raise ContractError(f"baseline tokenizer {tokenizer!r} != {TOKENIZER_ID!r}")
    return entry["selected"]


def fixed_config(track: str, variant: str, baselines_manifest: Mapping) -> dict:
    """test 잠금 해시에 들어가는 고정 설정: 기준선에서 가져온 BM25 k1·b와 dense 모델."""
    selected = _baseline_bm25(track, baselines_manifest)
    return {
        "fusion": FUSION,
        "bm25": {"k1": selected["k1"], "b": selected["b"], "tokenizer": TOKENIZER_ID},
        "dense": {"name": dense.MODEL_NAME, "revision": dense.MODEL_REVISION},
    }


@dataclass
class State:
    bm25: BM25Index
    dense: object


def setup(ctx: Context) -> State:
    """BM25와 dense 인덱스를 한 번 만든다(dense는 `dense_factory`, 모델 필요)."""
    params = _baseline_bm25(ctx.track, ctx.baselines_manifest)
    bm25 = BM25Index(ctx.corpus.texts, k1=params["k1"], b=params["b"])
    return State(bm25, ctx.dense_factory(ctx.corpus.texts))


def make_scorer(state: State, config: Mapping) -> Callable[[data.Question], dict[str, float]]:
    k = config["k"]

    def score(question: data.Question) -> dict[str, float]:
        bm25_ranking = sort_by_score(state.bm25.score(question.query))
        dense_ranking = sort_by_score(state.dense.score(question.query))
        return rrf_fuse([bm25_ranking, dense_ranking], k)

    return score


def describe(state: State, config: Mapping) -> dict:
    meta = state.dense.meta
    return {
        "fusion": FUSION,
        "bm25": {
            "k1": state.bm25.k1,
            "b": state.bm25.b,
            "tokenizer": TOKENIZER_ID,
            "candidates": "질의 토큰이 하나라도 든 문서만 순위에 든다(일치가 없으면 빈 순위)",
        },
        "dense": {
            "model": meta["model"],
            "runtime": meta["runtime"],
            "doc_encode_seconds": meta["doc_encode_seconds"],
            "candidates": "코퍼스 전체",
        },
        "tie_break": "RRF 점수가 같으면 문서 ID 오름차순(공통 채점 코드)",
    }
