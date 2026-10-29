"""리랭커 실험 `rerank` - BM25 상위 N건을 cross-encoder(bge-reranker-v2-m3)로 다시 정렬한다.

가설(사전 등록, test 실행 전에 고정): cross-encoder 리랭커(`BAAI/bge-reranker-v2-m3`, revision 고정)로
BM25 상위 N건을 다시 정렬하면, 같은 후보군의 BM25 순서보다 test macro nDCG@10이 높다. 주 트랙은 공개
트랙(기준 = results/baselines/public/bm25.jsonl)이고, KISA 트랙은 같은 규칙의 보조 판정이다.

동일 후보군: 후보는 기준선 manifest의 k1·b로 이 실험이 다시 계산한 BM25 전체 순위(unjudged 제거 전,
질의 토큰이 하나라도 든 문서만)의 상위 N건이다. 리랭커는 그 집합 안의 순서만 바꾸고 후보를 더하거나
빼지 않는다. N 밖 문서는 BM25 순서 그대로 N건 뒤에 둔다(후보가 N 미만이면 그만큼만). 그래서 recall@N은
기준과 같고 바뀌는 것은 순서뿐이다.

점수: 후보 N건은 리랭커 원점수(로짓, 활성화 함수 없음)를 그대로 쓰고, N 밖 문서는 BM25 순서를 유지하면서
`min(후보 점수) - 1 - BM25 순위 * 1e-6`을 받는다(항상 모든 후보보다 엄격히 작다). 그래서 `top1_score_raw`는
리랭커 원점수 1위다. N은 {20, 50, 100}에서 dev macro nDCG@10 최대, 같으면 작은 N이다.

numpy·torch·sentence-transformers는 이 모듈이 import 시점에 읽지 않는다. 리랭커는 `build_reranker`
안에서만 읽는다(테스트는 이 함수를 가짜로 바꾼다).
"""

import platform
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Protocol

from krsec_rag_lab.baselines import data
from krsec_rag_lab.baselines.bm25 import BM25Index
from krsec_rag_lab.baselines.tokens import TOKENIZER_ID
from krsec_rag_lab.experiments import ContractError
from krsec_rag_lab.experiments.harness import Context
from krsec_rag_lab.metrics import sort_by_score

NAME = "rerank"
HYPOTHESIS = (
    "cross-encoder 리랭커(BAAI/bge-reranker-v2-m3)로 BM25 상위 N건을 다시 정렬하면 "
    "같은 후보군의 BM25 순서보다 test macro nDCG@10이 높다."
)
PRIMARY = ("public", "rerank")
VARIANTS = {"public": ("rerank",), "kisa": ("rerank",)}
BASELINES = {"public": "bm25", "kisa": "bm25"}

N_GRID = (20, 50, 100)
SELECTION_RULE = "트랙마다 dev macro nDCG@10 최대인 N. 같으면 격자 순서(N 오름차순)에서 앞선 작은 N"
MODEL_NAME = "BAAI/bge-reranker-v2-m3"
MODEL_REVISION = "953dc6f6f85a1b2dbfca4c34a2796e7dde08d41e"
MAX_LENGTH = 512
BATCH_SIZE = 16
DEVICE = "cpu"
TAIL_STEP = 1e-6
SCORE_RULE = (
    "후보 N건: 리랭커 원점수(로짓). N 밖: min(후보 점수) - 1 - BM25 순위 * 1e-6 (BM25 순서 유지, "
    "모든 후보보다 엄격히 작다)"
)
PAIR_FORMAT = (
    "(질의 문자열 그대로, 색인 텍스트 그대로) 쌍, 지시문 접두사 없음, 512 토큰 초과분은 절단"
)


def grid(track: str, variant: str) -> list[dict]:
    return [{"n": n} for n in N_GRID]


def combine_scores(ranking: Sequence[str], raw_scores: Sequence[float], n: int) -> dict[str, float]:
    """BM25 전체 순위(1위부터)의 상위 n건에 리랭커 원점수를 주고, 나머지는 BM25 순서를 지키며 그보다 작게 둔다.

    `raw_scores`는 `ranking[:n]`의 리랭커 점수(같은 순서)다. 후보가 n 미만이면 있는 만큼만이다.
    """
    candidates = list(ranking[:n])
    if len(raw_scores) != len(candidates):
        raise ContractError(
            f"reranker returned {len(raw_scores)} scores for {len(candidates)} docs"
        )
    scores = {doc_id: float(score) for doc_id, score in zip(candidates, raw_scores, strict=True)}
    if not scores:
        return {}
    floor = min(scores.values()) - 1.0
    for rank, doc_id in enumerate(ranking[len(candidates) :], start=len(candidates) + 1):
        scores[doc_id] = floor - rank * TAIL_STEP
    return scores


def _baseline_bm25(track: str, baselines_manifest: Mapping) -> Mapping:
    entry = baselines_manifest["runs"][f"{track}/{BASELINES[track]}"]
    tokenizer = entry["config"]["tokenizer"]["id"]
    if tokenizer != TOKENIZER_ID:
        raise ContractError(f"baseline tokenizer {tokenizer!r} != {TOKENIZER_ID!r}")
    return entry["selected"]


def fixed_config(track: str, variant: str, baselines_manifest: Mapping) -> dict:
    """test 잠금 해시에 들어가는 고정 설정: 기준선에서 가져온 BM25 k1·b와 리랭커 모델·입력 형식."""
    selected = _baseline_bm25(track, baselines_manifest)
    return {
        "candidates": "BM25 전체 순위(unjudged 제거 전)의 상위 N건",
        "score": SCORE_RULE,
        "bm25": {"k1": selected["k1"], "b": selected["b"], "tokenizer": TOKENIZER_ID},
        "reranker": {
            "name": MODEL_NAME,
            "revision": MODEL_REVISION,
            "max_length": MAX_LENGTH,
            "activation": "none (로짓 원점수)",
            "pair_format": PAIR_FORMAT,
        },
    }


class Reranker(Protocol):
    """`build_reranker`가 돌려주는 객체. 질의와 문서 ID 목록을 받아 (원점수 목록, 절단된 쌍 수)를 낸다."""

    meta: dict

    def score(self, query: str, doc_ids: Sequence[str]) -> tuple[list[float], int]: ...


class CrossEncoderReranker:
    """sentence-transformers CrossEncoder 래퍼(`embed` 그룹). 점수는 활성화 함수 없는 로짓이다."""

    def __init__(self, texts: Mapping[str, str]):
        import numpy as np  # embed 그룹: CI dev 그룹에 없다
        import sentence_transformers
        import torch
        import transformers
        from sentence_transformers import CrossEncoder

        model = CrossEncoder(
            MODEL_NAME,
            revision=MODEL_REVISION,
            device=DEVICE,
            max_length=MAX_LENGTH,
            activation_fn=torch.nn.Identity(),
        )
        model.eval()
        self._model = model
        self._texts = texts
        tokenizer = model.tokenizer
        self._tokenizer = tokenizer
        self._specials = tokenizer.num_special_tokens_to_add(pair=True)
        doc_ids = list(texts)
        lengths = [
            len(ids)
            for ids in tokenizer(
                [texts[doc_id] for doc_id in doc_ids],
                add_special_tokens=False,
                truncation=False,
                return_attention_mask=False,
            )["input_ids"]
        ]
        self._doc_tokens = dict(zip(doc_ids, lengths, strict=True))
        over_limit = sum(1 for n in lengths if n + self._specials > MAX_LENGTH)
        self.meta = {
            "runtime": {
                "torch": torch.__version__,
                "numpy": np.__version__,
                "sentence_transformers": sentence_transformers.__version__,
                "transformers": transformers.__version__,
                "python": platform.python_version(),
            },
            "batch_size": BATCH_SIZE,
            "n_docs": len(lengths),
            "max_doc_tokens": max(lengths, default=0),
            "n_docs_truncated_even_with_empty_query": over_limit,
        }

    def score(self, query: str, doc_ids: Sequence[str]) -> tuple[list[float], int]:
        if not doc_ids:
            return [], 0
        query_tokens = len(
            self._tokenizer(query, add_special_tokens=False, truncation=False)["input_ids"]
        )
        truncated = sum(
            1
            for doc_id in doc_ids
            if query_tokens + self._doc_tokens[doc_id] + self._specials > MAX_LENGTH
        )
        scores = self._model.predict(
            [(query, self._texts[doc_id]) for doc_id in doc_ids],
            batch_size=BATCH_SIZE,
            show_progress_bar=False,
        )
        return [float(score) for score in scores], truncated


def build_reranker(texts: Mapping[str, str]) -> Reranker:
    """리랭커를 한 번 만든다(`embed` 그룹, 모델 필요). 테스트는 이 함수를 가짜로 바꾼다."""
    return CrossEncoderReranker(texts)


@dataclass
class State:
    bm25: BM25Index
    reranker: Reranker
    stats: dict[int, dict[str, int]] = field(default_factory=dict)


def setup(ctx: Context) -> State:
    """BM25 인덱스(기준선 k1·b)와 리랭커를 한 번 만든다(리랭커는 모델 필요)."""
    params = _baseline_bm25(ctx.track, ctx.baselines_manifest)
    bm25 = BM25Index(ctx.corpus.texts, k1=params["k1"], b=params["b"])
    return State(bm25, build_reranker(ctx.corpus.texts))


def make_scorer(state: State, config: Mapping) -> Callable[[data.Question], dict[str, float]]:
    n = config["n"]
    stats = state.stats.setdefault(n, {"questions": 0, "pairs": 0, "truncated_pairs": 0})

    def score(question: data.Question) -> dict[str, float]:
        ranking = sort_by_score(state.bm25.score(question.query))
        candidates = ranking[:n]
        raw, truncated = state.reranker.score(question.query, candidates)
        stats["questions"] += 1
        stats["pairs"] += len(candidates)
        stats["truncated_pairs"] += truncated
        return combine_scores(ranking, raw, n)

    return score


def describe(state: State, config: Mapping) -> dict:
    n = config["n"]
    return {
        "candidates": (
            "기준선 BM25 설정으로 다시 계산한 전체 순위(질의 토큰이 하나라도 든 문서만)의 상위 N건. "
            "저장본 상위 100건으로 후보를 만들지 않는다"
        ),
        "score": SCORE_RULE,
        "bm25": {"k1": state.bm25.k1, "b": state.bm25.b, "tokenizer": TOKENIZER_ID},
        "reranker": {
            "name": MODEL_NAME,
            "revision": MODEL_REVISION,
            "max_length": MAX_LENGTH,
            "activation": "none (로짓 원점수)",
            "device": DEVICE,
            **state.reranker.meta,
        },
        "selected_n_usage": {
            **state.stats.get(n, {"questions": 0, "pairs": 0, "truncated_pairs": 0}),
            "scope": "이 실행이 선택한 N으로 채점한 질문 전체(--split all이면 dev 격자 단계와 test를 합산)",
        },
        "tie_break": "점수가 같으면 문서 ID 오름차순(공통 채점 코드)",
    }
