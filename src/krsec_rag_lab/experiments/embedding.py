"""임베딩 교체 실험 `embedding` - dense 검색의 bge-m3를 다른 다국어 임베딩 모델 하나로 바꾼다.

가설(사전 등록, test 실행 전에 고정): bge-m3 대신 다른 다국어 임베딩 모델 하나로 바꾸면(다른 조건은 같게:
색인 텍스트, 질의 문자열, 전수 내적 검색, 청킹 없음) dense 베이스라인보다 test macro nDCG@10이 높다. 주 트랙은
공개 트랙(기준 = results/baselines/public/dense.jsonl)이고, KISA 트랙(기준 = results/baselines/kisa/dense.jsonl)은
같은 규칙의 보조 판정이다.

후보: 지금 lock의 sentence-transformers·transformers·torch로 CPU에서 로드되는 공개 다국어 모델 2개(CANDIDATES).
로드되지 않는 후보(EXCLUDED)는 제외하고 사유를 적는다. 공개 트랙 격자 = 후보 2개이고, dev macro nDCG@10이 가장
큰 모델을 고른다(같으면 파라미터가 적은 쪽, 그것도 같으면 모델 ID 사전순). KISA 트랙은 공개 트랙 dev에서 고른
모델 하나에 고정한다(커밋된 공개 트랙 manifest의 선택). 기권 τ는 트랙마다 dev에서 baselines와 같은 규칙으로 고른다.
탈락 후보는 test 질의를 인코딩하지 않는다: 하네스가 test를 확정 설정 하나로만 돌린다.

모델 고유로 따르는 것: pooling, 질의·문서 접두사(모델 카드의 정해진 사용법), 최대 길이(모델 최대와 8192 중
작은 값). 유지하는 것: L2 정규화, float32, CPU, 색인 텍스트 그대로(청킹 없음), 정규화 벡터 전수 내적.

numpy·torch·sentence-transformers는 이 모듈이 import 시점에 읽지 않는다. `build_candidate_index` 안에서만 읽는다.
"""

import json
import math
import platform
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path

from krsec_rag_lab.baselines import data, dense
from krsec_rag_lab.experiments import ContractError
from krsec_rag_lab.experiments.harness import RESULTS_DIR, Context

NAME = "embedding"
HYPOTHESIS = (
    "bge-m3 대신 다른 다국어 임베딩 모델 하나로 바꾸면(다른 조건은 같게: 색인 텍스트, 질의 문자열, 전수 내적 검색, "
    "청킹 없음) dense 베이스라인보다 test macro nDCG@10이 높다."
)
VARIANT = "swap"
PRIMARY = ("public", VARIANT)
VARIANTS = {"public": (VARIANT,), "kisa": (VARIANT,)}
BASELINES = {"public": "dense", "kisa": "dense"}

REPO_ROOT = Path(__file__).resolve().parents[3]
MAX_SEQ_CAP = dense.MAX_SEQ_LENGTH  # 모델 최대와 이 값 중 작은 값을 쓴다
DEVICE = dense.DEVICE
BATCH_SIZE = 8
TIE_TOLERANCE = 1e-12  # dev macro가 이 안이면 같은 값으로 본다(부동소수점 합산 순서 차이)
NORM_TOLERANCE = 1e-4  # float32 행의 L2 노름이 1에서 벗어나도 되는 폭
SELECTION_RULE = (
    "공개 트랙 dev macro nDCG@10 최대인 후보. 최댓값이 여럿(abs 1e-12 이내)이면 파라미터 수가 적은 쪽, "
    "그것도 같으면 모델 ID 사전순. KISA 트랙은 공개 트랙 dev에서 고른 모델 하나에 고정(τ만 KISA dev에서 선택)"
)
SCORING = "정규화 벡터의 내적(= 코사인), 코퍼스 전체에 점수를 매김(전수 검색)"


@dataclass(frozen=True)
class Candidate:
    """후보 모델 하나의 사전 등록 설정. 접두사는 모델 카드가 정한 사용법이다."""

    name: str
    revision: str
    parameters: int  # 로드한 모델의 파라미터 수(로드 때 일치를 확인한다)
    pooling: str
    model_max_seq_length: int  # 모델이 지원하는 최대 길이
    query_prefix: str
    document_prefix: str

    @property
    def max_seq_length(self) -> int:
        return min(self.model_max_seq_length, MAX_SEQ_CAP)

    def config(self) -> dict:
        """격자 행이자 test 설정 해시에 들어가는 확정 설정."""
        return {"model": self.name, "revision": self.revision, "parameters": self.parameters}


CANDIDATES = (
    Candidate(
        name="intfloat/multilingual-e5-large",
        revision="3d7cfbdacd47fdda877c5cd8a79fbcc4f2a574f3",
        parameters=559_890_432,
        pooling="mean",
        model_max_seq_length=512,
        query_prefix="query: ",
        document_prefix="passage: ",
    ),
    Candidate(
        name="Qwen/Qwen3-Embedding-0.6B",
        revision="97b0c614be4d77ee51c0cef4e5f07c00f9eb65b3",
        parameters=595_776_512,
        pooling="lasttoken",
        model_max_seq_length=32768,
        query_prefix=(
            "Instruct: Given a web search query, retrieve relevant passages that answer the query\n"
            "Query:"
        ),
        document_prefix="",
    ),
)
EXCLUDED = (
    {
        "name": "google/embeddinggemma-2",
        "revision": "914f7f89142e33e77833254d9c9b90c3cef7303b",
        "reason": (
            "지금 lock의 transformers 5.17.0이 모델 유형 embedding_gemma2를 인식하지 못해 로드에 실패했다"
            "(체크포인트는 transformers 5.18.0.dev0 기준). pyproject.toml·uv.lock을 바꾸지 않으므로 제외"
        ),
    },
)


def candidate_named(name: str) -> Candidate:
    for candidate in CANDIDATES:
        if candidate.name == name:
            return candidate
    raise ContractError(f"unknown embedding candidate {name!r}")


def format_query(candidate: Candidate, text: str) -> str:
    """질의 문자열에 모델의 질의 접두사를 붙인다."""
    return candidate.query_prefix + text


def format_document(candidate: Candidate, text: str) -> str:
    """색인 텍스트에 모델의 문서 접두사를 붙인다."""
    return candidate.document_prefix + text


def unit_norm_deviation(rows: Sequence[Sequence[float]]) -> float:
    """행마다 L2 노름과 1의 차이를 구해 가장 큰 값을 돌려준다(빈 입력은 0)."""
    return max((abs(math.sqrt(sum(x * x for x in row)) - 1.0) for row in rows), default=0.0)


def truncated_count(lengths: Sequence[int], max_seq_length: int) -> int:
    """토큰 길이 목록에서 최대 길이를 넘어 잘리는 문서 수."""
    return sum(1 for length in lengths if length > max_seq_length)


# ------------------------------------------------------------ 격자와 선택


def public_selection(repo_root: Path | None = None) -> dict:
    """공개 트랙 dev에서 고른 확정 설정(커밋된 공개 트랙 manifest). KISA 트랙이 이 모델에 고정된다."""
    root = REPO_ROOT if repo_root is None else repo_root
    path = root / RESULTS_DIR / NAME / "manifest.json"
    entry = None
    if path.exists():
        entry = json.loads(path.read_text(encoding="utf-8"))["runs"].get(f"public/{VARIANT}")
    if entry is None:
        raise ContractError(
            "kisa track uses the model chosen on the public dev; run --track public first"
        )
    return dict(entry["selected"]["config"])


def grid(track: str, variant: str) -> list[dict]:
    if track == "public":
        return [candidate.config() for candidate in CANDIDATES]
    chosen = public_selection()
    if chosen != candidate_named(chosen["model"]).config():
        raise ContractError("public selection does not match the registered candidate")
    return [chosen]


def select(rows: Sequence[Mapping]) -> int:
    """dev macro 최댓값(동점 허용 오차 이내)인 행 중 파라미터가 적은 쪽, 그것도 같으면 모델 ID 사전순."""
    best = max(row["dev_macro_ndcg@10"] for row in rows)
    tied = [
        index
        for index, row in enumerate(rows)
        if math.isclose(row["dev_macro_ndcg@10"], best, rel_tol=0.0, abs_tol=TIE_TOLERANCE)
    ]
    return min(tied, key=lambda i: (rows[i]["config"]["parameters"], rows[i]["config"]["model"]))


def fixed_config(track: str, variant: str, baselines_manifest: Mapping) -> dict:
    """test 잠금 해시에 들어가는 고정 설정: 인코딩 규칙, 후보 사전 등록, 기준선 dense 모델."""
    baseline_model = baselines_manifest["runs"][f"{track}/{BASELINES[track]}"]["config"]["model"]
    return {
        "encoding": {
            "normalized": True,
            "dtype": "float32",
            "device": DEVICE,
            "max_seq_length": f"min(모델 최대, {MAX_SEQ_CAP})",
            "truncation": "최대 길이 초과분은 절단(청킹 없음)",
            "index_text": "코퍼스 색인 텍스트 그대로(문서 접두사만 앞에 붙임)",
            "query": "질의 문자열 그대로(질의 접두사만 앞에 붙임)",
            "score": SCORING,
        },
        "candidates": [asdict(candidate) for candidate in CANDIDATES],
        "baseline_dense": {"name": baseline_model["name"], "revision": baseline_model["revision"]},
    }


# ------------------------------------------------------------ 인덱스


def _load_sentence_transformer(candidate: Candidate):
    import torch
    from sentence_transformers import SentenceTransformer

    return SentenceTransformer(
        candidate.name,
        revision=candidate.revision,
        device=DEVICE,
        model_kwargs={"dtype": torch.float32},
    )


def _pooling_mode(model: object) -> str | None:
    """로드한 모델의 pooling 모듈이 쓰는 방식(없거나 알 수 없으면 None)."""
    try:
        modules = list(model)  # type: ignore[call-overload]
    except TypeError:
        return None
    return next((m.pooling_mode for m in modules if hasattr(m, "pooling_mode")), None)


def build_candidate_index(
    candidate: Candidate,
    texts: Mapping[str, str],
    *,
    batch_size: int = BATCH_SIZE,
    load_model: Callable[[Candidate], object] | None = None,
) -> dense.DenseIndex:
    """후보 모델로 코퍼스를 한 번 인코딩해 행렬을 만든다(`embed` 그룹 필요). 질의는 호출마다 인코딩한다."""
    import numpy as np  # embed 그룹: CI dev 그룹에 없다
    import sentence_transformers
    import torch

    torch.manual_seed(0)
    model = (load_model or _load_sentence_transformer)(candidate)
    model.eval()
    loaded_max = model.max_seq_length
    if loaded_max is None or loaded_max < candidate.max_seq_length:
        raise ContractError(
            f"{candidate.name}: loaded max_seq_length {loaded_max} < registered {candidate.max_seq_length}"
        )
    model.max_seq_length = candidate.max_seq_length
    parameters = sum(p.numel() for p in model.parameters())
    if parameters != candidate.parameters:
        raise ContractError(
            f"{candidate.name}: loaded {parameters} parameters, registered {candidate.parameters}"
        )

    pooling = _pooling_mode(model)
    if pooling is not None and pooling != candidate.pooling:
        raise ContractError(
            f"{candidate.name}: loaded pooling {pooling!r} != {candidate.pooling!r}"
        )

    doc_ids = list(texts)
    doc_texts = [format_document(candidate, texts[doc_id]) for doc_id in doc_ids]
    lengths = [
        len(ids)
        for ids in model.tokenizer(
            doc_texts, add_special_tokens=True, truncation=False, return_attention_mask=False
        )["input_ids"]
    ]
    started = time.perf_counter()
    matrix = model.encode(
        doc_texts,
        batch_size=batch_size,
        normalize_embeddings=True,
        convert_to_numpy=True,
        show_progress_bar=False,
    ).astype(np.float32)
    encode_seconds = time.perf_counter() - started
    deviation = unit_norm_deviation(matrix.tolist())
    if deviation > NORM_TOLERANCE:
        raise ContractError(f"{candidate.name}: document rows are not unit norm ({deviation})")

    def encode_query(query: str):
        return model.encode(
            [format_query(candidate, query)],
            normalize_embeddings=True,
            convert_to_numpy=True,
            show_progress_bar=False,
        )[0].astype(np.float32)

    meta = {
        "model": {
            "name": candidate.name,
            "revision": candidate.revision,
            "parameters": parameters,
            "pooling": candidate.pooling,
            "normalized": True,
            "dtype": str(matrix.dtype),
            "device": DEVICE,
            "dimension": int(matrix.shape[1]),
            "model_max_seq_length": candidate.model_max_seq_length,
            "max_seq_length": candidate.max_seq_length,
            "query_prefix": candidate.query_prefix,
            "document_prefix": candidate.document_prefix,
            "n_truncated_docs": truncated_count(lengths, candidate.max_seq_length),
            "max_doc_tokens": max(lengths, default=0),
            "batch_size": batch_size,
            "max_norm_deviation": deviation,
        },
        "runtime": {
            "torch": torch.__version__,
            "numpy": np.__version__,
            "sentence_transformers": sentence_transformers.__version__,
            "python": platform.python_version(),
        },
        "doc_encode_seconds": encode_seconds,
    }
    return dense.DenseIndex(doc_ids, matrix, encode_query, meta)


@dataclass
class State:
    indexes: dict[str, object]  # 모델 이름 -> 인덱스(.score, .meta)


def setup(ctx: Context) -> State:
    """이 트랙 격자의 모델마다 코퍼스를 한 번 인코딩한다. 공개 트랙은 후보 둘, KISA 트랙은 고른 모델 하나."""
    factory = ctx.dense_factory
    if factory is dense.build_dense_index:  # 하네스 기본값은 bge-m3 빌더다: 이 실험의 빌더로 바꾼다
        factory = build_candidate_index
    indexes = {}
    for config in grid(ctx.track, ctx.variant):
        indexes[config["model"]] = factory(candidate_named(config["model"]), ctx.corpus.texts)
    return State(indexes)


def make_scorer(state: State, config: Mapping) -> Callable[[data.Question], dict[str, float]]:
    index = state.indexes[config["model"]]

    def score(question: data.Question) -> dict[str, float]:
        return index.score(question.query)

    return score


def describe(state: State, config: Mapping) -> dict:
    metas = [index.meta for index in state.indexes.values()]
    return {
        "scoring": SCORING,
        "models_loaded": [
            {**meta["model"], "doc_encode_seconds": meta["doc_encode_seconds"]} for meta in metas
        ],
        "selected_model": config["model"],
        "runtime": metas[0]["runtime"],
        "excluded_candidates": list(EXCLUDED),
        "candidates": "코퍼스 전체",
        "tie_break": "점수가 같으면 문서 ID 오름차순(공통 채점 코드)",
    }
