"""dense 베이스라인 - bge-m3 dense 출력만(sparse·colbert 헤드 미사용).

fixtures/embeddings_demo/manifest.json(#5)과 같은 표현을 쓴다: 모델 BAAI/bge-m3 revision
5617a9f6..., CLS pooling, L2 정규화, float32, max_seq_length 8192, CPU. 입력이 8192 토큰을 넘으면
sentence-transformers가 잘라 쓰고(청킹은 M3), 잘린 문서 수를 센다. 점수는 정규화 벡터의 내적(= 코사인)이다.

numpy·sentence-transformers·torch는 `embed` 그룹이라 CI(dev 그룹)에 없다. 이 모듈의 import 시점에는
읽지 않고 `build_dense_index` 안에서만 읽는다.
"""

import platform
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

MODEL_NAME = "BAAI/bge-m3"
MODEL_REVISION = "5617a9f61b028005a4858fdac845db406aefb181"
MAX_SEQ_LENGTH = 8192
DEVICE = "cpu"
DEFAULT_BATCH_SIZE = 2


@dataclass
class DenseIndex:
    """문서 행렬(행 = 문서, L2 정규화)과 질의 인코더. `matrix @ query_vector`가 점수 벡터다."""

    doc_ids: list[str]
    matrix: Any
    encode_query: Callable[[str], Any]
    meta: dict

    def score(self, query: str) -> dict[str, float]:
        sims = (self.matrix @ self.encode_query(query)).tolist()
        return dict(zip(self.doc_ids, sims, strict=True))


def model_description() -> dict:
    """manifest에 적는 모델·입력 형식·정밀도(고정값). 런타임 버전은 인덱스를 만들 때 채운다."""
    return {
        "name": MODEL_NAME,
        "revision": MODEL_REVISION,
        "pooling": "cls",
        "normalized": True,
        "dtype": "float32",
        "max_seq_length": MAX_SEQ_LENGTH,
        "device": DEVICE,
        "representation": "dense only (bge-m3의 sparse/colbert 헤드는 사용하지 않음)",
        "query_format": "질의 문자열 그대로(지시문 접두사 없음)",
        "document_format": "색인 텍스트 그대로, 8192 토큰 초과분은 절단(청킹 없음)",
    }


def build_dense_index(texts: Mapping[str, str], batch_size: int = DEFAULT_BATCH_SIZE) -> DenseIndex:
    """코퍼스를 한 번 인코딩해 행렬을 만든다(`embed` 그룹 필요). 질의는 호출마다 인코딩한다."""
    import numpy as np  # embed 그룹: CI dev 그룹에 없다
    import sentence_transformers
    import torch
    from sentence_transformers import SentenceTransformer

    torch.manual_seed(0)
    model = SentenceTransformer(MODEL_NAME, revision=MODEL_REVISION, device=DEVICE)
    model.eval()
    model.max_seq_length = MAX_SEQ_LENGTH
    doc_ids = list(texts)
    doc_texts = [texts[doc_id] for doc_id in doc_ids]

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

    def encode_query(query: str) -> Any:
        return model.encode(
            [query], normalize_embeddings=True, convert_to_numpy=True, show_progress_bar=False
        )[0].astype(np.float32)

    meta = {
        "model": {
            **model_description(),
            "dimension": int(matrix.shape[1]),
            "n_truncated_docs": truncated_count(lengths),
            "max_doc_tokens": max(lengths, default=0),
            "batch_size": batch_size,
        },
        "runtime": {
            "torch": torch.__version__,
            "numpy": np.__version__,
            "sentence_transformers": sentence_transformers.__version__,
            "python": platform.python_version(),
        },
        "doc_encode_seconds": encode_seconds,
    }
    return DenseIndex(doc_ids, matrix, encode_query, meta)


def truncated_count(lengths: Sequence[int]) -> int:
    """토큰 길이 목록에서 8192를 넘어 잘리는 문서 수."""
    return sum(1 for length in lengths if length > MAX_SEQ_LENGTH)
