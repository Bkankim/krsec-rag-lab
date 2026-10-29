"""청킹 실험 `chunking` - KISA 공지를 고정 길이 청크로 나눠 bge-m3로 인코딩하고 문서 점수 = 청크 점수 최댓값.

가설(사전 등록, test 실행 전에 고정): KISA 공지를 청크로 나눠 bge-m3로 인코딩하고 문서 점수를 청크 점수의
최댓값으로 두면, 문서 하나를 한 벡터로 만드는 dense 베이스라인보다 test macro nDCG@10이 높다. 주 트랙은
KISA 트랙(기준 = results/baselines/kisa/dense.jsonl)이다. 공개 트랙은 NVD 설명문이 짧아 청킹이 거의 바뀌지
않으므로 판정하지 않고(VARIANTS에 없다), 청크가 2개 이상인 레코드 수만 manifest `description`에 센다.

파싱 고정: 본문은 하네스가 `load_cached_body`로 읽은 정규화 본문 그대로이고 이 모듈은 색인 텍스트(제목 + 줄바꿈 +
본문)를 자르기만 한다. 청크는 bge-m3 토크나이저(모델과 같은 revision) 토큰 수 기준 고정 길이·겹침이고, 토큰
오프셋으로 색인 텍스트의 문자 구간 [시작, 끝)을 정한다. 청크 ID는 `<문서 ID>#<시작>-<끝>`(오프셋만, 텍스트 없음)이다.
모델·pooling·정규화는 기준선과 같다(`baselines.dense.build_dense_index`를 청크 텍스트에 쓴다).

보조 보고(판정에는 쓰지 않는다, eval-protocol 8절): 골든셋 `answers[].evidence`(본문 오프셋)를 제목 길이 + 1만큼 밀어
색인 텍스트 오프셋으로 바꾸고, 1자 이상 겹치는 청크를 정답 청크로 본 설정별 청크 hit@10. 모델 실행 때의 관측값이라
`--compare`가 다시 계산하지 않고 manifest `description`에만 둔다.

numpy·torch·sentence-transformers·transformers는 이 모듈이 import 시점에 읽지 않는다. dense 인덱스는 하네스
문맥의 `dense_factory`가, 토크나이저는 `load_offsets_tokenizer`가 함수 안에서만 읽는다.
"""

import gc
import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field

from krsec_rag_lab.baselines import data, dense
from krsec_rag_lab.experiments import ContractError
from krsec_rag_lab.experiments.harness import Context
from krsec_rag_lab.metrics import hit_at_k, macro_mean, sort_by_score

NAME = "chunking"
HYPOTHESIS = (
    "KISA 공지를 청크로 나눠 bge-m3로 인코딩하고 문서 점수를 청크 점수의 최댓값으로 두면, "
    "문서 하나를 한 벡터로 만드는 dense 베이스라인보다 test macro nDCG@10이 높다."
)
VARIANT = "chunk_max"
PRIMARY = ("kisa", VARIANT)
VARIANTS = {"kisa": (VARIANT,)}
BASELINES = {"kisa": "dense"}

SIZES = (256, 512, 1024)  # 청크 크기(토큰)
OVERLAP_DIVISORS = (None, 8)  # 겹침: 0, 크기의 1/8
CHUNK_HIT_K = 10

TokenOffsets = list[tuple[int, int]]
OffsetsTokenizer = Callable[[Sequence[str]], list[TokenOffsets]]

CHUNK_UNIT = (
    "bge-m3 토크나이저로 색인 텍스트 전체를 한 번 토큰화(특수 토큰 제외)하고, 토큰 `size`개 창을 "
    "`size - overlap` 간격으로 민다. 마지막 창은 텍스트 끝까지(짧을 수 있음), 텍스트가 한 창보다 짧으면 청크 1개. "
    "청크의 문자 구간은 첫 토큰 시작 ~ 마지막 토큰 끝(반개구간)이고 첫 청크는 0에서, 마지막 청크는 텍스트 끝에서 끝난다. "
    "인코딩할 때 청크 텍스트는 다시 토큰화되므로 특수 토큰 2개가 더해진다."
)
CHUNK_ID_FORMAT = "<문서 ID>#<색인 텍스트 문자 시작>-<끝> (반개구간, 텍스트 없음)"
AGGREGATION = "문서 점수 = 그 문서 청크 점수(정규화 벡터 내적)의 최댓값, 후보 = 코퍼스 전체 문서"
EVIDENCE_RULE = (
    "정답 청크 = 정답 문서의 근거 구간(두 판정자 구간 전부, 제목 길이 + 1만큼 이동)과 1자 이상 겹치는 청크; "
    "순위 = 청크 점수 내림차순 전체 순위에서 그 질문 unjudged 문서의 청크를 지운 목록(접기 없음); "
    f"질문 하나의 hit@{CHUNK_HIT_K}가 유형별 평균 -> 유형 단순 평균(macro)"
)


# ------------------------------------------------------------ 청크 경계


@dataclass(frozen=True)
class Chunk:
    chunk_id: str
    doc_id: str
    start: int  # 색인 텍스트 문자 오프셋, 반개구간 [start, end)
    end: int


def config_label(config: Mapping) -> str:
    return f"{config['size']}/{config['overlap']}"


def grid(track: str, variant: str) -> list[dict]:
    return [
        {"size": size, "overlap": 0 if divisor is None else size // divisor}
        for size in SIZES
        for divisor in OVERLAP_DIVISORS
    ]


def make_chunk_id(doc_id: str, start: int, end: int) -> str:
    return f"{doc_id}#{start}-{end}"


def token_windows(n_tokens: int, size: int, overlap: int) -> list[tuple[int, int]]:
    """토큰 번호 구간 [시작, 끝)의 목록. 창이 텍스트 끝에 닿으면 멈추고, 토큰이 없으면 빈 목록이다."""
    if size <= 0 or not 0 <= overlap < size:
        raise ValueError(
            f"need size > 0 and 0 <= overlap < size, got size={size} overlap={overlap}"
        )
    step = size - overlap
    windows = []
    start = 0
    while start < n_tokens:
        end = min(start + size, n_tokens)
        windows.append((start, end))
        if end == n_tokens:
            break
        start += step
    return windows


def chunk_text_spans(
    offsets: Sequence[tuple[int, int]], text_length: int, size: int, overlap: int
) -> list[tuple[int, int]]:
    """토큰 문자 오프셋 목록에서 청크의 문자 구간을 만든다. 토큰이 없으면 텍스트 전체 한 구간이다."""
    windows = token_windows(len(offsets), size, overlap)
    if not windows:
        return [(0, text_length)]
    spans = [(offsets[first][0], offsets[last - 1][1]) for first, last in windows]
    return [
        (0 if i == 0 else s, text_length if i == len(spans) - 1 else e)
        for i, (s, e) in enumerate(spans)
    ]


def build_chunks(
    doc_id: str, text: str, offsets: Sequence[tuple[int, int]], size: int, overlap: int
) -> list[Chunk]:
    return [
        Chunk(make_chunk_id(doc_id, start, end), doc_id, start, end)
        for start, end in chunk_text_spans(offsets, len(text), size, overlap)
    ]


def overlaps(chunk_start: int, chunk_end: int, span_start: int, span_end: int) -> bool:
    """eval-protocol 8절 4단계: 1자 이상 겹침, c_start < e_end and e_start < c_end."""
    return chunk_start < span_end and span_start < chunk_end


def gold_chunk_ids(
    chunks: Sequence[Chunk],
    evidence: Mapping[str, Sequence[tuple[int, int]]],
    shifts: Mapping[str, int],
) -> frozenset[str]:
    """`evidence[문서 ID]` = 본문 오프셋 구간들, `shifts[문서 ID]` = 색인 텍스트에서 밀리는 만큼(제목 길이 + 1)."""
    gold = set()
    for chunk in chunks:
        shift = shifts.get(chunk.doc_id, 0)
        if any(
            overlaps(chunk.start, chunk.end, start + shift, end + shift)
            for start, end in evidence.get(chunk.doc_id, ())
        ):
            gold.add(chunk.chunk_id)
    return frozenset(gold)


def doc_scores_from_chunks(
    chunk_scores: Mapping[str, float], doc_of: Mapping[str, str]
) -> dict[str, float]:
    """문서 점수 = 그 문서 청크 점수의 최댓값."""
    scores: dict[str, float] = {}
    for chunk_id, score in chunk_scores.items():
        doc_id = doc_of[chunk_id]
        if doc_id not in scores or score > scores[doc_id]:
            scores[doc_id] = score
    return scores


# ------------------------------------------------------------ 토크나이저


def load_offsets_tokenizer() -> OffsetsTokenizer:
    """모델과 같은 revision의 bge-m3 토크나이저로 텍스트마다 토큰 문자 오프셋을 돌려준다(`embed` 그룹 필요)."""
    from transformers import AutoTokenizer  # embed 그룹: CI dev 그룹에 없다

    tokenizer = AutoTokenizer.from_pretrained(dense.MODEL_NAME, revision=dense.MODEL_REVISION)
    tokenizer.model_max_length = (
        10**9
    )  # 긴 공지를 한 번에 토큰화한다(절단 경고 방지, 절단하지 않는다)

    def offsets_of(texts: Sequence[str]) -> list[TokenOffsets]:
        encoded = tokenizer(
            list(texts),
            add_special_tokens=False,
            truncation=False,
            return_offsets_mapping=True,
            return_attention_mask=False,
        )
        return [[(int(a), int(b)) for a, b in pairs] for pairs in encoded["offset_mapping"]]

    return offsets_of


# ------------------------------------------------------------ 하네스 인터페이스


def fixed_config(track: str, variant: str, baselines_manifest: Mapping) -> dict:
    """test 잠금 해시에 들어가는 고정 설정. 기준선의 dense 모델·revision과 같아야 한다."""
    model = baselines_manifest["runs"][f"{track}/{BASELINES[track]}"]["config"]["model"]
    if (model["name"], model["revision"]) != (dense.MODEL_NAME, dense.MODEL_REVISION):
        raise ContractError(
            f"baseline dense model {model['name']}@{model['revision']} != "
            f"{dense.MODEL_NAME}@{dense.MODEL_REVISION}"
        )
    return {
        "chunk_unit": CHUNK_UNIT,
        "chunk_id_format": CHUNK_ID_FORMAT,
        "aggregation": AGGREGATION,
        "dense": {"name": dense.MODEL_NAME, "revision": dense.MODEL_REVISION},
        "tokenizer": {"name": dense.MODEL_NAME, "revision": dense.MODEL_REVISION},
    }


def _read_evidence(ctx: Context):
    """골든셋에서 질문별 {문서 ID: [(시작, 끝)]}과 문서별 색인 텍스트 이동량을 읽는다(본문 없음)."""
    manifest = json.loads((ctx.root / data.KISA_MANIFEST).read_text(encoding="utf-8"))
    parser_version = manifest["parser_version"]
    titles = {
        str(row["nttId"]): row["title"] for row in data.read_jsonl(ctx.root / data.KISA_METADATA)
    }
    shifts = {}
    for doc_id, text in ctx.corpus.texts.items():
        title = titles[doc_id]
        if not text.startswith(f"{title}\n"):
            raise ContractError(f"{doc_id}: indexed text does not start with 'title\\n'")
        shifts[doc_id] = len(title) + 1
    evidence: dict[str, dict[str, list[tuple[int, int]]]] = {}
    for row in data.read_jsonl(ctx.root / data.KISA_GOLDEN):
        per_doc: dict[str, list[tuple[int, int]]] = {}
        for answer in row["answers"]:
            for span in answer.get("evidence", ()):
                if span["parser_version"] != parser_version:
                    raise ContractError(f"{row['question_id']}: evidence parser_version differs")
                per_doc.setdefault(answer["doc_id"], []).append((span["start"], span["end"]))
        evidence[row["question_id"]] = per_doc
    return evidence, shifts


@dataclass
class State:
    texts: dict[str, str]
    dense_factory: Callable[..., object]
    chunks: dict[str, list[Chunk]]  # 설정 라벨 -> 청크
    token_counts: dict[str, int]  # 문서 ID -> 토큰 수
    questions: list[data.Question]
    evidence: dict[str, dict[str, list[tuple[int, int]]]]
    shifts: dict[str, int]
    public_multi_chunk: dict[str, int] | None
    live: tuple[str, object] | None = None  # 지금 메모리에 있는 (설정 라벨, dense 인덱스) 하나
    metas: dict[str, dict] = field(default_factory=dict)
    rankings: dict[tuple[str, str], list[str]] = field(default_factory=dict)

    def index_for(self, label: str):
        """설정의 dense 인덱스. 모델이 설정마다 하나씩 쌓이지 않도록 한 번에 하나만 들고 있는다."""
        if self.live is not None and self.live[0] == label:
            return self.live[1]
        self.live = None
        gc.collect()
        chunks = self.chunks[label]
        texts = {c.chunk_id: self.texts[c.doc_id][c.start : c.end] for c in chunks}
        index = self.dense_factory(texts)
        self.live = (label, index)
        self.metas[label] = getattr(index, "meta", {})
        return index


def setup(ctx: Context) -> State:
    """색인 텍스트를 한 번 토큰화해 설정마다 청크 경계를 만든다. dense 인덱스는 점수를 낼 때 설정별로 만든다."""
    tokenize = load_offsets_tokenizer()
    doc_ids = list(ctx.corpus.texts)
    offsets = dict(zip(doc_ids, tokenize([ctx.corpus.texts[d] for d in doc_ids]), strict=True))
    configs = grid(ctx.track, ctx.variant)
    chunks = {
        config_label(config): [
            chunk
            for doc_id in doc_ids
            for chunk in build_chunks(
                doc_id, ctx.corpus.texts[doc_id], offsets[doc_id], config["size"], config["overlap"]
            )
        ]
        for config in configs
    }
    public_multi_chunk = None
    if (ctx.root / data.PUBLIC_CORPUS).exists():
        public = data.load_public_corpus(ctx.root)
        public_offsets = tokenize(list(public.texts.values()))
        public_multi_chunk = {
            config_label(config): sum(
                1
                for text, pairs in zip(public.texts.values(), public_offsets, strict=True)
                if len(chunk_text_spans(pairs, len(text), config["size"], config["overlap"])) >= 2
            )
            for config in configs
        }
    evidence, shifts = _read_evidence(ctx)
    return State(
        texts=ctx.corpus.texts,
        dense_factory=ctx.dense_factory,
        chunks=chunks,
        token_counts={doc_id: len(offsets[doc_id]) for doc_id in doc_ids},
        questions=ctx.questions,
        evidence=evidence,
        shifts=shifts,
        public_multi_chunk=public_multi_chunk,
    )


def make_scorer(state: State, config: Mapping) -> Callable[[data.Question], dict[str, float]]:
    label = config_label(config)
    doc_of = {chunk.chunk_id: chunk.doc_id for chunk in state.chunks[label]}
    state.index_for(label)  # 인덱스를 지금 만든다(앞 설정의 모델은 여기서 내려간다)

    def score(question: data.Question) -> dict[str, float]:
        chunk_scores = state.index_for(label).score(question.query)
        state.rankings[(label, question.question_id)] = sort_by_score(chunk_scores)
        return doc_scores_from_chunks(chunk_scores, doc_of)

    return score


# ------------------------------------------------------------ 보조 보고(청크 단위)


def chunk_hit_report(state: State, label: str) -> dict:
    """설정 하나의 청크 hit@10: 분할별 macro와 유형별 평균. 순위를 낸 질문(dev 전부, test는 확정 설정만)만 센다."""
    chunks = state.chunks[label]
    by_doc: dict[str, list[Chunk]] = {}
    for chunk in chunks:
        by_doc.setdefault(chunk.doc_id, []).append(chunk)
    report: dict[str, dict] = {}
    for split in data.SPLITS:
        per_type: dict[str, list[float | None]] = {}
        n_questions = n_with_gold_chunks = 0
        for question in state.questions:
            ranking = state.rankings.get((label, question.question_id))
            if ranking is None or question.split != split or question.excluded or not question.gold:
                continue
            gold_ids = gold_chunk_ids(
                [c for doc_id in question.gold for c in by_doc[doc_id]],
                state.evidence.get(question.question_id, {}),
                state.shifts,
            )
            skipped = {c.chunk_id for doc_id in question.unjudged for c in by_doc[doc_id]}
            condensed = [chunk_id for chunk_id in ranking if chunk_id not in skipped]
            value = hit_at_k(condensed, gold_ids, CHUNK_HIT_K)
            per_type.setdefault(question.query_type, []).append(value)
            n_questions += 1
            n_with_gold_chunks += value is not None
        if n_questions:
            report[split] = {
                f"macro_hit@{CHUNK_HIT_K}": macro_mean(per_type),
                "by_type": {
                    query_type: {
                        "mean": _mean(values),
                        "n_with_gold_chunks": sum(v is not None for v in values),
                        "n_questions": len(values),
                    }
                    for query_type, values in sorted(per_type.items())
                },
                "n_questions": n_questions,
                "n_with_gold_chunks": n_with_gold_chunks,
            }
    return report


def _mean(values: Sequence[float | None]) -> float | None:
    defined = [v for v in values if v is not None]
    return sum(defined) / len(defined) if defined else None


def chunk_stats(state: State, label: str) -> dict:
    per_doc: dict[str, int] = {}
    for chunk in state.chunks[label]:
        per_doc[chunk.doc_id] = per_doc.get(chunk.doc_id, 0) + 1
    return {
        "n_chunks": len(state.chunks[label]),
        "n_docs": len(per_doc),
        "n_docs_with_2plus_chunks": sum(1 for n in per_doc.values() if n >= 2),
        "max_chunks_per_doc": max(per_doc.values(), default=0),
    }


def describe(state: State, config: Mapping) -> dict:
    labels = list(state.chunks)
    built = [state.metas[label] for label in labels if label in state.metas]
    first = built[0] if built else {}
    model = {
        **dense.model_description(),
        "document_format": "청크 텍스트(색인 텍스트의 문자 구간), 청크마다 인코딩, 문서 절단 없음",
    }
    return {
        "chunking": {
            "unit": CHUNK_UNIT,
            "chunk_id": CHUNK_ID_FORMAT,
            "aggregation": AGGREGATION,
            "grid_labels": "size/overlap (토큰)",
        },
        "dense": {
            "model": model,
            "runtime": first.get("runtime", {}),
            "doc_encode_seconds_by_config": {
                label: state.metas[label].get("doc_encode_seconds")
                for label in labels
                if label in state.metas
            },
            "note": "dense 인덱스는 설정마다 점수를 내기 직전에 만든다(timing.index_seconds는 토큰화·청크 경계만)",
        },
        "tokens": {
            "n_docs": len(state.token_counts),
            "max_doc_tokens": max(state.token_counts.values(), default=0),
            "n_docs_over_8192_tokens": dense.truncated_count(list(state.token_counts.values())),
            "note": "색인 텍스트 전체 토큰화(특수 토큰 제외) 기준",
        },
        "chunk_stats": {label: chunk_stats(state, label) for label in labels},
        "public_records_with_2plus_chunks": state.public_multi_chunk,
        "chunk_hit": {
            "rule": EVIDENCE_RULE,
            "observed_on": "모델 실행 때의 관측값(--compare 범위 밖). dev는 격자 전체, test는 확정 설정만",
            "by_config": {label: chunk_hit_report(state, label) for label in labels},
        },
    }
