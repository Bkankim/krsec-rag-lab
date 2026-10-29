"""프레임워크 없는 생성 파이프라인 - 검색 -> 문맥 -> 프롬프트 -> LLM -> 계약 파싱 -> 질문별 행 -> 지표.

공개 함수(형제 티켓이 그대로 부른다. 정본 시그니처는 docs/m5-generation.md):

- `build_index(track, root, load_body)`: #11 BM25 색인(트랙별 k1·b, 토큰화는 baselines 그대로).
- `retrieve(index, question, k)`: 질문의 `unjudged`를 지우기 전 BM25 점수를 (-점수, 문서 ID)로 정렬한 상위 k개.
- `build_context(track, doc_ids, load_body)`: `[문서 ID]` 머리 + 색인 텍스트(문서당 문자 상한), 잘린 문서 ID.
- `build_prompt(question, context_text)`: 채팅 메시지. `prompt_fingerprint()`가 그 해시다.
- `parse_answer(raw, allowed_ids)`: 출력 계약 `{answer, abstain, citations}` 파싱.
- `generate(question, context_text, allowed_ids, llm)`: LLM 호출 + 파싱 + 파싱 실패 시 재질의 1회.
- `run_question(...)`: 위 함수를 묶어 질문 하나의 결과 행을 만든다.

KISA 트랙의 본문은 호출자가 넘기는 `load_body`로만 읽는다. 커밋하는 행에는 KISA 답변 원문도, 계약 밖
문자열(무효 인용)도 남기지 않는다: 문맥에 있던 문서 ID만 `citations`에 남고 나머지는 개수만 센다.
표준 라이브러리만 쓴다(Ollama 호출은 llm.py).
"""

import hashlib
import json
import math
import os
import statistics
import tempfile
import time
from collections.abc import Callable, Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from krsec_rag_lab.baselines import data, runner
from krsec_rag_lab.baselines.bm25 import BM25Index
from krsec_rag_lab.generation.llm import LLM, LLMResponse
from krsec_rag_lab.metrics import sort_by_score

SCHEMA = "m5-generation-v1"
TOPK_SCHEMA = "m5-topk-v1"
RESULTS_DIR = Path("results/m5/generation")
BASELINES_MANIFEST = Path("results/baselines/manifest.json")
KS = (1, 3, 5)
DOC_CHAR_CAP = 3000
SUCCESS_FLOOR = 0.8
TOLERANCE = 1e-9
SPLIT_VALUES = (*data.SPLITS, "all")

STATUS_OK = "ok"
STATUS_OVERFLOW = "context_overflow"
PARSE_FAILED_PREFIX = "parse_failed:"
PARSE_REASONS = (
    "empty",
    "not_json",
    "not_object",
    "missing_answer",
    "missing_abstain",
    "missing_citations",
    "bad_answer",
    "bad_abstain",
    "bad_citations",
)

ROW_KEYS = (
    "question_id",
    "split",
    "query_type",
    "k",
    "status",
    "abstain",
    "citations",
    "n_invalid_citations",
    "retrieved",
    "truncated",
    "n_retrieved",
    "prompt_tokens",
    "completion_tokens",
    "latency_ms",
    "context_sha256",
    "n_attempts",
    "context_chars",
)
PUBLIC_ROW_KEYS = (*ROW_KEYS, "answer")

SYSTEM_PROMPT = (
    "당신은 보안 문서 질의응답 도우미입니다. 사용자가 준 [문서] 목록의 내용만 근거로 질문에 한국어로 "
    "답하세요. 문서에 질문의 답이 없으면 추측하지 말고 기권하세요.\n"
    "출력은 JSON 객체 하나만 쓰고 다른 글자는 쓰지 마세요: "
    '{"answer": 문자열, "abstain": true 또는 false, "citations": [문서 ID 문자열, ...]}\n'
    "- answer: 질문에 대한 답. 기권하면 빈 문자열.\n"
    "- abstain: 문서에 답이 없어 기권하면 true, 답하면 false.\n"
    "- citations: 답의 근거로 쓴 문서의 ID 목록. [문서 ID] 머리에 적힌 ID를 그대로 쓰고, 기권하면 "
    "빈 목록."
)
USER_TEMPLATE = "[문서]\n{context}\n\n[질문]\n{question}"
EMPTY_CONTEXT = "(검색된 문서 없음)"
RETRY_TEMPLATE = (
    "직전 응답이 출력 형식 규칙을 어겼습니다(사유: {reason}). 위 규칙대로 JSON 객체 하나만 다시 "
    "출력하세요."
)
DOC_SEPARATOR = "\n\n"

TextLoader = Callable[[str], str]
Messages = list[dict[str, str]]


# ------------------------------------------------------------------ 검색


class GenerationIndex(BM25Index):
    """BM25 색인 + 문서 ID -> 색인 텍스트. `retrieve`는 점수 함수(`score`)만 쓴다."""

    def __init__(self, track: str, texts: Mapping[str, str], k1: float, b: float):
        super().__init__(texts, k1=k1, b=b)
        self.track = track
        self.texts = dict(texts)

    def text(self, doc_id: str) -> str:
        return self.texts[doc_id]


def bm25_params(track: str, root: Path) -> tuple[float, float]:
    """#11 베이스라인 manifest에서 트랙별 BM25 k1·b(dev에서 고른 값)를 읽는다."""
    manifest = json.loads((root / BASELINES_MANIFEST).read_text(encoding="utf-8"))
    selected = manifest["runs"][f"{track}/bm25"]["selected"]
    return float(selected["k1"]), float(selected["b"])


def build_index(
    track: str, root: Path, load_body: data.BodyLoader | None = None
) -> GenerationIndex:
    """트랙의 코퍼스로 #11과 같은 BM25 색인을 다시 만든다. KISA는 `load_body(nttId, 문서 항목)`이 필요하다."""
    if track == "public":
        corpus = data.load_public_corpus(root)
    elif track == "kisa":
        if load_body is None:
            raise ValueError("kisa track needs load_body")
        corpus = data.load_kisa_corpus(root, load_body)
    else:
        raise ValueError(f"unknown track {track!r}")
    k1, b = bm25_params(track, root)
    return GenerationIndex(track, corpus.texts, k1, b)


def retrieve(index: BM25Index, question: str, k: int) -> list[tuple[str, float]]:
    """질문 문자열의 BM25 상위 k개 (문서 ID, 점수). unjudged를 지우지 않은 순위이고 0건일 수 있다."""
    if k < 1:
        raise ValueError(f"k must be positive, got {k}")
    scores = index.score(question)
    return [(doc_id, scores[doc_id]) for doc_id in sort_by_score(scores)[:k]]


# ------------------------------------------------------------------ 문맥·프롬프트


def build_context(
    track: str,
    doc_ids: Sequence[str],
    load_body: TextLoader,
    char_cap: int = DOC_CHAR_CAP,
) -> tuple[str, list[str]]:
    """문서마다 `[문서 ID]` 머리 + 색인 텍스트(문자 `char_cap`까지)를 이어 붙인다.

    `load_body(doc_id)`는 색인 텍스트를 돌려준다(공개 = `id + description_en`, KISA = 제목 + 줄바꿈 +
    본문). 상한을 넘어 잘린 문서 ID를 함께 돌려준다. 문서가 없으면 빈 문자열이다.
    """
    if track not in data.TRACKS:
        raise ValueError(f"unknown track {track!r}")
    blocks: list[str] = []
    truncated: list[str] = []
    for doc_id in doc_ids:
        text = load_body(doc_id)
        if len(text) > char_cap:
            text = text[:char_cap]
            truncated.append(doc_id)
        blocks.append(f"[{doc_id}]\n{text}")
    return DOC_SEPARATOR.join(blocks), truncated


def build_prompt(question: str, context_text: str) -> Messages:
    """채팅 메시지(시스템 + 사용자). 문맥이 비면 고정 문구로 대신한다."""
    user = USER_TEMPLATE.format(context=context_text or EMPTY_CONTEXT, question=question)
    return [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": user}]


def retry_messages(messages: Messages, raw: str, reason: str) -> Messages:
    """재질의 메시지: 첫 질문 + 직전 응답 + 고정 문구의 교정 요청(같은 요청은 온도 0에서 같은 답이라 소용없다)."""
    return [
        *messages,
        {"role": "assistant", "content": raw},
        {"role": "user", "content": RETRY_TEMPLATE.format(reason=reason)},
    ]


def prompt_fingerprint() -> str:
    """고정 프롬프트(첫 질의 틀 + 재질의 문구)의 sha256. 자리표시 문구로 `build_prompt`를 부른다."""
    probe = build_prompt("{question}", "{context}")
    payload = {"messages": probe, "retry": RETRY_TEMPLATE, "empty_context": EMPTY_CONTEXT}
    text = json.dumps(payload, ensure_ascii=False, sort_keys=True)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ------------------------------------------------------------------ 계약 파싱


def _failed(reason: str) -> tuple[str, bool, list[str], list[str], str]:
    return "", False, [], [], f"{PARSE_FAILED_PREFIX}{reason}"


def parse_answer(
    raw: str, allowed_ids: Collection[str]
) -> tuple[str, bool, list[str], list[str], str]:
    """출력 계약 파싱. (answer, abstain, citations, invalid_citations, parse_status)를 돌려준다.

    - 성공: parse_status = "ok". citations = 문맥에 있던 ID(중복 제거, 등장 순서), invalid_citations = 그 밖의
      문자열(중복 제거). 인용 원소는 문자열이거나 정수(JSON 숫자로 쓴 nttId)여야 하고 정수는 문자열로 바꾼다.
    - 실패: ("", False, [], [], "parse_failed:<reason>"), reason은 PARSE_REASONS 중 하나(입력 문자열을 담지 않는다).
    """
    if not raw or not raw.strip():
        return _failed("empty")
    try:
        parsed = json.loads(raw)
    except ValueError:
        return _failed("not_json")
    if not isinstance(parsed, dict):
        return _failed("not_object")
    for key in ("answer", "abstain", "citations"):
        if key not in parsed:
            return _failed(f"missing_{key}")
    answer, abstain, citations = parsed["answer"], parsed["abstain"], parsed["citations"]
    if not isinstance(answer, str):
        return _failed("bad_answer")
    if not isinstance(abstain, bool):
        return _failed("bad_abstain")
    if not isinstance(citations, list):
        return _failed("bad_citations")
    seen: dict[str, None] = {}
    for item in citations:
        if isinstance(item, bool) or not isinstance(item, str | int):
            return _failed("bad_citations")
        seen[str(item).strip()] = None
    allowed = set(allowed_ids)
    valid = [doc_id for doc_id in seen if doc_id in allowed]
    invalid = [doc_id for doc_id in seen if doc_id not in allowed]
    return answer, abstain, valid, invalid, STATUS_OK


# ------------------------------------------------------------------ 생성


@dataclass(frozen=True)
class GenerationResult:
    """파싱 결과 + 시도 횟수·토큰·지연. 토큰은 첫 시도의 입력, 모든 시도의 출력 합이다."""

    answer: str
    abstain: bool
    citations: list[str]
    n_invalid_citations: int
    status: str
    n_attempts: int
    prompt_tokens: int | None
    completion_tokens: int | None
    latency_ms: float | None


def _sum_optional(values: Iterable[float | int | None]) -> float | int | None:
    present = [value for value in values if value is not None]
    return sum(present) if present else None


def generate(
    question: str, context_text: str, allowed_ids: Collection[str], llm: LLM
) -> GenerationResult:
    """LLM을 부르고 계약대로 파싱한다. 파싱 실패면 재질의를 1회 한다(최대 2회 호출).

    첫 응답의 `prompt_eval_count`가 `llm.max_prompt_tokens`(= num_ctx - num_predict) 이상이면 입력이 창을
    넘은 것이라 파싱하지 않고 `context_overflow`로 기록한다(재질의 없음).
    """
    messages = build_prompt(question, context_text)
    first = llm(messages)
    responses: list[LLMResponse] = [first]
    limit = getattr(llm, "max_prompt_tokens", None)
    prompt_tokens = first.prompt_eval_count
    if limit is not None and prompt_tokens is not None and prompt_tokens >= limit:
        answer, abstain, citations, invalid, status = "", False, [], [], STATUS_OVERFLOW
    else:
        answer, abstain, citations, invalid, status = parse_answer(first.content, allowed_ids)
        if status != STATUS_OK:
            reason = status.removeprefix(PARSE_FAILED_PREFIX)
            second = llm(retry_messages(messages, first.content, reason))
            responses.append(second)
            answer, abstain, citations, invalid, status = parse_answer(second.content, allowed_ids)
    return GenerationResult(
        answer=answer,
        abstain=abstain,
        citations=citations,
        n_invalid_citations=len(invalid),
        status=status,
        n_attempts=len(responses),
        prompt_tokens=prompt_tokens,
        completion_tokens=_sum_optional(r.eval_count for r in responses),
        latency_ms=_sum_optional(r.latency_ms for r in responses),
    )


def run_question(
    question: data.Question, index: GenerationIndex, k: int, llm: LLM, track: str | None = None
) -> dict:
    """질문 하나: 검색 -> 문맥 -> 생성 -> 결과 행(`answer` 포함. 커밋 전 `commit_row`로 거른다)."""
    track = track or index.track
    retrieved = [doc_id for doc_id, _ in retrieve(index, question.query, k)]
    context_text, truncated = build_context(track, retrieved, index.text)
    result = generate(question.query, context_text, set(retrieved), llm)
    latency = None if result.latency_ms is None else round(result.latency_ms, 3)
    return {
        "question_id": question.question_id,
        "split": question.split,
        "query_type": question.query_type,
        "k": k,
        "status": result.status,
        "abstain": result.abstain,
        "citations": result.citations,
        "n_invalid_citations": result.n_invalid_citations,
        "retrieved": retrieved,
        "truncated": truncated,
        "n_retrieved": len(retrieved),
        "prompt_tokens": result.prompt_tokens,
        "completion_tokens": result.completion_tokens,
        "latency_ms": latency,
        "context_sha256": sha256_text(context_text),
        "n_attempts": result.n_attempts,
        "context_chars": len(context_text),
        "answer": result.answer,
    }


# ------------------------------------------------------------------ 행 검증·저장


def commit_row(row: Mapping, track: str) -> dict:
    """커밋하는 행: KISA는 `answer`·`run_id` 없이 ROW_KEYS만, 공개는 `answer`까지."""
    keys = PUBLIC_ROW_KEYS if track == "public" else ROW_KEYS
    return {key: row[key] for key in keys}


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def validate_row(row: Mapping, track: str) -> None:
    """허용 키 집합과 값 형식·일관성 검사(본문 유출 경로 차단). 위반하면 ValueError."""
    expected = set(PUBLIC_ROW_KEYS if track == "public" else ROW_KEYS)
    _require(
        set(row) == expected, f"row keys {sorted(set(row) ^ expected)} differ from allowed set"
    )
    status = row["status"]
    _require(
        status in (STATUS_OK, STATUS_OVERFLOW)
        or (
            isinstance(status, str)
            and status.startswith(PARSE_FAILED_PREFIX)
            and status.removeprefix(PARSE_FAILED_PREFIX) in PARSE_REASONS
        ),
        f"{row['question_id']}: bad status {status!r}",
    )
    _require(isinstance(row["abstain"], bool), "abstain must be bool")
    for key in ("citations", "retrieved", "truncated"):
        value = row[key]
        _require(
            isinstance(value, list) and all(isinstance(v, str) for v in value),
            f"{key} must be a list of strings",
        )
    _require(len(set(row["citations"])) == len(row["citations"]), "citations must be unique")
    _require(
        set(row["citations"]) <= set(row["retrieved"]),
        "citations must be a subset of retrieved (contract-valid ids only)",
    )
    _require(
        set(row["truncated"]) <= set(row["retrieved"]), "truncated must be a subset of retrieved"
    )
    _require(
        row["n_retrieved"] == len(row["retrieved"]) and len(row["retrieved"]) <= row["k"],
        "n_retrieved inconsistent with retrieved/k",
    )
    for key in ("n_invalid_citations", "n_attempts", "context_chars"):
        _require(_is_int(row[key]) and row[key] >= 0, f"{key} must be a non-negative int")
    _require(row["n_attempts"] in (1, 2), "n_attempts must be 1 or 2")
    for key in ("prompt_tokens", "completion_tokens"):
        _require(row[key] is None or _is_int(row[key]), f"{key} must be int or null")
    latency = row["latency_ms"]
    _require(
        latency is None or (isinstance(latency, int | float) and not isinstance(latency, bool)),
        "latency_ms must be a number or null",
    )
    _require(
        isinstance(row["context_sha256"], str) and len(row["context_sha256"]) == 64,
        "context_sha256 must be a sha256 hex digest",
    )
    _require(
        status == STATUS_OK
        or not (row["abstain"] or row["citations"] or row["n_invalid_citations"]),
        "non-ok rows carry no abstain/citations",
    )
    _require(track != "public" or isinstance(row["answer"], str), "answer must be a string")


def check_row_set(rows: Sequence[Mapping], questions: Sequence[data.Question], k: int) -> None:
    """행의 question_id 집합이 예상 질문 집합과 정확히 같고(중복·누락·초과 없음) k가 같은지 확인한다."""
    ids = [row["question_id"] for row in rows]
    if len(set(ids)) != len(ids):
        raise ValueError("duplicate question_id in rows")
    expected = {question.question_id for question in questions}
    if set(ids) != expected:
        missing, extra = sorted(expected - set(ids)), sorted(set(ids) - expected)
        raise ValueError(f"question_id set differs: missing={missing[:3]} extra={extra[:3]}")
    by_id = {question.question_id: question for question in questions}
    for row in rows:
        question = by_id[row["question_id"]]
        if (
            row["k"] != k
            or row["split"] != question.split
            or row["query_type"] != question.query_type
        ):
            raise ValueError(f"{row['question_id']}: k/split/query_type differ from question set")


def expected_questions(track: str, root: Path) -> list[data.Question]:
    """생성 대상 질문: 공개 = 질의셋 전부, KISA = `excluded`가 아닌 질문(질의 파일 순서)."""
    return [q for q in data.load_questions(track, root) if not q.excluded]


def success_rate(rows: Sequence[Mapping]) -> float:
    """계약 파싱 성공률 = 최종 status == ok 행 수 / 행 수(context_overflow·최종 파싱 실패는 실패)."""
    return sum(row["status"] == STATUS_OK for row in rows) / len(rows) if rows else 0.0


def max_failures(n_expected: int, floor: float = SUCCESS_FLOOR) -> int:
    """성공률이 floor 이상이려면 허용되는 최대 실패 수."""
    return n_expected - math.ceil(floor * n_expected)


class GateFailure(RuntimeError):
    """계약 파싱 성공률이 하한 미만이 되어 실행을 중단한다."""


def read_jsonl_rows(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def write_jsonl_atomic(path: Path, rows: Iterable[Mapping]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=path.name, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            for row in rows:
                handle.write(json.dumps(row, ensure_ascii=False) + "\n")
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def run_track_k(
    questions: Sequence[data.Question],
    index: GenerationIndex,
    k: int,
    llm: LLM,
    run_id: str,
    local_path: Path,
    failure_limit: int | None = None,
    on_row: Callable[[int, int, dict], None] | None = None,
) -> list[dict]:
    """한 (트랙, k)의 모든 질문을 돌린다. 질문마다 `local_path`(로컬 캐시, 답변 원문 포함)에 이어 쓴다.

    같은 `run_id`의 행이 이미 있으면 다시 호출하지 않고 이어 간다(실행이 끊겨도 이어 돌릴 수 있다). 실패 수가
    `failure_limit`을 넘으면 GateFailure다(성공률 하한을 더 채울 수 없음). 끝나면 질문 순서로 다시 쓴다.
    """
    done: dict[str, dict] = {}
    for row in read_jsonl_rows(local_path):
        if row.get("run_id") == run_id and row.get("k") == k:
            done[row["question_id"]] = row
    if not done and local_path.exists():
        local_path.unlink()
    local_path.parent.mkdir(parents=True, exist_ok=True)
    rows: list[dict] = []
    failures = 0
    with local_path.open("a", encoding="utf-8") as handle:
        for position, question in enumerate(questions, start=1):
            row = done.get(question.question_id)
            if row is None:
                row = {**run_question(question, index, k, llm), "run_id": run_id}
                handle.write(json.dumps(row, ensure_ascii=False) + "\n")
                handle.flush()
            rows.append(row)
            failures += row["status"] != STATUS_OK
            if on_row is not None:
                on_row(position, len(questions), row)
            if failure_limit is not None and failures > failure_limit:
                raise GateFailure(
                    f"k={k}: {failures} failures after {position} of {len(questions)} questions "
                    f"exceed the allowed {failure_limit}"
                )
    write_jsonl_atomic(local_path, rows)
    return rows


# ------------------------------------------------------------------ 기계 지표

RATE_KEYS = (
    "parse_success_rate",
    "parse_fail_rate",
    "context_overflow_rate",
    "correct_abstain_rate",
    "false_abstain_rate",
    "citation_hit_rate",
    "invalid_citation_rate",
)


def _ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def _median(values: Sequence[float | int | None]) -> float | None:
    present = [value for value in values if value is not None]
    return float(statistics.median(present)) if present else None


def _maximum(values: Sequence[int | None]) -> int | None:
    present = [value for value in values if value is not None]
    return max(present) if present else None


def cell_metrics(rows: Sequence[Mapping], questions: Mapping[str, data.Question]) -> dict:
    """행 묶음 하나(트랙 x k x 분할 x 유형 중 한 칸)의 기계 지표. 정의는 docs/m5-generation.md.

    - 올바른 기권률 = no_answer 질문 중 ok·abstain 비율(분모 = no_answer 질문 전부).
    - 잘못된 기권률 = 정답 있는 질문 중 ok·abstain 비율(분모 = 정답 있는 질문 전부).
    - 인용 적중률 = 정답 있는 ok·비기권 답 중 citations ∩ gold ≠ ∅ 비율(분모 0이면 null).
    - 무효 인용률 = 무효 인용 수 합 / (검증 인용 수 합 + 무효 인용 수 합), 분모 0이면 null.
    - unjudged 문서 인용은 적중도 무효도 아니다(검증 인용에는 들어간다): 개수만 따로 센다.
    """
    n = len(rows)
    no_answer = [r for r in rows if questions[r["question_id"]].query_type == "no_answer"]
    answerable = [r for r in rows if questions[r["question_id"]].gold]
    answered = [r for r in answerable if r["status"] == STATUS_OK and not r["abstain"]]
    hits = sum(bool(set(r["citations"]) & questions[r["question_id"]].gold) for r in answered)
    n_valid = sum(len(r["citations"]) for r in rows)
    n_invalid = sum(r["n_invalid_citations"] for r in rows)
    n_ok = sum(r["status"] == STATUS_OK for r in rows)
    n_overflow = sum(r["status"] == STATUS_OVERFLOW for r in rows)
    n_unjudged_cited = sum(
        len(set(r["citations"]) & questions[r["question_id"]].unjudged) for r in rows
    )
    prompt_tokens = [r["prompt_tokens"] for r in rows]
    return {
        "n_questions": n,
        "n_no_answer": len(no_answer),
        "n_answerable": len(answerable),
        "n_ok": n_ok,
        "n_parse_failed": n - n_ok - n_overflow,
        "n_context_overflow": n_overflow,
        "parse_success_rate": _ratio(n_ok, n),
        "parse_fail_rate": _ratio(n - n_ok - n_overflow, n),
        "context_overflow_rate": _ratio(n_overflow, n),
        "correct_abstain_rate": _ratio(
            sum(r["status"] == STATUS_OK and r["abstain"] for r in no_answer), len(no_answer)
        ),
        "false_abstain_rate": _ratio(
            sum(r["status"] == STATUS_OK and r["abstain"] for r in answerable), len(answerable)
        ),
        "n_cited_answers": len(answered),
        "n_citation_hits": hits,
        "citation_hit_rate": _ratio(hits, len(answered)),
        "n_valid_citations": n_valid,
        "n_invalid_citations": n_invalid,
        "n_unjudged_citations": n_unjudged_cited,
        "invalid_citation_rate": _ratio(n_invalid, n_valid + n_invalid),
        "prompt_tokens_median": _median(prompt_tokens),
        "prompt_tokens_max": _maximum(prompt_tokens),
        "latency_ms_median": _median([r["latency_ms"] for r in rows]),
        "context_chars_median": _median([r["context_chars"] for r in rows]),
        "n_truncated_questions": sum(bool(r["truncated"]) for r in rows),
        "n_retried": sum(r["n_attempts"] > 1 for r in rows),
    }


def _macro(type_cells: Sequence[Mapping]) -> dict:
    """정답 있는 유형 칸들의 단순 평균(정의된 값만). 비율 지표만 평균하고 나머지는 null이다."""
    cell: dict = {key: None for key in cell_metrics([], {})}
    cell["n_questions"] = sum(c["n_questions"] for c in type_cells)
    for key in RATE_KEYS:
        defined = [c[key] for c in type_cells if c[key] is not None]
        cell[key] = sum(defined) / len(defined) if defined else None
    return cell


def compute_topk(
    rows_by_cell: Mapping[tuple[str, int], Sequence[Mapping]],
    questions_by_track: Mapping[str, Sequence[data.Question]],
) -> dict:
    """트랙 x k x 분할 x 유형별 지표. `rows_by_cell` = {(트랙, k): 커밋 행 목록}.

    유형 칸: 질문 유형 4개(행이 있는 것만) + `all`(분할 안 전체) + `macro`(정답 있는 유형의 단순 평균).
    분할 칸: dev, test, all(두 분할 합).
    """
    cells: list[dict] = []
    for (track, k), rows in sorted(rows_by_cell.items()):
        by_id = {q.question_id: q for q in questions_by_track[track]}
        for split in SPLIT_VALUES:
            in_split = [r for r in rows if split == "all" or r["split"] == split]
            if not in_split:
                continue
            type_cells = []
            for query_type in data.QUERY_TYPES:
                subset = [r for r in in_split if r["query_type"] == query_type]
                if subset:
                    type_cells.append((query_type, cell_metrics(subset, by_id)))
            answerable_types = [c for t, c in type_cells if t != "no_answer"]
            blocks = [
                *type_cells,
                ("macro", _macro(answerable_types)),
                ("all", cell_metrics(in_split, by_id)),
            ]
            for query_type, metrics in blocks:
                cells.append(
                    {"track": track, "k": k, "split": split, "query_type": query_type, **metrics}
                )
    return {"schema": TOPK_SCHEMA, "cells": cells}


def compare_topk(stored: Mapping, recomputed: Mapping, tolerance: float = TOLERANCE) -> list[str]:
    """저장본과 다시 계산한 값을 비교한다. 다른 칸·값마다 한 줄(없으면 같다). 실수는 절대 오차 tolerance."""
    problems: list[str] = []
    if stored.get("schema") != recomputed.get("schema"):
        problems.append("schema differs")

    def key(cell: Mapping) -> tuple:
        return (cell["track"], cell["k"], cell["split"], cell["query_type"])

    old = {key(cell): cell for cell in stored.get("cells", [])}
    new = {key(cell): cell for cell in recomputed.get("cells", [])}
    if len(old) != len(stored.get("cells", [])):
        problems.append("stored topk has duplicate cells")
    for cell_key in sorted(set(old) ^ set(new)):
        problems.append(f"cell {cell_key} only in {'stored' if cell_key in old else 'recomputed'}")
    for cell_key in sorted(set(old) & set(new)):
        a, b = old[cell_key], new[cell_key]
        if set(a) != set(b):
            problems.append(f"cell {cell_key}: field set differs")
            continue
        for field in sorted(a):
            x, y = a[field], b[field]
            if isinstance(x, float | int) and isinstance(y, float | int):
                same = abs(x - y) <= tolerance
            else:
                same = x == y
            if not same:
                problems.append(f"cell {cell_key}: {field} stored={x!r} recomputed={y!r}")
    return problems


# ------------------------------------------------------------------ 실행·manifest·저장본 검사

OVERFLOW_RULE = (
    "보내기 전에 셀 수 없다(Ollama에 tokenize 엔드포인트가 없고 토크나이저 파일을 따로 받지 않는다). "
    "응답의 prompt_eval_count가 num_ctx - num_predict 이상이면 context_overflow로 바꿔 기록한다"
)
TOKEN_METHOD = (
    "Ollama 응답의 prompt_eval_count를 그대로 기록한다(없으면 null). 재질의가 있어도 입력 토큰은 첫 시도 값, "
    "출력 토큰·지연은 모든 시도의 합"
)
LATENCY_RULE = "(total_duration - load_duration)를 밀리초로 바꾼 값(모델 적재 시간 제외)"


class TokenReproError(RuntimeError):
    """같은 프롬프트를 두 번 보냈는데 prompt_eval_count가 달랐다(접두사 KV 캐시 재사용 의심)."""


def check_token_repro(
    index: GenerationIndex, questions: Sequence[data.Question], k: int, llm: LLM, n_pairs: int = 3
) -> dict:
    """같은 프롬프트를 두 번 보내 `prompt_eval_count`가 같은지 확인한다(질문 `n_pairs`개)."""
    pairs = []
    for question in questions[:n_pairs]:
        retrieved = [doc_id for doc_id, _ in retrieve(index, question.query, k)]
        context_text, _ = build_context(index.track, retrieved, index.text)
        messages = build_prompt(question.query, context_text)
        first, second = llm(messages), llm(messages)
        pairs.append((first.prompt_eval_count, second.prompt_eval_count))
    identical = all(a is not None and a == b for a, b in pairs)
    return {
        "k": k,
        "n_pairs": len(pairs),
        "n_identical": sum(a is not None and a == b for a, b in pairs),
        "identical": identical,
    }


def make_run_id(config: Mapping) -> str:
    """실행 ID = 모델 digest·옵션·프롬프트·문맥 규칙·검색 설정이 같으면 같은 값(이어 돌리기·#66 대조용)."""
    text = json.dumps(config, ensure_ascii=False, sort_keys=True)
    return sha256_text(text)[:16]


def run_config(model: Mapping, llm: object, root: Path) -> dict:
    """run_id를 정하는 설정(시각·환경 제외)."""
    request = llm.request_body([]) if hasattr(llm, "request_body") else {}
    request.pop("messages", None)
    return {
        "schema": SCHEMA,
        "model": {key: model.get(key) for key in ("name", "digest", "weights_sha256")},
        "request": request,
        "prompt_sha256": prompt_fingerprint(),
        "doc_char_cap": DOC_CHAR_CAP,
        "baselines_manifest_sha256": data.file_sha256(root / BASELINES_MANIFEST),
    }


def now_utc() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def new_manifest(model: Mapping, llm: object, root: Path, token_repro: Mapping | None) -> dict:
    config = run_config(model, llm, root)
    return {
        "schema": SCHEMA,
        "run_id": make_run_id(config),
        "created_at": now_utc(),
        "environment": runner.environment(),
        "model": dict(model),
        "request": config["request"],
        "prompt": {
            "sha256": config["prompt_sha256"],
            "function": "krsec_rag_lab.generation.pipeline.build_prompt",
            "retry": "파싱 실패 시 1회: 첫 질의 + 직전 응답 + 고정 교정 문구(RETRY_TEMPLATE)",
        },
        "context_rules": {
            "doc_header": "[문서 ID]",
            "doc_separator": DOC_SEPARATOR,
            "per_doc_char_cap": DOC_CHAR_CAP,
            "index_text": {"public": data.PUBLIC_INDEX_TEXT, "kisa": data.KISA_INDEX_TEXT},
            "empty_context": EMPTY_CONTEXT,
        },
        "output_contract": {
            "json": '{"answer": str, "abstain": bool, "citations": [문서 ID]}',
            "parse_reasons": list(PARSE_REASONS),
            "statuses": [STATUS_OK, f"{PARSE_FAILED_PREFIX}<reason>", STATUS_OVERFLOW],
            "success_floor": SUCCESS_FLOOR,
        },
        "token_counting": {
            "method": TOKEN_METHOD,
            "overflow_rule": OVERFLOW_RULE,
            "max_prompt_tokens": getattr(llm, "max_prompt_tokens", None),
            "latency": LATENCY_RULE,
            "repro_check": token_repro,
        },
        "retrieval": {
            "source": "results/baselines/manifest.json의 트랙별 BM25 선택 값(k1·b), 토큰화 bm25-tok-v1",
            "baselines_manifest_sha256": config["baselines_manifest_sha256"],
            "rank": "unjudged를 지우기 전 BM25 점수를 (-점수, 문서 ID)로 정렬한 상위 k개",
        },
        "tracks": {},
    }


def load_manifest(out_dir: Path) -> dict | None:
    path = out_dir / "manifest.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else None


def write_json(path: Path, payload: Mapping) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def output_name(track: str, k: int) -> str:
    return f"{track}_k{k}.jsonl"


def load_stored_rows(out_dir: Path, manifest: Mapping) -> dict[tuple[str, int], list[dict]]:
    """manifest에 적힌 (트랙, k)의 커밋 행을 읽는다."""
    stored: dict[tuple[str, int], list[dict]] = {}
    for track, block in manifest["tracks"].items():
        for key in block["outputs"]:
            k = int(key.removeprefix("k"))
            stored[(track, k)] = read_jsonl_rows(out_dir / output_name(track, k))
    return stored


def recompute_topk(root: Path, out_dir: Path, manifest: Mapping) -> dict:
    stored = load_stored_rows(out_dir, manifest)
    questions = {track: data.load_questions(track, root) for track in manifest["tracks"]}
    return compute_topk(stored, questions)


def check_stored(root: Path, out_dir: Path) -> list[str]:
    """저장본 검사(모델·Ollama·KISA 캐시 없이): 행 키·집합·성공률·manifest 해시 + topk.json 재계산 대조."""
    manifest = load_manifest(out_dir)
    if manifest is None:
        return ["manifest.json is missing"]
    problems: list[str] = []
    for track, block in manifest["tracks"].items():
        expected = expected_questions(track, root)
        for key, output in block["outputs"].items():
            k = int(key.removeprefix("k"))
            path = out_dir / output_name(track, k)
            label = f"{track} k={k}"
            if not path.is_file():
                problems.append(f"{label}: {path.name} is missing")
                continue
            if data.file_sha256(path) != output["sha256"]:
                problems.append(f"{label}: sha256 differs from manifest")
            rows = read_jsonl_rows(path)
            try:
                for row in rows:
                    validate_row(row, track)
                check_row_set(rows, expected, k)
            except ValueError as error:
                problems.append(f"{label}: {error}")
                continue
            if len(rows) != len(expected):
                problems.append(f"{label}: {len(rows)} rows != {len(expected)} expected")
            if success_rate(rows) < SUCCESS_FLOOR:
                problems.append(
                    f"{label}: parse success {success_rate(rows):.4f} < {SUCCESS_FLOOR}"
                )
    if problems:
        return problems
    topk_path = out_dir / "topk.json"
    if not topk_path.is_file():
        return ["topk.json is missing"]
    stored_topk = json.loads(topk_path.read_text(encoding="utf-8"))
    return compare_topk(stored_topk, recompute_topk(root, out_dir, manifest))


def sample_questions(questions: Sequence[data.Question], limit: int | None) -> list[data.Question]:
    """`limit`개를 질문 유형을 돌려 가며(유형마다 질문 순서대로) 뽑는 소표본. None이면 전부."""
    if limit is None or limit >= len(questions):
        return list(questions)
    by_type = [
        [q for q in questions if q.query_type == query_type] for query_type in data.QUERY_TYPES
    ]
    picked: list[data.Question] = []
    for position in range(max(len(group) for group in by_type)):
        picked.extend(group[position] for group in by_type if position < len(group))
    return picked[:limit]


def run_track(
    track: str,
    ks: Sequence[int],
    root: Path,
    index: GenerationIndex,
    llm: LLM,
    manifest: dict,
    out_dir: Path,
    local_dir: Path,
    limit: int | None = None,
    on_row: Callable[[int, int, dict], None] | None = None,
) -> dict:
    """한 트랙의 k마다 질문을 돌려 `<out_dir>/<track>_k<k>.jsonl`을 쓰고 manifest의 트랙 항목을 갱신한다.

    성공률이 하한(80%) 미만이면 그 (트랙, k)의 결과는 쓰지 않고 GateFailure다(`limit`을 준 소표본은 제외).
    로컬 캐시(`local_dir/<track>_k<k>.jsonl`, 답변 원문 포함)는 이어 돌리기에도 쓴다.
    """
    expected = expected_questions(track, root)
    questions = sample_questions(expected, limit)
    failure_limit = None if limit else max_failures(len(expected))
    block = manifest["tracks"].setdefault(track, {})
    block.update(
        {
            "created_at": now_utc(),
            "environment": runner.environment(),
            "inputs": data.input_fingerprints(track, root),
            "n_documents": index.n_documents,
            "n_questions": len(questions),
            "n_expected_questions": len(expected),
            "retrieval": {"k1": index.k1, "b": index.b, "tokenizer": "bm25-tok-v1"},
            "docs_over_char_cap": sum(len(t) > DOC_CHAR_CAP for t in index.texts.values()),
            "local_cache": (
                "<KISA-ROOT>/data/m5/generation/kisa_k<k>.jsonl (gitignore, 답변 원문 포함)"
                if track == "kisa"
                else "data/m5/generation/public_k<k>.jsonl (gitignore, 이어 돌리기용)"
            ),
        }
    )
    outputs = block.setdefault("outputs", {})
    for k in ks:
        started = time.perf_counter()
        rows = run_track_k(
            questions,
            index,
            k,
            llm,
            manifest["run_id"],
            local_dir / output_name(track, k),
            failure_limit=failure_limit,
            on_row=on_row,
        )
        committed = [commit_row(row, track) for row in rows]
        for row in committed:
            validate_row(row, track)
        check_row_set(committed, questions, k)
        rate = success_rate(rows)
        if failure_limit is not None and rate < SUCCESS_FLOOR:
            raise GateFailure(f"{track} k={k}: parse success {rate:.4f} < {SUCCESS_FLOOR}")
        path = out_dir / output_name(track, k)
        write_jsonl_atomic(path, committed)
        outputs[f"k{k}"] = {
            "file": path.name,
            "sha256": data.file_sha256(path),
            "n_rows": len(committed),
            "parse_success_rate": rate,
            "wall_seconds_this_invocation": round(time.perf_counter() - started, 1),
        }
    return manifest


# ------------------------------------------------------------------ 보고서 표

DOC_PATH = Path("docs/m5-generation.md")
BEGIN = "<!-- BEGIN GENERATED TABLES (scripts/run_generation.py --render-docs) -->"
END = "<!-- END GENERATED TABLES -->"
TRACK_TITLES = {"public": "공개 트랙 (NVD)", "kisa": "KISA 트랙"}


def _fmt(value: float | None, digits: int = 3) -> str:
    return "-" if value is None else f"{value:.{digits}f}"


def _fmt_int(value: float | None) -> str:
    return "-" if value is None else f"{value:.0f}"


def _seconds(value_ms: float | None) -> str:
    return "-" if value_ms is None else f"{value_ms / 1000:.2f}"


def render_tables(topk: Mapping) -> str:
    """topk.json -> 보고서 표(마크다운). 숫자는 topk.json에서만 오고 문서의 서술은 사람이 쓴다."""
    cells = {(c["track"], c["k"], c["split"], c["query_type"]): c for c in topk["cells"]}
    tracks = [t for t in data.TRACKS if any(key[0] == t for key in cells)]
    ks = sorted({key[1] for key in cells})
    lines: list[str] = []
    for track in tracks:
        lines += [f"### {TRACK_TITLES[track]}: k별 요약 (dev+test 전체)", ""]
        lines += [
            (
                "| k | 질문 수 | 계약 파싱 성공률 | 재질의 수 | 문맥 초과 | 올바른 기권률 "
                "| 잘못된 기권률 | 인용 적중률 | 무효 인용률 | 입력 토큰 중앙값 | 입력 토큰 최대 "
                "| 지연 중앙값(초) |"
            ),
            "|---|---|---|---|---|---|---|---|---|---|---|---|",
        ]
        for k in ks:
            c = cells.get((track, k, "all", "all"))
            if c is None:
                continue
            lines.append(
                f"| {k} | {c['n_questions']} | {_fmt(c['parse_success_rate'])} | {c['n_retried']} "
                f"| {c['n_context_overflow']} | {_fmt(c['correct_abstain_rate'])} "
                f"| {_fmt(c['false_abstain_rate'])} | {_fmt(c['citation_hit_rate'])} "
                f"| {_fmt(c['invalid_citation_rate'])} | {_fmt_int(c['prompt_tokens_median'])} "
                f"| {_fmt_int(c['prompt_tokens_max'])} | {_seconds(c['latency_ms_median'])} |"
            )
        lines += ["", f"### {TRACK_TITLES[track]}: 유형별 (dev+test 전체)", ""]
        lines += [
            (
                "| k | 유형 | 질문 수 | 파싱 성공률 | 올바른 기권률 | 잘못된 기권률 | 인용 적중률 "
                "| 무효 인용률 | unjudged 인용 수 | 입력 토큰 중앙값 |"
            ),
            "|---|---|---|---|---|---|---|---|---|---|",
        ]
        for k in ks:
            for query_type in (*data.QUERY_TYPES, "macro"):
                c = cells.get((track, k, "all", query_type))
                if c is None:
                    continue
                lines.append(
                    f"| {k} | {query_type} | {c['n_questions']} | {_fmt(c['parse_success_rate'])} "
                    f"| {_fmt(c['correct_abstain_rate'])} | {_fmt(c['false_abstain_rate'])} "
                    f"| {_fmt(c['citation_hit_rate'])} | {_fmt(c['invalid_citation_rate'])} "
                    f"| {_fmt_int(c['n_unjudged_citations'])} "
                    f"| {_fmt_int(c['prompt_tokens_median'])} |"
                )
        lines += ["", f"### {TRACK_TITLES[track]}: 분할별 macro (정답 있는 유형의 단순 평균)", ""]
        lines += [
            "| k | 분할 | 파싱 성공률 | 잘못된 기권률 | 인용 적중률 | 무효 인용률 |",
            "|---|---|---|---|---|---|",
        ]
        for k in ks:
            for split in SPLIT_VALUES:
                c = cells.get((track, k, split, "macro"))
                if c is None:
                    continue
                lines.append(
                    f"| {k} | {split} | {_fmt(c['parse_success_rate'])} "
                    f"| {_fmt(c['false_abstain_rate'])} | {_fmt(c['citation_hit_rate'])} "
                    f"| {_fmt(c['invalid_citation_rate'])} |"
                )
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_docs(root: Path, out_dir: Path | None = None) -> str:
    """results/m5/generation/topk.json의 표를 docs/m5-generation.md의 표시 구간에 옮긴다."""
    out_dir = out_dir or root / RESULTS_DIR
    topk = json.loads((out_dir / "topk.json").read_text(encoding="utf-8"))
    path = root / DOC_PATH
    text = path.read_text(encoding="utf-8")
    start, end = text.index(BEGIN), text.index(END)
    if start > end:
        raise ValueError("BEGIN marker comes after END marker")
    updated = f"{text[: start + len(BEGIN)]}\n\n{render_tables(topk)}\n{text[end:]}"
    path.write_text(updated, encoding="utf-8")
    return updated
