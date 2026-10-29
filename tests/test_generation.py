"""생성 파이프라인(M5) 테스트 - 가짜 LLM과 합성 코퍼스만 쓴다. 네트워크·Ollama·모델·KISA 캐시를 쓰지 않는다.

확인하는 것: 문맥 구성(ID 머리, 문자 상한, 잘림), 출력 계약 파싱(정상·키 누락·JSON 아님·문맥 밖 인용), 재질의 1회,
문맥 초과 경계, 기계 지표(기권·인용·토큰) 계산, 커밋 행 허용 키와 KISA 행의 answer 부재·유출 방지,
예상 질문 집합 검사, 이어 돌리기, Ollama 응답 모형(urllib 대체), 저장본 검사(`--metrics-only`).
"""

import hashlib
import importlib.util
import io
import json
import sys
import urllib.error
from pathlib import Path

import pytest

from krsec_rag_lab.baselines import data
from krsec_rag_lab.baselines.bm25 import BM25Index
from krsec_rag_lab.generation import llm as llm_module
from krsec_rag_lab.generation import pipeline as pl
from krsec_rag_lab.generation.llm import LLMError, LLMResponse

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "run_generation.py"
SPEC = importlib.util.spec_from_file_location("run_generation", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
run_generation = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = run_generation
SPEC.loader.exec_module(run_generation)

# ------------------------------------------------------------ 가짜 LLM


def reply(answer="답", abstain=False, citations=()):
    return json.dumps(
        {"answer": answer, "abstain": abstain, "citations": list(citations)}, ensure_ascii=False
    )


class FakeLLM:
    """응답 목록을 차례로 돌려주는 호출 가능 객체(LLM 규약). 호출한 메시지를 `calls`에 쌓는다."""

    def __init__(
        self, replies, max_prompt_tokens=None, prompt_tokens=100, eval_count=10, latency_ms=5.0
    ):
        self.replies = list(replies)
        self.max_prompt_tokens = max_prompt_tokens
        self.prompt_tokens = prompt_tokens
        self.eval_count = eval_count
        self.latency_ms = latency_ms
        self.calls = []

    def __call__(self, messages):
        self.calls.append([dict(m) for m in messages])
        content = self.replies[min(len(self.calls), len(self.replies)) - 1]
        if callable(content):
            content = content(messages)
        tokens = self.prompt_tokens
        if isinstance(tokens, list):
            tokens = tokens[min(len(self.calls), len(tokens)) - 1]
        return LLMResponse(content, tokens, self.eval_count, self.latency_ms, "stop")


# ------------------------------------------------------------ 합성 코퍼스

PUBLIC_RECORDS = {
    "CVE-2026-0001": "Acme Router firmware allows remote buffer overflow",
    "CVE-2026-0002": "Acme Router web console allows command injection",
    "CVE-2026-0003": "Globex Gateway improper authentication in the admin panel",
    "CVE-2026-0004": "Globex Gateway cross site scripting in the login page",
    "CVE-2026-0005": "Initech Database server SQL injection through the search box",
    "CVE-2026-0006": "Initech Database backup tool path traversal",
}


def public_query(qid, query, query_type, split, gold=(), unjudged=()):
    return {
        "id": qid,
        "query": query,
        "query_type": query_type,
        "split": split,
        "gold": list(gold),
        "unjudged": list(unjudged),
        "vendor_product": None,
    }


PUBLIC_QUERIES = [
    public_query("q-cve-1", "CVE-2026-0001 취약점의 영향 범위", "cve_explicit", "dev", ["CVE-2026-0001"]),
    public_query("q-cve-2", "CVE-2026-0005 어떤 취약점", "cve_explicit", "test", ["CVE-2026-0005"]),
    public_query("q-prod-1", "globex gateway authentication 취약점", "product_symptom", "dev", ["CVE-2026-0003"], ["CVE-2026-0004"]),
    public_query("q-prod-2", "acme router injection 취약점", "product_symptom", "test", ["CVE-2026-0002"]),
    public_query("q-na-1", "zzzz qqqq 레코드", "no_answer", "dev"),
    public_query("q-na-2", "wwww yyyy 레코드", "no_answer", "test"),
]  # fmt: skip

NTT_IDS = ["90001", "90002", "90003"]
KISA_BODIES = {
    "90001": "SYNTHETIC-BODY-ALPHA " + "가나다라 " * 800,
    "90002": "SYNTHETIC-BODY-BETA 인증 우회 CVE-2026-1003",
    "90003": "SYNTHETIC-BODY-GAMMA 패치 안내",
}


def kisa_row(qid, query, query_type, split, answers=(), unjudged=(), excluded=False):
    return {
        "question_id": qid,
        "query": query,
        "query_type": query_type,
        "split": split,
        "answers": [
            {"doc_id": doc, "doc_sha256": hashlib.sha256(doc.encode()).hexdigest()}
            for doc in answers
        ],
        "unjudged": list(unjudged),
        "excluded": excluded,
    }


KISA_QUESTIONS = [
    kisa_row("k-cve-1", "가나다라 공지", "cve_explicit", "dev", ["90001"]),
    kisa_row("k-prod-1", "인증 우회 공지", "product_symptom", "test", ["90002"]),
    kisa_row("k-ex-1", "판정 불가 질문", "explanation_comparison", "dev", [], ["90003"], True),
    kisa_row("k-na-1", "zzzz 없는 공지", "no_answer", "dev"),
]


def write_jsonl(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + "\n", encoding="utf-8"
    )


def write_root(root):
    write_jsonl(
        root / data.PUBLIC_CORPUS,
        [{"id": cve, "description_en": text} for cve, text in PUBLIC_RECORDS.items()],
    )
    write_jsonl(root / data.PUBLIC_QUERIES, PUBLIC_QUERIES)
    documents = [
        {"nttId": ntt, "sha256": hashlib.sha256(ntt.encode()).hexdigest()} for ntt in NTT_IDS
    ]
    (root / "fixtures/kisa").mkdir(parents=True, exist_ok=True)
    (root / data.KISA_MANIFEST).write_text(json.dumps({"documents": documents}), encoding="utf-8")
    write_jsonl(root / data.KISA_METADATA, [{"nttId": n, "title": f"공지 {n}"} for n in NTT_IDS])
    write_jsonl(root / data.KISA_GOLDEN, KISA_QUESTIONS)
    baselines = {
        "runs": {
            "public/bm25": {"selected": {"k1": 1.2, "b": 0.75}},
            "kisa/bm25": {"selected": {"k1": 3.0, "b": 0.9}},
        }
    }
    write_json(root / pl.BASELINES_MANIFEST, baselines)


def write_json(path, payload):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def fake_body_loader(ntt_id, document):
    assert document["nttId"] == ntt_id
    return KISA_BODIES[ntt_id]


@pytest.fixture
def root(tmp_path):
    write_root(tmp_path)
    return tmp_path


# ------------------------------------------------------------ 문맥 구성


def test_context_has_id_header_and_index_text():
    texts = {"A-1": "alpha text", "B-2": "beta text"}
    context, truncated = pl.build_context("public", ["B-2", "A-1"], texts.__getitem__)
    assert context == "[B-2]\nbeta text\n\n[A-1]\nalpha text"
    assert truncated == []


@pytest.mark.parametrize(
    ("length", "cap", "expect_truncated"),
    [(9, 10, False), (10, 10, False), (11, 10, True), (30, 10, True)],
)
def test_context_char_cap_boundary_and_truncated_ids(length, cap, expect_truncated):
    texts = {"D-1": "x" * length, "D-2": "y"}
    context, truncated = pl.build_context("kisa", ["D-1", "D-2"], texts.__getitem__, char_cap=cap)
    assert truncated == (["D-1"] if expect_truncated else [])
    assert context.startswith("[D-1]\n" + "x" * min(length, cap))
    assert context.endswith("[D-2]\ny")


def test_context_counts_every_truncated_document():
    texts = {f"D-{i}": "z" * 50 for i in range(4)}
    context, truncated = pl.build_context("kisa", list(texts), texts.__getitem__, char_cap=20)
    assert truncated == list(texts)
    assert context.count("z") == 80


def test_empty_context_and_unknown_track():
    assert pl.build_context("public", [], {}.__getitem__) == ("", [])
    with pytest.raises(ValueError, match="unknown track"):
        pl.build_context("other", [], {}.__getitem__)


def test_prompt_messages_and_empty_context_placeholder():
    messages = pl.build_prompt("질문입니다", "[A-1]\ntext")
    assert [m["role"] for m in messages] == ["system", "user"]
    assert messages[0]["content"] == pl.SYSTEM_PROMPT
    assert "[A-1]\ntext" in messages[1]["content"]
    assert messages[1]["content"].endswith("[질문]\n질문입니다")
    assert pl.EMPTY_CONTEXT in pl.build_prompt("질문", "")[1]["content"]


def test_prompt_fingerprint_is_a_stable_sha256(monkeypatch):
    first = pl.prompt_fingerprint()
    assert first == pl.prompt_fingerprint()
    assert len(first) == 64
    monkeypatch.setattr(pl, "SYSTEM_PROMPT", pl.SYSTEM_PROMPT + " ")
    assert pl.prompt_fingerprint() != first


def test_prompt_text_has_no_em_dash():
    assert "—" not in pl.SYSTEM_PROMPT + pl.USER_TEMPLATE + pl.RETRY_TEMPLATE


# ------------------------------------------------------------ 출력 계약 파싱

ALLOWED = {"CVE-2026-0001", "CVE-2026-0002"}


def test_parse_ok():
    answer, abstain, citations, invalid, status = pl.parse_answer(
        reply("영향 범위는 넓다", False, ["CVE-2026-0001"]), ALLOWED
    )
    assert (answer, abstain, citations, invalid, status) == (
        "영향 범위는 넓다",
        False,
        ["CVE-2026-0001"],
        [],
        "ok",
    )


@pytest.mark.parametrize(
    ("raw", "reason"),
    [
        ("", "empty"),
        ("   \n", "empty"),
        ("not json at all", "not_json"),
        ('{"answer": "x", "abstain": false, "citations": [', "not_json"),
        ("[1, 2]", "not_object"),
        ('"text"', "not_object"),
        ('{"abstain": false, "citations": []}', "missing_answer"),
        ('{"answer": "x", "citations": []}', "missing_abstain"),
        ('{"answer": "x", "abstain": false}', "missing_citations"),
        ('{"answer": 3, "abstain": false, "citations": []}', "bad_answer"),
        ('{"answer": "x", "abstain": "true", "citations": []}', "bad_abstain"),
        ('{"answer": "x", "abstain": 1, "citations": []}', "bad_abstain"),
        ('{"answer": "x", "abstain": false, "citations": "CVE-2026-0001"}', "bad_citations"),
        ('{"answer": "x", "abstain": false, "citations": [true]}', "bad_citations"),
        ('{"answer": "x", "abstain": false, "citations": [["a"]]}', "bad_citations"),
        ('{"answer": "x", "abstain": false, "citations": [null]}', "bad_citations"),
    ],
)
def test_parse_failures_use_fixed_reason_codes(raw, reason):
    result = pl.parse_answer(raw, ALLOWED)
    assert result == ("", False, [], [], f"parse_failed:{reason}")
    assert reason in pl.PARSE_REASONS


def test_parse_failure_status_never_carries_input_text():
    secret = "SYNTHETIC-BODY-SECRET"
    for raw in (f"{secret} not json", f'["{secret}"]', f'{{"answer": "{secret}"}}'):
        assert secret not in pl.parse_answer(raw, ALLOWED)[4]


def test_parse_out_of_context_citations_are_invalid_and_deduplicated():
    raw = reply("x", False, ["CVE-2026-0001", "CVE-2026-9999", "CVE-2026-0001", " CVE-2026-0002 "])
    _, _, citations, invalid, status = pl.parse_answer(raw, ALLOWED)
    assert status == "ok"
    assert citations == ["CVE-2026-0001", "CVE-2026-0002"]
    assert invalid == ["CVE-2026-9999"]


def test_parse_integer_ids_become_strings():
    raw = '{"answer": "x", "abstain": false, "citations": [90001, "90002", 99999]}'
    _, _, citations, invalid, status = pl.parse_answer(raw, {"90001", "90002"})
    assert (status, citations, invalid) == ("ok", ["90001", "90002"], ["99999"])


def test_parse_extra_keys_are_ignored_and_abstain_may_cite():
    raw = '{"answer": "", "abstain": true, "citations": [], "reason": "no"}'
    assert pl.parse_answer(raw, ALLOWED) == ("", True, [], [], "ok")


# ------------------------------------------------------------ generate: 재질의·문맥 초과


def test_generate_first_attempt_ok():
    llm = FakeLLM([reply("답", False, ["A"])], prompt_tokens=123, eval_count=7, latency_ms=11.5)
    result = pl.generate("질문", "[A]\ntext", {"A"}, llm)
    assert (result.status, result.answer, result.citations) == ("ok", "답", ["A"])
    assert (result.n_attempts, result.prompt_tokens, result.completion_tokens) == (1, 123, 7)
    assert result.latency_ms == 11.5
    assert len(llm.calls) == 1


def test_generate_retries_once_then_succeeds():
    llm = FakeLLM(["not json", reply("고친 답", False, ["A"])], prompt_tokens=[100, 250])
    result = pl.generate("질문", "[A]\ntext", {"A"}, llm)
    assert result.status == "ok"
    assert result.n_attempts == 2
    assert result.prompt_tokens == 100  # 입력 토큰은 첫 시도
    assert result.completion_tokens == 20  # 출력 토큰·지연은 모든 시도의 합
    assert result.latency_ms == 10.0
    assert len(llm.calls) == 2
    retry = llm.calls[1]
    assert retry[:2] == llm.calls[0]
    assert retry[2] == {"role": "assistant", "content": "not json"}
    assert retry[3] == {
        "role": "user",
        "content": pl.RETRY_TEMPLATE.format(reason="not_json"),
    }


def test_generate_gives_up_after_one_retry():
    llm = FakeLLM(["nope", '{"answer": "x"}', reply()])
    result = pl.generate("질문", "ctx", {"A"}, llm)
    assert result.status == "parse_failed:missing_abstain"
    assert result.n_attempts == 2
    assert len(llm.calls) == 2  # 세 번째 호출은 없다
    assert (result.abstain, result.citations, result.n_invalid_citations) == (False, [], 0)


def test_generate_counts_invalid_citations_without_keeping_them():
    llm = FakeLLM([reply("x", False, ["A", "SYNTHETIC-BODY-LEAK", "Z-9"])])
    result = pl.generate("질문", "ctx", {"A"}, llm)
    assert result.citations == ["A"]
    assert result.n_invalid_citations == 2
    assert "SYNTHETIC-BODY-LEAK" not in repr(result)


@pytest.mark.parametrize(
    ("prompt_tokens", "status"),
    [
        (100, "ok"),
        (999, "ok"),
        (1000, "context_overflow"),
        (1001, "context_overflow"),
        (None, "ok"),  # 세지 못하면 판정하지 않는다
    ],
)
def test_generate_context_overflow_boundary(prompt_tokens, status):
    llm = FakeLLM([reply("x", False, ["A"])], max_prompt_tokens=1000, prompt_tokens=prompt_tokens)
    result = pl.generate("질문", "ctx", {"A"}, llm)
    assert result.status == status
    if status == "context_overflow":
        assert (result.abstain, result.citations, result.n_attempts) == (False, [], 1)
        assert len(llm.calls) == 1  # 재질의 없음
        assert result.prompt_tokens == prompt_tokens


def test_generate_without_a_limit_never_reports_overflow():
    llm = FakeLLM([reply()], prompt_tokens=10**6)
    assert pl.generate("질문", "ctx", set(), llm).status == "ok"


# ------------------------------------------------------------ 검색


def test_retrieve_is_bm25_top_k_with_id_tiebreak():
    index = pl.GenerationIndex("public", PUBLIC_RECORDS, 1.2, 0.75)
    reference = BM25Index(PUBLIC_RECORDS, k1=1.2, b=0.75)
    scores = reference.score("acme router firmware")
    ranked = sorted(scores, key=lambda d: (-scores[d], d))
    assert [d for d, _ in pl.retrieve(index, "acme router firmware", 2)] == ranked[:2]
    assert pl.retrieve(index, "acme router firmware", 2)[0][1] == scores[ranked[0]]


def test_retrieve_returns_fewer_than_k_or_nothing():
    index = pl.GenerationIndex("public", PUBLIC_RECORDS, 1.2, 0.75)
    assert len(pl.retrieve(index, "sql injection", 5)) < 5
    assert pl.retrieve(index, "zzzz qqqq", 5) == []
    with pytest.raises(ValueError, match="k must be positive"):
        pl.retrieve(index, "sql", 0)


def test_retrieve_ties_sort_by_doc_id():
    index = pl.GenerationIndex("public", {"B-2": "same", "A-1": "same", "C-3": "other"}, 1.2, 0.75)
    assert [d for d, _ in pl.retrieve(index, "same", 2)] == ["A-1", "B-2"]


def test_build_index_reads_selected_params_per_track(root):
    public = pl.build_index("public", root)
    assert (public.k1, public.b, public.n_documents) == (1.2, 0.75, len(PUBLIC_RECORDS))
    kisa = pl.build_index("kisa", root, fake_body_loader)
    assert (kisa.k1, kisa.b, kisa.n_documents) == (3.0, 0.9, len(NTT_IDS))
    assert kisa.text("90002") == f"공지 90002\n{KISA_BODIES['90002']}"
    assert public.text("CVE-2026-0001") == "CVE-2026-0001 " + PUBLIC_RECORDS["CVE-2026-0001"]


def test_build_index_kisa_needs_a_loader_and_rejects_unknown_tracks(root):
    with pytest.raises(ValueError, match="load_body"):
        pl.build_index("kisa", root)
    with pytest.raises(ValueError, match="unknown track"):
        pl.build_index("other", root)


# ------------------------------------------------------------ run_question·행 키·유출 방지


def questions_by_id(root, track):
    return {q.question_id: q for q in data.load_questions(track, root)}


def test_run_question_row_has_exactly_the_fixed_keys(root):
    index = pl.build_index("public", root)
    question = questions_by_id(root, "public")["q-prod-1"]
    llm = FakeLLM([reply("답", False, ["CVE-2026-0003"])])
    row = pl.run_question(question, index, 3, llm)
    assert tuple(row) == pl.PUBLIC_ROW_KEYS
    pl.validate_row(row, "public")
    assert row["retrieved"][0] == "CVE-2026-0003"
    assert row["n_retrieved"] == len(row["retrieved"]) <= 3
    assert row["context_chars"] > 0
    assert (
        row["context_sha256"]
        == hashlib.sha256(
            pl.build_context("public", row["retrieved"], index.text)[0].encode()
        ).hexdigest()
    )
    assert (row["split"], row["query_type"], row["k"]) == ("dev", "product_symptom", 3)


def test_zero_retrieved_still_calls_the_llm_with_an_empty_context(root):
    index = pl.build_index("public", root)
    question = questions_by_id(root, "public")["q-na-1"]
    llm = FakeLLM([reply("", True, [])])
    row = pl.run_question(question, index, 5, llm)
    assert len(llm.calls) == 1
    assert pl.EMPTY_CONTEXT in llm.calls[0][1]["content"]
    assert (row["n_retrieved"], row["retrieved"], row["context_chars"]) == (0, [], 0)
    assert (row["status"], row["abstain"]) == ("ok", True)  # 자동 기권이 아니라 모델 응답


def test_run_question_records_truncated_documents(root):
    index = pl.build_index("kisa", root, fake_body_loader)
    question = questions_by_id(root, "kisa")["k-cve-1"]
    row = pl.run_question(question, index, 1, FakeLLM([reply("x", False, ["90001"])]))
    assert row["retrieved"] == ["90001"]
    assert row["truncated"] == ["90001"]
    assert row["context_chars"] == len("[90001]\n") + pl.DOC_CHAR_CAP


def test_kisa_commit_row_has_no_answer_and_no_body_text(root):
    index = pl.build_index("kisa", root, fake_body_loader)
    question = questions_by_id(root, "kisa")["k-prod-1"]
    llm = FakeLLM([reply("SYNTHETIC-BODY-BETA 를 옮긴 답", False, ["90002"])])
    full = pl.run_question(question, index, 3, llm)
    committed = pl.commit_row(full, "kisa")
    assert "answer" not in committed
    assert tuple(committed) == pl.ROW_KEYS
    pl.validate_row(committed, "kisa")
    assert "SYNTHETIC-BODY" not in json.dumps(committed, ensure_ascii=False)


def test_public_commit_row_keeps_answer(root):
    index = pl.build_index("public", root)
    question = questions_by_id(root, "public")["q-cve-1"]
    row = pl.run_question(question, index, 1, FakeLLM([reply("공개 답", False, ["CVE-2026-0001"])]))
    assert pl.commit_row(row, "public")["answer"] == "공개 답"


def test_citations_carrying_a_synthetic_body_are_dropped_and_counted(root):
    index = pl.build_index("kisa", root, fake_body_loader)
    question = questions_by_id(root, "kisa")["k-prod-1"]
    leak = KISA_BODIES["90002"]
    llm = FakeLLM([reply("답", False, ["90002", leak, "SYNTHETIC-BODY-GAMMA"])])
    committed = pl.commit_row(pl.run_question(question, index, 3, llm), "kisa")
    text = json.dumps(committed, ensure_ascii=False)
    assert committed["citations"] == ["90002"]
    assert committed["n_invalid_citations"] == 2
    assert "SYNTHETIC-BODY" not in text
    assert leak not in text


def valid_row(**changes):
    row = {
        "question_id": "q1",
        "split": "dev",
        "query_type": "cve_explicit",
        "k": 3,
        "status": "ok",
        "abstain": False,
        "citations": ["A"],
        "n_invalid_citations": 0,
        "retrieved": ["A", "B"],
        "truncated": [],
        "n_retrieved": 2,
        "prompt_tokens": 100,
        "completion_tokens": 10,
        "latency_ms": 12.5,
        "context_sha256": "0" * 64,
        "n_attempts": 1,
        "context_chars": 50,
    }
    row.update(changes)
    return row


@pytest.mark.parametrize("track", ["public", "kisa"])
def test_validate_row_accepts_the_allowed_shape(track):
    row = valid_row()
    if track == "public":
        row["answer"] = "답"
    pl.validate_row(row, track)


@pytest.mark.parametrize(
    ("track", "changes", "message"),
    [
        ("kisa", {"answer": "원문"}, "keys"),
        ("kisa", {"context": "원문"}, "keys"),
        ("public", {}, "keys"),  # answer 누락
        ("public", {"answer": "x", "raw": "x"}, "keys"),
        ("kisa", {"status": "parse_failed:custom text"}, "bad status"),
        ("kisa", {"status": "failed"}, "bad status"),
        ("kisa", {"abstain": "false"}, "abstain"),
        ("kisa", {"citations": ["Z"]}, "subset of retrieved"),
        ("kisa", {"citations": ["A", "A"]}, "unique"),
        ("kisa", {"truncated": ["Z"]}, "truncated"),
        ("kisa", {"n_retrieved": 3}, "n_retrieved"),
        ("kisa", {"retrieved": ["A", "B", "C", "D"], "n_retrieved": 4}, "n_retrieved"),
        ("kisa", {"n_attempts": 3}, "n_attempts"),
        ("kisa", {"prompt_tokens": "100"}, "prompt_tokens"),
        ("kisa", {"latency_ms": "12"}, "latency_ms"),
        ("kisa", {"context_sha256": "abc"}, "context_sha256"),
        ("kisa", {"status": "context_overflow", "citations": ["A"]}, "non-ok"),
        ("kisa", {"status": "parse_failed:not_json", "abstain": True}, "non-ok"),
    ],
)
def test_validate_row_rejects(track, changes, message):
    row = valid_row()
    if track == "public" and "answer" not in changes and message != "keys":
        row["answer"] = "x"
    row.update(changes)
    with pytest.raises(ValueError, match=message):
        pl.validate_row(row, track)


# ------------------------------------------------------------ 예상 질문 집합


def test_expected_questions_exclude_flagged_kisa_questions(root):
    assert [q.question_id for q in pl.expected_questions("kisa", root)] == [
        "k-cve-1",
        "k-prod-1",
        "k-na-1",
    ]
    assert len(pl.expected_questions("public", root)) == len(PUBLIC_QUERIES)


def full_rows(root, track="public", k=3):
    index = pl.build_index(track, root, fake_body_loader if track == "kisa" else None)
    questions = pl.expected_questions(track, root)
    llm = FakeLLM([reply("x", False, [])])
    return questions, [pl.commit_row(pl.run_question(q, index, k, llm), track) for q in questions]


def test_check_row_set_accepts_the_exact_set(root):
    questions, rows = full_rows(root)
    pl.check_row_set(rows, questions, 3)


def test_check_row_set_rejects_a_missing_row_filled_by_a_duplicate(root):
    questions, rows = full_rows(root)
    tampered = [*rows[:-1], dict(rows[0])]  # 누락 1건을 다른 행 복제로 채움
    with pytest.raises(ValueError, match="duplicate"):
        pl.check_row_set(tampered, questions, 3)


def test_check_row_set_rejects_missing_extra_and_wrong_k(root):
    questions, rows = full_rows(root)
    with pytest.raises(ValueError, match="differs"):
        pl.check_row_set(rows[:-1], questions, 3)
    with pytest.raises(ValueError, match="differs"):
        pl.check_row_set([*rows, {**rows[0], "question_id": "q-extra"}], questions, 3)
    with pytest.raises(ValueError, match="k/split"):
        pl.check_row_set(rows, questions, 5)
    with pytest.raises(ValueError, match="k/split"):
        pl.check_row_set([{**rows[0], "split": "test"}, *rows[1:]], questions, 3)


# ------------------------------------------------------------ 기계 지표


def gq(qid, query_type, gold=(), unjudged=(), split="dev"):
    return data.Question(
        qid, "질문", query_type, split, frozenset(gold), frozenset(unjudged), excluded=False
    )


def mrow(qid, query_type, split="dev", **changes):
    row = valid_row(question_id=qid, query_type=query_type, split=split)
    row.update(changes)
    return row


def test_cell_metrics_hand_computed_example():
    questions = {
        "a1": gq("a1", "cve_explicit", ["G1"], ["U1"]),
        "a2": gq("a2", "cve_explicit", ["G2"]),
        "a3": gq("a3", "cve_explicit", ["G3"]),
        "a4": gq("a4", "cve_explicit", ["G4"]),
        "a5": gq("a5", "cve_explicit", ["G5"]),
        "n1": gq("n1", "no_answer"),
        "n2": gq("n2", "no_answer"),
        "n3": gq("n3", "no_answer"),
    }
    rows = [
        # a1: 적중 + unjudged 인용 1 + 무효 1
        mrow("a1", "cve_explicit", citations=["G1", "U1"], n_invalid_citations=1, retrieved=["G1", "U1"], prompt_tokens=100, latency_ms=10.0, context_chars=10),
        # a2: 비기권인데 정답 아님
        mrow("a2", "cve_explicit", citations=["X"], retrieved=["X"], prompt_tokens=300, latency_ms=30.0, context_chars=30),
        # a3: 잘못된 기권
        mrow("a3", "cve_explicit", abstain=True, citations=[], retrieved=["G3"], prompt_tokens=200, latency_ms=20.0, context_chars=20),
        # a4: 파싱 실패(기권 아님으로 센다, 인용 분모에도 안 들어감)
        mrow("a4", "cve_explicit", status="parse_failed:not_json", citations=[], prompt_tokens=400, latency_ms=40.0, n_attempts=2, context_chars=40),
        # a5: 문맥 초과
        mrow("a5", "cve_explicit", status="context_overflow", citations=[], prompt_tokens=None, latency_ms=None, context_chars=50),
        # n1: 올바른 기권, n2: 기권 안 함, n3: 파싱 실패
        mrow("n1", "no_answer", abstain=True, citations=[], retrieved=[], n_retrieved=0, truncated=[]),
        mrow("n2", "no_answer", citations=["X"], retrieved=["X"]),
        mrow("n3", "no_answer", status="parse_failed:empty", citations=[]),
    ]  # fmt: skip
    cell = pl.cell_metrics(rows, questions)
    assert cell["n_questions"] == 8
    assert (cell["n_ok"], cell["n_parse_failed"], cell["n_context_overflow"]) == (5, 2, 1)
    assert cell["parse_success_rate"] == 5 / 8
    assert cell["parse_fail_rate"] == 2 / 8
    assert cell["context_overflow_rate"] == 1 / 8
    assert cell["correct_abstain_rate"] == 1 / 3  # 분모 = no_answer 전부(파싱 실패 포함)
    assert cell["false_abstain_rate"] == 1 / 5  # 분모 = 정답 있는 질문 전부
    assert cell["n_cited_answers"] == 2  # a1, a2 (ok, 비기권)
    assert cell["n_citation_hits"] == 1
    assert cell["citation_hit_rate"] == 1 / 2
    assert (cell["n_valid_citations"], cell["n_invalid_citations"]) == (4, 1)  # G1,U1,X,X / 1
    assert cell["invalid_citation_rate"] == 1 / 5
    assert cell["n_unjudged_citations"] == 1
    assert cell["prompt_tokens_median"] == 100.0  # 100 x4, 200, 300, 400 (null 제외)
    assert cell["prompt_tokens_max"] == 400
    assert cell["n_retried"] == 1


def test_cell_metrics_medians_ignore_nulls():
    questions = {f"a{i}": gq(f"a{i}", "cve_explicit", ["G"]) for i in range(1, 5)}
    rows = [
        mrow("a1", "cve_explicit", prompt_tokens=10, latency_ms=1.0, context_chars=5),
        mrow("a2", "cve_explicit", prompt_tokens=30, latency_ms=3.0, context_chars=7),
        mrow("a3", "cve_explicit", prompt_tokens=20, latency_ms=2.0, context_chars=9),
        mrow("a4", "cve_explicit", prompt_tokens=None, latency_ms=None, context_chars=11),
    ]
    cell = pl.cell_metrics(rows, questions)
    assert (cell["prompt_tokens_median"], cell["prompt_tokens_max"]) == (20.0, 30)
    assert cell["latency_ms_median"] == 2.0
    assert cell["context_chars_median"] == 8.0


def test_cell_metrics_zero_denominators_are_null():
    questions = {"n1": gq("n1", "no_answer")}
    rows = [mrow("n1", "no_answer", abstain=True, citations=[], retrieved=[], n_retrieved=0)]
    cell = pl.cell_metrics(rows, questions)
    assert cell["correct_abstain_rate"] == 1.0
    assert cell["false_abstain_rate"] is None  # 정답 있는 질문 없음
    assert cell["citation_hit_rate"] is None  # 인용 분모 0
    assert cell["invalid_citation_rate"] is None  # 인용 0건
    assert pl.cell_metrics([], {})["parse_success_rate"] is None


def test_answers_without_citations_add_zero_to_the_invalid_rate():
    questions = {"a1": gq("a1", "cve_explicit", ["G"]), "a2": gq("a2", "cve_explicit", ["G"])}
    rows = [
        mrow("a1", "cve_explicit", citations=[], n_invalid_citations=0),
        mrow("a2", "cve_explicit", citations=["G"], n_invalid_citations=1, retrieved=["G"]),
    ]
    cell = pl.cell_metrics(rows, questions)
    assert cell["invalid_citation_rate"] == 1 / 2  # 마이크로: 무효 1 / (검증 1 + 무효 1)
    assert cell["citation_hit_rate"] == 1 / 2


def test_unjudged_citation_is_neither_a_hit_nor_invalid():
    questions = {"a1": gq("a1", "cve_explicit", ["G"], ["U"])}
    rows = [mrow("a1", "cve_explicit", citations=["U"], retrieved=["U", "G"])]
    cell = pl.cell_metrics(rows, questions)
    assert cell["citation_hit_rate"] == 0.0
    assert cell["n_unjudged_citations"] == 1
    assert cell["n_invalid_citations"] == 0


def test_compute_topk_cells_macro_and_splits():
    questions = {
        "c1": gq("c1", "cve_explicit", ["G"], split="dev"),
        "c2": gq("c2", "cve_explicit", ["G"], split="test"),
        "p1": gq("p1", "product_symptom", ["G"], split="dev"),
        "n1": gq("n1", "no_answer", split="dev"),
    }
    rows = [
        mrow("c1", "cve_explicit", "dev", citations=["G"], retrieved=["G"]),
        mrow("c2", "cve_explicit", "test", abstain=True, citations=[]),
        mrow("p1", "product_symptom", "dev", citations=["X"], retrieved=["X"]),
        mrow("n1", "no_answer", "dev", abstain=True, citations=[], retrieved=[], n_retrieved=0),
    ]
    topk = pl.compute_topk({("public", 3): rows}, {"public": list(questions.values())})
    by_key = {(c["split"], c["query_type"]): c for c in topk["cells"]}
    assert {c["track"] for c in topk["cells"]} == {"public"}
    assert {c["k"] for c in topk["cells"]} == {3}
    assert ("dev", "macro") in by_key
    assert ("test", "no_answer") not in by_key  # 행이 없는 칸은 만들지 않는다
    # dev macro = (cve_explicit 1.0 + product_symptom 0.0) / 2 (인용 적중률)
    assert by_key[("dev", "macro")]["citation_hit_rate"] == 0.5
    assert by_key[("all", "cve_explicit")]["n_questions"] == 2
    assert by_key[("all", "all")]["n_questions"] == 4
    assert by_key[("all", "macro")]["false_abstain_rate"] == (0.5 + 0.0) / 2
    assert by_key[("dev", "macro")]["correct_abstain_rate"] is None  # macro는 정답 있는 유형만
    assert by_key[("dev", "no_answer")]["correct_abstain_rate"] == 1.0


def test_compare_topk_tolerance_and_structure():
    base = {"schema": pl.TOPK_SCHEMA, "cells": [cell_of(0.5), cell_of(None, k=5)]}
    same = {"schema": pl.TOPK_SCHEMA, "cells": [cell_of(0.5 + 1e-10), cell_of(None, k=5)]}
    assert pl.compare_topk(base, same) == []
    off = {"schema": pl.TOPK_SCHEMA, "cells": [cell_of(0.5 + 1e-6), cell_of(None, k=5)]}
    assert any("citation_hit_rate" in p for p in pl.compare_topk(base, off))
    null_vs_value = {"schema": pl.TOPK_SCHEMA, "cells": [cell_of(0.5), cell_of(0.0, k=5)]}
    assert pl.compare_topk(base, null_vs_value)
    missing = {"schema": pl.TOPK_SCHEMA, "cells": [cell_of(0.5)]}
    assert any("only in stored" in p for p in pl.compare_topk(base, missing))
    assert any("only in recomputed" in p for p in pl.compare_topk(missing, base))
    assert pl.compare_topk(base, {"schema": "other", "cells": base["cells"]})


def cell_of(rate, k=3):
    return {
        "track": "public",
        "k": k,
        "split": "all",
        "query_type": "all",
        "citation_hit_rate": rate,
        "n_questions": 4,
    }


# ------------------------------------------------------------ 이어 돌리기·성공률 하한


def test_success_rate_counts_overflow_and_final_failures_as_failures():
    rows = [
        {"status": "ok"},
        {"status": "ok"},
        {"status": "parse_failed:not_json"},
        {"status": "context_overflow"},
    ]
    assert pl.success_rate(rows) == 0.5
    assert pl.success_rate([]) == 0.0


@pytest.mark.parametrize(("n", "allowed"), [(144, 28), (52, 10), (10, 2), (5, 1), (1, 0)])
def test_max_failures_keeps_success_at_or_above_80_percent(n, allowed):
    assert pl.max_failures(n) == allowed
    assert (n - allowed) / n >= pl.SUCCESS_FLOOR
    assert (n - allowed - 1) / n < pl.SUCCESS_FLOOR


def test_run_track_k_resumes_without_calling_the_llm_again(root, tmp_path):
    index = pl.build_index("public", root)
    questions = pl.expected_questions("public", root)
    local = tmp_path / "local" / "public_k3.jsonl"
    first = FakeLLM([reply("x", False, [])])
    pl.run_track_k(questions[:3], index, 3, first, "run-1", local)
    assert len(first.calls) == 3
    second = FakeLLM([reply("x", False, [])])
    rows = pl.run_track_k(questions, index, 3, second, "run-1", local)
    assert len(second.calls) == len(questions) - 3  # 이미 한 3건은 다시 부르지 않는다
    assert [r["question_id"] for r in rows] == [q.question_id for q in questions]
    assert all(r["run_id"] == "run-1" for r in rows)
    other = FakeLLM([reply("x", False, [])])
    pl.run_track_k(questions, index, 3, other, "run-2", local)
    assert len(other.calls) == len(questions)  # 다른 실행 ID의 캐시는 쓰지 않는다


def test_run_track_k_aborts_when_the_floor_cannot_be_met(root, tmp_path):
    index = pl.build_index("public", root)
    questions = pl.expected_questions("public", root)
    llm = FakeLLM(["not json"])
    with pytest.raises(pl.GateFailure, match="exceed"):
        pl.run_track_k(questions, index, 3, llm, "run-1", tmp_path / "p.jsonl", failure_limit=1)
    assert len(llm.calls) == 4  # 실패 2건(질문당 호출 2회)에서 중단


# ------------------------------------------------------------ Ollama 응답 모형


def chat_payload(**changes):
    payload = {
        "model": "m",
        "message": {"role": "assistant", "content": '{"answer": ""}'},
        "done": True,
        "done_reason": "stop",
        "total_duration": 5_000_000_000,
        "load_duration": 2_000_000_000,
        "prompt_eval_count": 321,
        "eval_count": 45,
    }
    payload.update(changes)
    return payload


def test_parse_chat_response_reads_tokens_and_latency_without_load_time():
    response = llm_module.parse_chat_response(chat_payload())
    assert response == LLMResponse('{"answer": ""}', 321, 45, 3000.0, "stop")


@pytest.mark.parametrize("missing", ["prompt_eval_count", "eval_count", "total_duration"])
def test_parse_chat_response_missing_numbers_are_none(missing):
    payload = chat_payload()
    del payload[missing]
    response = llm_module.parse_chat_response(payload)
    field = {
        "prompt_eval_count": "prompt_eval_count",
        "eval_count": "eval_count",
        "total_duration": "latency_ms",
    }[missing]
    assert getattr(response, field) is None


@pytest.mark.parametrize(
    "payload",
    [{}, {"message": "x"}, {"message": {"role": "assistant"}}, {"message": {"content": 3}}],
)
def test_parse_chat_response_rejects_a_malformed_payload(payload):
    with pytest.raises(LLMError):
        llm_module.parse_chat_response(payload)


def test_request_body_pins_the_fixed_options():
    llm = llm_module.OllamaLLM(model="qwen3:8b")
    body = llm.request_body([{"role": "user", "content": "hi"}])
    assert body["stream"] is False
    assert body["format"] == "json"
    assert body["think"] is False
    assert body["options"] == {"temperature": 0, "seed": 42, "num_ctx": 16384, "num_predict": 512}
    assert "keep_alive" not in body
    assert llm.max_prompt_tokens == 16384 - 512
    assert llm_module.OllamaLLM(keep_alive=0).request_body([])["keep_alive"] == 0


class FakeHTTPResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def patch_urlopen(monkeypatch, handler):
    seen = []

    def fake(request, timeout=None):
        seen.append(request)
        return handler(request)

    monkeypatch.setattr(llm_module.urllib.request, "urlopen", fake)
    return seen


def test_ollama_llm_posts_to_api_chat_and_parses(monkeypatch):
    seen = patch_urlopen(
        monkeypatch, lambda r: FakeHTTPResponse(json.dumps(chat_payload()).encode())
    )
    response = llm_module.OllamaLLM(host="http://127.0.0.1:11434/")(
        [{"role": "user", "content": "q"}]
    )
    assert response.prompt_eval_count == 321
    assert seen[0].full_url == "http://127.0.0.1:11434/api/chat"
    assert json.loads(seen[0].data)["messages"] == [{"role": "user", "content": "q"}]
    assert seen[0].get_method() == "POST"


@pytest.mark.parametrize(
    "failure",
    [
        urllib.error.URLError("refused"),
        TimeoutError("slow"),
        ConnectionResetError("reset"),
        urllib.error.HTTPError("http://x/api/chat", 500, "boom", {}, io.BytesIO(b"body text")),
    ],
)
def test_ollama_llm_turns_transport_errors_into_llm_error(monkeypatch, failure):
    def boom(request):
        raise failure

    patch_urlopen(monkeypatch, boom)
    with pytest.raises(LLMError) as caught:
        llm_module.OllamaLLM()([{"role": "user", "content": "SYNTHETIC-BODY-PROMPT"}])
    assert "SYNTHETIC-BODY-PROMPT" not in str(caught.value)


@pytest.mark.parametrize("raw", [b"not json", b"[1]", b""])
def test_ollama_llm_rejects_non_object_json(monkeypatch, raw):
    patch_urlopen(monkeypatch, lambda r: FakeHTTPResponse(raw))
    with pytest.raises(LLMError):
        llm_module.OllamaLLM()([])


def test_model_info_reads_digest_license_and_context_limit(monkeypatch):
    weights = "a" * 64
    show = {
        "modelfile": f"# generated\nFROM /some/local/path/sha256-{weights}\nTEMPLATE x\n",
        "license": "                                 Apache License\n Version 2.0",
        "details": {"family": "qwen3", "parameter_size": "8.2B", "quantization_level": "Q4_K_M"},
        "model_info": {"general.architecture": "qwen3", "qwen3.context_length": 40960},
        "capabilities": ["completion"],
    }
    tags = {"models": [{"name": "other", "digest": "0"}, {"name": "qwen3:8b", "digest": "d" * 64}]}
    answers = {"/api/show": show, "/api/tags": tags, "/api/version": {"version": "0.32.15"}}
    patch_urlopen(
        monkeypatch,
        lambda r: FakeHTTPResponse(json.dumps(answers[r.full_url.rsplit("11434", 1)[1]]).encode()),
    )
    info = llm_module.model_info("qwen3:8b")
    assert info["digest"] == "d" * 64
    assert info["weights_sha256"] == weights
    assert (info["license"], info["context_length"]) == ("Apache-2.0", 40960)
    assert info["ollama_version"] == "0.32.15"
    assert "/some/local" not in json.dumps(info)


# ------------------------------------------------------------ 실행·manifest·저장본 검사


@pytest.fixture
def stored(root, tmp_path):
    """합성 코퍼스로 두 트랙 x k=1,3을 가짜 LLM으로 돌려 저장한 결과 디렉터리."""
    out_dir = tmp_path / "out"
    local = tmp_path / "local"
    llm = FakeLLM([reply("답", False, [])])
    model = {"name": "fake:1b", "digest": "d" * 64, "weights_sha256": "w" * 64}
    manifest = pl.new_manifest(model, llm, root, {"identical": True})
    for track in ("public", "kisa"):
        index = pl.build_index(track, root, fake_body_loader if track == "kisa" else None)
        pl.run_track(track, [1, 3], root, index, llm, manifest, out_dir, local)
    pl.write_json(out_dir / "manifest.json", manifest)
    pl.write_json(out_dir / "topk.json", pl.recompute_topk(root, out_dir, manifest))
    return out_dir, local, manifest


def test_stored_results_pass_the_check(root, stored):
    out_dir, _, manifest = stored
    assert pl.check_stored(root, out_dir) == []
    assert sorted(manifest["tracks"]) == ["kisa", "public"]
    assert sorted(manifest["tracks"]["kisa"]["outputs"]) == ["k1", "k3"]
    assert manifest["tracks"]["kisa"]["n_questions"] == 3  # excluded 제외
    assert manifest["run_id"] == pl.make_run_id(pl.run_config(manifest["model"], FakeLLM([]), root))


def test_kisa_result_rows_have_no_answer_but_the_local_cache_does(root, stored):
    out_dir, local, manifest = stored
    for k in (1, 3):
        for row in pl.read_jsonl_rows(out_dir / f"kisa_k{k}.jsonl"):
            assert "answer" not in row
            assert tuple(row) == pl.ROW_KEYS
        cached = pl.read_jsonl_rows(local / f"kisa_k{k}.jsonl")
        assert all(r["answer"] == "답" and r["run_id"] == manifest["run_id"] for r in cached)
        # 로컬 캐시 행은 커밋 행의 문맥 해시와 같다(#66이 같은 실행인지 확인한다)
        committed = pl.read_jsonl_rows(out_dir / f"kisa_k{k}.jsonl")
        assert [r["context_sha256"] for r in cached] == [r["context_sha256"] for r in committed]
    for row in pl.read_jsonl_rows(out_dir / "public_k1.jsonl"):
        assert tuple(row) == pl.PUBLIC_ROW_KEYS


def test_committed_outputs_contain_no_kisa_body_or_local_paths(root, stored):
    out_dir, local, _ = stored
    for path in out_dir.rglob("*"):
        if path.is_file():
            text = path.read_text(encoding="utf-8")
            assert "SYNTHETIC-BODY" not in text
            assert str(root) not in text
            assert str(local) not in text


def rewrite_rows(path, edit):
    rows = pl.read_jsonl_rows(path)
    pl.write_jsonl_atomic(path, edit(rows))


def refresh_hash(out_dir, track, k):
    manifest = pl.load_manifest(out_dir)
    manifest["tracks"][track]["outputs"][f"k{k}"]["sha256"] = data.file_sha256(
        out_dir / f"{track}_k{k}.jsonl"
    )
    pl.write_json(out_dir / "manifest.json", manifest)


@pytest.mark.parametrize(
    ("track", "edit", "message"),
    [
        ("kisa", lambda rows: [{**r, "answer": "원문"} for r in rows], "keys"),
        ("kisa", lambda rows: [{**r, "run_id": "x"} for r in rows], "keys"),
        ("public", lambda rows: rows[:-1], "differs"),
        ("public", lambda rows: [*rows[:-1], dict(rows[0])], "duplicate"),
        ("kisa", lambda rows: [{**r, "citations": ["Z-9"]} for r in rows], "subset"),
        (
            "public",
            lambda rows: [{**r, "status": "parse_failed:not_json", "citations": []} for r in rows],
            "parse success",
        ),
    ],
)
def test_check_stored_fails_for_tampered_rows(root, stored, track, edit, message):
    out_dir, _, _ = stored
    rewrite_rows(out_dir / f"{track}_k3.jsonl", edit)
    refresh_hash(out_dir, track, 3)
    problems = pl.check_stored(root, out_dir)
    assert problems
    assert any(message in p for p in problems)


def test_check_stored_detects_a_changed_file_without_a_manifest_update(root, stored):
    out_dir, _, _ = stored
    rewrite_rows(out_dir / "public_k1.jsonl", lambda rows: [{**r, "answer": "바뀜"} for r in rows])
    assert any("sha256 differs" in p for p in pl.check_stored(root, out_dir))


def test_check_stored_detects_a_changed_topk_value(root, stored):
    out_dir, _, _ = stored
    topk = json.loads((out_dir / "topk.json").read_text(encoding="utf-8"))
    topk["cells"][0]["parse_success_rate"] = 0.5
    pl.write_json(out_dir / "topk.json", topk)
    assert any("parse_success_rate" in p for p in pl.check_stored(root, out_dir))


def test_check_stored_tolerates_float_noise_below_1e9(root, stored):
    out_dir, _, _ = stored
    topk = json.loads((out_dir / "topk.json").read_text(encoding="utf-8"))
    cell = next(c for c in topk["cells"] if c["parse_success_rate"] is not None)
    cell["parse_success_rate"] += 1e-11
    pl.write_json(out_dir / "topk.json", topk)
    assert pl.check_stored(root, out_dir) == []


def test_check_stored_reports_missing_files(root, stored, tmp_path):
    out_dir, _, _ = stored
    (out_dir / "kisa_k1.jsonl").unlink()
    assert any("missing" in p for p in pl.check_stored(root, out_dir))
    assert pl.check_stored(root, tmp_path / "nowhere") == ["manifest.json is missing"]
    (out_dir / "kisa_k1.jsonl").write_text("", encoding="utf-8")
    (out_dir / "topk.json").unlink()
    assert pl.check_stored(root, out_dir)


def test_run_track_refuses_to_write_below_the_success_floor(root, tmp_path):
    index = pl.build_index("public", root)
    llm = FakeLLM(["not json"])
    manifest = pl.new_manifest({"name": "m", "digest": "d", "weights_sha256": "w"}, llm, root, None)
    with pytest.raises(pl.GateFailure):
        pl.run_track("public", [3], root, index, llm, manifest, tmp_path / "o", tmp_path / "l")
    assert not (tmp_path / "o" / "public_k3.jsonl").exists()


def test_sample_questions_rotates_through_query_types(root):
    questions = pl.expected_questions("public", root)
    sample = pl.sample_questions(questions, 4)
    assert [q.query_type for q in sample] == [
        "cve_explicit",
        "product_symptom",
        "no_answer",
        "cve_explicit",
    ]
    assert pl.sample_questions(questions, None) == questions
    assert pl.sample_questions(questions, 99) == questions


# ------------------------------------------------------------ CLI


def test_cli_metrics_only_fails_without_stored_results(tmp_path, capsys):
    code = run_generation.main(["--metrics-only", "--out-dir", str(tmp_path)])
    assert code == 1
    assert "manifest.json is missing" in capsys.readouterr().err


def test_cli_metrics_only_passes_on_synthetic_results(root, stored, monkeypatch, capsys):
    out_dir, _, manifest = stored
    monkeypatch.setattr(run_generation, "ROOT", root)
    assert run_generation.main(["--metrics-only", "--out-dir", str(out_dir)]) == 0
    assert manifest["run_id"] in capsys.readouterr().out


@pytest.mark.parametrize(
    "argv",
    [
        [],  # --track 없음
        ["--track", "kisa"],  # --kisa-root 없음
        ["--track", "public", "--limit", "3"],  # --limit은 --out-dir 필수
        ["--track", "public", "--k", "2"],  # k는 1, 3, 5만
        ["--track", "other"],
    ],
)
def test_cli_rejects_bad_arguments_before_touching_the_model(argv):
    with pytest.raises(SystemExit) as caught:
        run_generation.main(argv)
    assert caught.value.code == 2


def test_cli_ollama_error_is_exit_1_with_a_fixed_message(root, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(run_generation, "ROOT", root)
    monkeypatch.setattr(
        run_generation.llm_module,
        "model_info",
        lambda *a, **k: (_ for _ in ()).throw(LLMError("down")),
    )
    code = run_generation.main(
        ["--track", "public", "--limit", "2", "--out-dir", str(tmp_path / "o")]
    )
    assert code == 1
    assert "down" in capsys.readouterr().err


# ------------------------------------------------------------ 커밋된 결과 정합성

COMMITTED = ROOT / pl.RESULTS_DIR


@pytest.mark.skipif(not (COMMITTED / "manifest.json").is_file(), reason="results not generated yet")
def test_committed_results_pass_the_stored_check():
    assert pl.check_stored(ROOT, COMMITTED) == []


@pytest.mark.skipif(not (COMMITTED / "manifest.json").is_file(), reason="results not generated yet")
def test_committed_results_cover_both_tracks_and_all_k():
    manifest = json.loads((COMMITTED / "manifest.json").read_text(encoding="utf-8"))
    assert sorted(manifest["tracks"]) == ["kisa", "public"]
    for track, block in manifest["tracks"].items():
        assert sorted(block["outputs"]) == ["k1", "k3", "k5"]
        expected = len(pl.expected_questions(track, ROOT))
        for output in block["outputs"].values():
            assert output["n_rows"] == expected
            assert output["parse_success_rate"] >= pl.SUCCESS_FLOOR
    assert str(Path.home()) not in (COMMITTED / "manifest.json").read_text(encoding="utf-8")


# ------------------------------------------------------------ 보고서 표·문서


def synthetic_topk():
    questions = {
        "c1": gq("c1", "cve_explicit", ["G"]),
        "n1": gq("n1", "no_answer"),
    }
    rows = [
        mrow("c1", "cve_explicit", citations=["G"], retrieved=["G"]),
        mrow("n1", "no_answer", abstain=True, citations=[], retrieved=[], n_retrieved=0),
    ]
    return pl.compute_topk(
        {("public", 1): rows, ("public", 3): rows}, {"public": list(questions.values())}
    )


def test_render_tables_has_one_row_per_k_and_dashes_for_null():
    text = pl.render_tables(synthetic_topk())
    assert "### 공개 트랙 (NVD): k별 요약" in text
    assert "### KISA 트랙" not in text  # 행이 없는 트랙은 만들지 않는다
    summary = [line for line in text.splitlines() if line.startswith("| 1 | 2 |")]
    assert len(summary) == 1
    assert "1.000" in summary[0]
    macro = [line for line in text.splitlines() if line.startswith("| 1 | macro |")]
    assert macro
    assert "| - |" in macro[0]  # macro의 올바른 기권률은 null


def test_render_docs_replaces_only_the_marked_block(tmp_path):
    out_dir = tmp_path / "res"
    pl.write_json(out_dir / "topk.json", synthetic_topk())
    doc = tmp_path / pl.DOC_PATH
    doc.parent.mkdir(parents=True)
    doc.write_text(f"앞 문장\n{pl.BEGIN}\n옛 표\n{pl.END}\n뒤 문장\n", encoding="utf-8")
    updated = pl.render_docs(tmp_path, out_dir)
    assert updated.startswith("앞 문장\n") and updated.endswith("\n뒤 문장\n")
    assert "옛 표" not in updated
    assert pl.render_docs(tmp_path, out_dir) == updated  # 멱등


DOC = (ROOT / pl.DOC_PATH).read_text(encoding="utf-8")


@pytest.mark.parametrize(
    "function",
    [
        pl.build_index,
        pl.retrieve,
        pl.build_context,
        pl.build_prompt,
        pl.generate,
        pl.parse_answer,
        pl.run_question,
    ],
)
def test_doc_states_the_public_signature(function):
    import inspect

    names = ", ".join(inspect.signature(function).parameters)
    assert f"`{function.__name__}({names})`" in DOC


def test_doc_states_the_fixed_prompt_verbatim():
    for text in (pl.SYSTEM_PROMPT, pl.USER_TEMPLATE, pl.RETRY_TEMPLATE, pl.prompt_fingerprint()):
        assert text in DOC
    assert "—" not in DOC
    assert "/" + "Users" not in DOC


def test_doc_lists_every_row_key_and_reason_code():
    for key in pl.PUBLIC_ROW_KEYS:
        assert f"`{key}`" in DOC
    for reason in pl.PARSE_REASONS:
        assert f"`{reason}`" in DOC


@pytest.mark.skipif(not (COMMITTED / "topk.json").is_file(), reason="results not generated yet")
def test_doc_tables_match_the_committed_topk():
    topk = json.loads((COMMITTED / "topk.json").read_text(encoding="utf-8"))
    assert pl.render_tables(topk) in DOC
