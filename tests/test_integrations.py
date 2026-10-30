"""LangChain/LangGraph 어댑터(M5, #67) 테스트 - 가짜 LLM과 합성 색인만 쓴다. 네트워크·Ollama·모델·KISA 캐시를 쓰지 않는다.

langchain-core·langgraph는 CI의 dev 그룹에 없다. 없으면 이 파일 전체가 skip이다(`uv sync --locked --group langchain`).

확인하는 것: 코어 경로와 그래프 경로의 동등성(검색 순서·ID·점수, LLM에 넘긴 입력 문자열, abstain·citations·answer, 결과 행 전체;
동점·검색 0건·재질의·문맥 밖 인용 포함), 기권 분기와 인용 검사 노드(결과를 바꾸지 않음), `BaseRetriever` 어댑터,
langchain·langgraph import가 integrations 밖에 없다는 제약, CLI 보조 함수(기준 행 고르기, 필드 비교, run_id 대조)와
저장 결과를 되돌려 주는 가짜 LLM으로 `--compare` 전체 경로(검색 재현 포함).
"""

import asyncio
import importlib.util
import json
import re
import sys
from pathlib import Path

import pytest

pytest.importorskip("langchain_core")
pytest.importorskip("langgraph")

from krsec_rag_lab.baselines import data
from krsec_rag_lab.generation import llm as llm_module
from krsec_rag_lab.generation import pipeline as pl
from krsec_rag_lab.generation.llm import LLMResponse
from krsec_rag_lab.integrations.langchain_adapter import BM25CoreRetriever
from krsec_rag_lab.integrations.langgraph_pipeline import (
    NODE_CHECK,
    build_graph,
    check_citation_format,
    run_graph_question,
)

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "run_langgraph.py"
SPEC = importlib.util.spec_from_file_location("run_langgraph", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
run_langgraph = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = run_langgraph
SPEC.loader.exec_module(run_langgraph)

# ------------------------------------------------------------ 합성 색인·가짜 LLM

# A-1·B-2·C-3은 본문이 같아 BM25 점수가 같다(동점은 문서 ID 순). D-4는 한 번 더 나오는 토큰이 있다.
TEXTS = {
    "C-3": "alpha beta shared",
    "A-1": "alpha beta shared",
    "B-2": "alpha beta shared",
    "D-4": "alpha alpha gamma delta",
    "E-5": "epsilon only",
    "F-6": "common zeta",
    "G-7": "common eta",
    "H-8": "common theta",
    "I-9": "common iota",
    "J-10": "common kappa",
    "K-11": "common lambda",
}
QUERIES = {
    "single": "epsilon",
    "tie": "shared",
    "tie_and_more": "alpha",
    "zero_hits": "zzzunknown",
    "many_hits": "common",
}
HEADER = re.compile(r"^\[([^\]\n]+)\]$", re.MULTILINE)


def reply(answer="답", abstain=False, citations=()):
    return json.dumps(
        {"answer": answer, "abstain": abstain, "citations": list(citations)}, ensure_ascii=False
    )


def context_of(messages):
    user = messages[1]["content"]  # 재질의 메시지도 둘째 메시지가 첫 질의의 user다
    return user.split("[문서]\n", 1)[1].split("\n\n[질문]\n", 1)[0]


def cite_first(messages):
    """받은 문맥에 따라 응답한다: 첫 문서 ID를 인용하고, 문맥이 비면 기권한다."""
    ids = HEADER.findall(context_of(messages))
    if not ids:
        return reply(answer="", abstain=True)
    return reply(answer=f"답:{ids[0]}", citations=[ids[0], *ids[:2]])


def cite_outside(messages):
    return reply(answer="문맥 밖 인용", citations=["ZZ-0"])


class FakeLLM:
    """응답을 차례로 돌려주는 호출 가능 객체(LLM 규약). 호출한 메시지를 `calls`에 쌓는다."""

    def __init__(self, replies):
        self.replies = list(replies)
        self.max_prompt_tokens = None
        self.calls = []

    def __call__(self, messages):
        self.calls.append([dict(m) for m in messages])
        content = self.replies[min(len(self.calls), len(self.replies)) - 1]
        if callable(content):
            content = content(messages)
        return LLMResponse(
            content=content,
            prompt_eval_count=100,
            eval_count=10,
            latency_ms=5.0,
            done_reason="stop",
        )


# 이름 -> 새 가짜 LLM을 만드는 함수(코어 경로와 그래프 경로가 각자 새 LLM을 쓴다)
LLMS = {
    "cite_first": lambda: FakeLLM([cite_first]),
    "retry_then_cite": lambda: FakeLLM(["not json", cite_first]),
    "bad_twice": lambda: FakeLLM(["not json", "{}"]),
    "cite_outside": lambda: FakeLLM([cite_outside]),
    "always_abstain": lambda: FakeLLM([reply(answer="", abstain=True)]),
}


@pytest.fixture(scope="module")
def index():
    return pl.GenerationIndex("public", TEXTS, k1=1.2, b=0.75)


def make_question(name, query):
    return data.Question(
        question_id=f"q-{name}",
        query=query,
        query_type="cve_explicit",
        split="test",
        gold=frozenset({"A-1"}),
        unjudged=frozenset(),
        excluded=False,
    )


# ------------------------------------------------------------ 동등성: 코어 경로 대 그래프 경로


@pytest.mark.parametrize("k", [1, 3, 5])
@pytest.mark.parametrize("llm_name", sorted(LLMS))
@pytest.mark.parametrize("query_name", sorted(QUERIES))
def test_graph_matches_core_path(index, query_name, llm_name, k):
    question = make_question(query_name, QUERIES[query_name])
    core_llm, graph_llm = LLMS[llm_name](), LLMS[llm_name]()

    core_row = pl.run_question(question, index, k, core_llm)
    graph_state = build_graph(index, graph_llm).invoke({"question": question.query, "k": k})
    graph_row = run_graph_question(build_graph(index, LLMS[llm_name]()), question, k)

    # 검색 결과의 순서·ID·점수
    core_retrieved = pl.retrieve(index, question.query, k)
    assert [tuple(pair) for pair in graph_state["retrieved"]] == core_retrieved
    # LLM에 넘긴 입력 문자열(재질의 메시지 포함)이 같다
    assert graph_llm.calls == core_llm.calls
    # 출력 계약 필드와 결과 행 전체
    for field in ("abstain", "citations", "answer"):
        assert graph_state[field] == core_row[field]
    assert graph_row == core_row


def test_matrix_covers_ties_and_zero_hits(index):
    tie = pl.retrieve(index, QUERIES["tie"], 5)
    assert [doc_id for doc_id, _ in tie] == ["A-1", "B-2", "C-3"]
    assert len({score for _, score in tie}) == 1
    assert pl.retrieve(index, QUERIES["zero_hits"], 3) == []
    assert len(pl.retrieve(index, QUERIES["many_hits"], 3)) == 3


def test_zero_hits_reach_the_llm_with_the_empty_context_phrase(index):
    llm = LLMS["cite_first"]()
    state = build_graph(index, llm).invoke({"question": QUERIES["zero_hits"], "k": 3})
    assert state["retrieved"] == []
    assert state["context_text"] == ""
    assert pl.EMPTY_CONTEXT in llm.calls[0][1]["content"]
    assert state["abstain"] is True


# ------------------------------------------------------------ 분기와 인용 검사 노드


def test_abstain_ends_without_citation_check(index):
    graph = build_graph(index, LLMS["cite_first"]())
    state = graph.invoke({"question": QUERIES["zero_hits"], "k": 3})
    assert state["abstain"] is True
    assert "citation_check" not in state


def test_answer_goes_through_citation_check_and_keeps_the_result(index):
    state = build_graph(index, LLMS["cite_first"]()).invoke({"question": "alpha", "k": 3})
    assert state["abstain"] is False
    assert state["citation_check"] == {"ok": True, "n_citations": 2, "n_outside_context": 0}
    core = pl.run_question(make_question("x", "alpha"), index, 3, LLMS["cite_first"]())
    assert state["citations"] == core["citations"]
    assert state["answer"] == core["answer"]


def test_citation_check_reports_but_does_not_change_outside_citations(index):
    state = build_graph(index, LLMS["cite_outside"]()).invoke({"question": "alpha", "k": 3})
    # 코어 parse_answer가 문맥 밖 인용을 걸러 둔다. 검사 노드는 걸러진 뒤의 값을 본다
    assert state["citations"] == []
    assert state["n_invalid_citations"] == 1
    assert state["citation_check"]["ok"] is True


@pytest.mark.parametrize(
    ("citations", "expected"),
    [
        (["A-1", "B-2"], {"ok": True, "n_citations": 2, "n_outside_context": 0}),
        ([], {"ok": True, "n_citations": 0, "n_outside_context": 0}),
        (["A-1", "ZZ-0"], {"ok": False, "n_citations": 2, "n_outside_context": 1}),
        (["A-1", "A-1"], {"ok": False, "n_citations": 2, "n_outside_context": 0}),
    ],
)
def test_check_citation_format(citations, expected):
    assert check_citation_format("답", False, citations, {"A-1", "B-2"}) == expected


def test_graph_shape_matches_the_documented_flow(index):
    drawn = build_graph(index, LLMS["cite_first"]()).get_graph()
    assert {"retrieve", "generate", NODE_CHECK} <= set(drawn.nodes)
    edges = {(edge.source, edge.target, edge.conditional) for edge in drawn.edges}
    assert ("retrieve", "generate", False) in edges
    assert ("generate", NODE_CHECK, True) in edges
    assert (NODE_CHECK, "__end__", False) in edges
    assert ("generate", "__end__", True) in edges


# ------------------------------------------------------------ 실제 공개 질의셋과 코퍼스(커밋된 입력, 모델 없음)


def test_graph_matches_core_on_committed_public_questions():
    index = pl.build_index("public", ROOT)
    questions = pl.expected_questions("public", ROOT)
    picked = pl.sample_questions(questions, 12)
    assert {q.query_type for q in picked} >= {"cve_explicit", "product_symptom", "no_answer"}
    for k in (1, 3, 5):
        for question in picked:
            core_row = pl.run_question(question, index, k, LLMS["cite_first"]())
            graph_row = run_graph_question(build_graph(index, LLMS["cite_first"]()), question, k)
            assert graph_row == core_row


# ------------------------------------------------------------ BaseRetriever 어댑터


@pytest.mark.parametrize("k", [1, 3, 5])
@pytest.mark.parametrize("query_name", sorted(QUERIES))
def test_retriever_wraps_core_retrieve(index, query_name, k):
    query = QUERIES[query_name]
    docs = BM25CoreRetriever(index=index, k=k).invoke(query)
    core = pl.retrieve(index, query, k)
    assert [doc.metadata["doc_id"] for doc in docs] == [doc_id for doc_id, _ in core]
    assert [doc.metadata["score"] for doc in docs] == [score for _, score in core]
    assert [doc.metadata["rank"] for doc in docs] == list(range(1, len(core) + 1))
    assert [doc.page_content for doc in docs] == [index.text(doc_id) for doc_id, _ in core]
    assert [doc.id for doc in docs] == [doc_id for doc_id, _ in core]


def test_retriever_keeps_the_core_tie_order_and_empty_result(index):
    assert [d.metadata["doc_id"] for d in BM25CoreRetriever(index=index, k=5).invoke("shared")] == [
        "A-1",
        "B-2",
        "C-3",
    ]
    assert BM25CoreRetriever(index=index, k=3).invoke("zzzunknown") == []


def test_retriever_and_graph_see_the_same_documents(index):
    docs = BM25CoreRetriever(index=index, k=3).invoke("common")
    state = build_graph(index, LLMS["cite_first"]()).invoke({"question": "common", "k": 3})
    assert [d.metadata["doc_id"] for d in docs] == [doc_id for doc_id, _ in state["retrieved"]]


def test_retriever_rejects_non_positive_k(index):
    with pytest.raises(ValueError, match="k must be positive"):
        BM25CoreRetriever(index=index, k=0).invoke("alpha")


def test_retriever_async_invoke(index):
    docs = asyncio.run(BM25CoreRetriever(index=index, k=2).ainvoke("shared"))
    assert [d.metadata["doc_id"] for d in docs] == ["A-1", "B-2"]


# ------------------------------------------------------------ 제약: import 위치


def test_frameworks_are_imported_only_inside_integrations():
    pattern = re.compile(r"^\s*(?:from|import)\s+(?:langchain|langgraph)", re.MULTILINE)
    src = ROOT / "src" / "krsec_rag_lab"
    offenders = [
        str(path.relative_to(ROOT))
        for path in src.rglob("*.py")
        if "integrations" not in path.relative_to(src).parts and pattern.search(path.read_text())
    ]
    assert offenders == []
    assert not pattern.search((src / "integrations" / "__init__.py").read_text())


# ------------------------------------------------------------ CLI 보조 함수


def stored_row(question_id, **overrides):
    row = {
        "question_id": question_id,
        "split": "test",
        "k": 3,
        "abstain": False,
        "citations": ["A-1"],
        "answer": "답",
        "retrieved": ["A-1"],
        "context_sha256": "h",
    }
    row.update(overrides)
    return row


def test_pick_baseline_rows_takes_test_rows_in_file_order():
    rows = [
        stored_row("d1", split="dev"),
        stored_row("t1"),
        stored_row("t2"),
        stored_row("d2", split="dev"),
        stored_row("t3"),
    ]
    assert [r["question_id"] for r in run_langgraph.pick_baseline_rows(rows, 2)] == ["t1", "t2"]
    with pytest.raises(ValueError, match="only 3 test rows"):
        run_langgraph.pick_baseline_rows(rows, 4)
    with pytest.raises(ValueError, match="positive"):
        run_langgraph.pick_baseline_rows(rows, 0)


@pytest.mark.parametrize(
    ("field", "value"),
    [("abstain", True), ("citations", ["B-2"]), ("citations", []), ("answer", "다른 답")],
)
def test_compare_rows_flags_each_field(field, value):
    stored = stored_row("t1")
    graph_row = {**stored, field: value}
    result = run_langgraph.compare_rows(graph_row, stored)
    assert result["match"] is False
    assert [name for name, same in result["fields"].items() if not same] == [field]


def test_compare_rows_match_and_context_check():
    stored = stored_row("t1")
    assert run_langgraph.compare_rows(dict(stored), stored) == {
        "question_id": "t1",
        "match": True,
        "fields": {"abstain": True, "citations": True, "answer": True},
        "same_context": True,
    }
    other_context = run_langgraph.compare_rows({**stored, "context_sha256": "x"}, stored)
    assert other_context["match"] is True
    assert other_context["same_context"] is False


@pytest.fixture
def committed_manifest():
    return run_langgraph.load_manifest()


def fake_model_info(manifest, **overrides):
    model = {key: manifest["model"][key] for key in ("name", "digest", "weights_sha256")}
    model.update(overrides)
    return lambda name, host: model


def test_committed_run_id_is_reproduced_by_the_current_code(committed_manifest, monkeypatch):
    monkeypatch.setattr(llm_module, "model_info", fake_model_info(committed_manifest))
    llm = llm_module.OllamaLLM(model=committed_manifest["model"]["name"])
    identity = run_langgraph.check_run_identity(llm, committed_manifest, llm.host)
    assert identity["run_id"] == committed_manifest["run_id"]


@pytest.mark.parametrize(
    "override", [{"digest": "0" * 64}, {"weights_sha256": "1" * 64}], ids=["digest", "weights"]
)
def test_run_identity_rejects_another_model_build(committed_manifest, monkeypatch, override):
    monkeypatch.setattr(llm_module, "model_info", fake_model_info(committed_manifest, **override))
    llm = llm_module.OllamaLLM(model=committed_manifest["model"]["name"])
    with pytest.raises(pl.GateFailure, match="run_id"):
        run_langgraph.check_run_identity(llm, committed_manifest, llm.host)


def test_run_identity_rejects_changed_request_options(committed_manifest, monkeypatch):
    monkeypatch.setattr(llm_module, "model_info", fake_model_info(committed_manifest))
    llm = llm_module.OllamaLLM(
        model=committed_manifest["model"]["name"], options={**llm_module.OPTIONS, "seed": 7}
    )
    with pytest.raises(pl.GateFailure, match="run_id"):
        run_langgraph.check_run_identity(llm, committed_manifest, llm.host)


# ------------------------------------------------------------ CLI 전체 경로(가짜 LLM)


class FakeOllama(llm_module.OllamaLLM):
    """실제 `OllamaLLM`의 요청 본문·옵션을 쓰되 HTTP 대신 `responder(messages) -> 응답 JSON`을 부른다."""

    responder = None

    def __call__(self, messages):
        return LLMResponse(
            content=type(self).responder(messages),
            prompt_eval_count=100,
            eval_count=10,
            latency_ms=5.0,
            done_reason="stop",
        )


def patch_ollama(monkeypatch, responder):
    fake = type("BoundFakeOllama", (FakeOllama,), {"responder": staticmethod(responder)})
    monkeypatch.setattr(llm_module, "OllamaLLM", fake)


def replaying_responder(stored_by_query):
    """질문에 대응하는 저장 행의 답을 그대로 돌려준다(검색·문맥이 저장본과 같을 때만 쓸모 있다)."""

    def respond(messages):
        question = messages[1]["content"].rsplit("[질문]\n", 1)[1]
        row = stored_by_query[question]
        return reply(row["answer"], row["abstain"], row["citations"])

    return respond


def test_compare_replaying_committed_answers_matches_all_ten(
    committed_manifest, monkeypatch, capsys
):
    stored_rows = pl.read_jsonl_rows(ROOT / run_langgraph.BASELINE_FILE)
    queries = {q.question_id: q.query for q in pl.expected_questions("public", ROOT)}
    stored_by_query = {queries[row["question_id"]]: row for row in stored_rows}
    monkeypatch.setattr(llm_module, "model_info", fake_model_info(committed_manifest))
    patch_ollama(monkeypatch, replaying_responder(stored_by_query))

    assert run_langgraph.main(["--compare", "--n", "10"]) == 0
    report = json.loads(capsys.readouterr().out)
    picked = [r["question_id"] for r in stored_rows if r["split"] == "test"][:10]
    assert report["question_ids"] == picked
    assert (report["n_compared"], report["n_match"], report["mismatched"]) == (10, 10, [])
    assert all(item["same_context"] for item in report["results"])
    assert report["identity"]["run_id"] == committed_manifest["run_id"]


def test_compare_reports_mismatch_and_exits_one(committed_manifest, monkeypatch, capsys):
    monkeypatch.setattr(llm_module, "model_info", fake_model_info(committed_manifest))
    patch_ollama(monkeypatch, lambda messages: reply(answer="항상 같은 답", citations=[]))

    assert run_langgraph.main(["--compare", "--n", "3"]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["n_compared"] == 3
    assert report["n_match"] == 0
    assert report["mismatched"] == report["question_ids"]


def test_split_mode_prints_core_equal_rows(monkeypatch, capsys):
    monkeypatch.setattr(llm_module, "OllamaLLM", lambda **kwargs: LLMS["cite_first"]())
    assert run_langgraph.main(["--split", "test", "--limit", "3", "--k", "3"]) == 0
    printed = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    index = pl.build_index("public", ROOT)
    questions = [q for q in pl.expected_questions("public", ROOT) if q.split == "test"][:3]
    expected = [pl.run_question(q, index, 3, LLMS["cite_first"]()) for q in questions]
    assert printed == expected


def test_single_question_mode_prints_the_final_state(monkeypatch, capsys):
    monkeypatch.setattr(llm_module, "OllamaLLM", lambda **kwargs: LLMS["cite_first"]())
    assert run_langgraph.main(["--question", "CVE-2026-70283 설명", "--k", "1"]) == 0
    state = json.loads(capsys.readouterr().out)
    assert state["k"] == 1
    assert "context_text" not in state
    assert state["status"] == "ok"


@pytest.mark.parametrize(
    "argv",
    [
        ["--limit", "3", "--question", "x"],
        ["--split", "test", "--limit", "0"],
        ["--k", "2", "--compare"],
    ],
)
def test_cli_rejects_bad_arguments(argv):
    with pytest.raises(SystemExit):
        run_langgraph.main(argv)
