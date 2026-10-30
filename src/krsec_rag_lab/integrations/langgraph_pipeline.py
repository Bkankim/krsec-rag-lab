"""LangGraph 상태 그래프 - 검색 노드 -> 생성 노드 -> (기권이면 종료, 아니면 인용 검사 노드).

모든 노드는 코어의 공개 함수(`retrieve`, `build_context`, `generate`, `parse_answer`)를 그대로 부른다. LLM은 코어와
같은 방식으로(호출 가능 객체 `llm(messages) -> LLMResponse`) 넘기고, 그래프는 점수·문맥·프롬프트·재질의 규칙을
새로 만들지 않는다. 인용 검사 노드는 상태를 바꾸지 않고 `citation_check`만 덧붙이므로 코어와 출력이 같다.

    retrieve --> generate --(abstain=false)--> check_citations --> END
                          \\--(abstain=true)--> END
"""

import json
from typing import Any, TypedDict

from langgraph.graph import END, START, StateGraph

from krsec_rag_lab.baselines import data
from krsec_rag_lab.generation.llm import LLM
from krsec_rag_lab.generation.pipeline import (
    STATUS_OK,
    GenerationIndex,
    build_context,
    generate,
    parse_answer,
    retrieve,
    sha256_text,
)

NODE_RETRIEVE = "retrieve"
NODE_GENERATE = "generate"
NODE_CHECK = "check_citations"


class GraphState(TypedDict, total=False):
    """입력은 `question`·`k`. 나머지는 노드가 채운다. 검색 점수는 `[문서 ID, 점수]` 목록이다."""

    question: str
    k: int
    retrieved: list[tuple[str, float]]
    context_text: str
    truncated: list[str]
    answer: str
    abstain: bool
    citations: list[str]
    n_invalid_citations: int
    status: str
    n_attempts: int
    prompt_tokens: int | None
    completion_tokens: int | None
    latency_ms: float | None
    citation_check: dict[str, Any]


def route_after_generate(state: GraphState) -> str:
    """생성 결과의 `abstain`으로 분기한다: 기권이면 종료, 아니면 인용 검사."""
    return END if state["abstain"] else NODE_CHECK


def check_citation_format(answer: str, abstain: bool, citations: list[str], allowed_ids) -> dict:
    """출력 계약을 코어 `parse_answer`로 다시 통과시켜 인용이 문맥 ID 안의 중복 없는 문자열인지 확인한다.

    gold 여부는 보지 않는다. 결과를 고치지 않고 검사 결과만 돌려준다.
    """
    payload = json.dumps(
        {"answer": answer, "abstain": abstain, "citations": citations}, ensure_ascii=False
    )
    _, _, valid, invalid, status = parse_answer(payload, allowed_ids)
    return {
        "ok": status == STATUS_OK and not invalid and valid == citations,
        "n_citations": len(citations),
        "n_outside_context": len(invalid),
    }


def build_graph(index: GenerationIndex, llm: LLM, track: str | None = None):
    """색인과 LLM을 닫아 둔 컴파일된 그래프. `graph.invoke({"question": ..., "k": ...})`로 돌린다."""
    track = track or index.track

    def retrieve_node(state: GraphState) -> dict:
        retrieved = retrieve(index, state["question"], state["k"])
        context_text, truncated = build_context(
            track, [doc_id for doc_id, _ in retrieved], index.text
        )
        return {"retrieved": retrieved, "context_text": context_text, "truncated": truncated}

    def generate_node(state: GraphState) -> dict:
        allowed = {doc_id for doc_id, _ in state["retrieved"]}
        result = generate(state["question"], state["context_text"], allowed, llm)
        return {
            "answer": result.answer,
            "abstain": result.abstain,
            "citations": result.citations,
            "n_invalid_citations": result.n_invalid_citations,
            "status": result.status,
            "n_attempts": result.n_attempts,
            "prompt_tokens": result.prompt_tokens,
            "completion_tokens": result.completion_tokens,
            "latency_ms": result.latency_ms,
        }

    def check_node(state: GraphState) -> dict:
        allowed = {doc_id for doc_id, _ in state["retrieved"]}
        return {
            "citation_check": check_citation_format(
                state["answer"], state["abstain"], state["citations"], allowed
            )
        }

    graph = StateGraph(GraphState)
    graph.add_node(NODE_RETRIEVE, retrieve_node)
    graph.add_node(NODE_GENERATE, generate_node)
    graph.add_node(NODE_CHECK, check_node)
    graph.add_edge(START, NODE_RETRIEVE)
    graph.add_edge(NODE_RETRIEVE, NODE_GENERATE)
    graph.add_conditional_edges(
        NODE_GENERATE, route_after_generate, {NODE_CHECK: NODE_CHECK, END: END}
    )
    graph.add_edge(NODE_CHECK, END)
    return graph.compile()


def state_to_row(state: GraphState, question: data.Question) -> dict:
    """그래프의 최종 상태를 코어 `run_question`과 같은 키의 결과 행으로 바꾼다(`answer` 포함)."""
    retrieved = [doc_id for doc_id, _ in state["retrieved"]]
    latency = state["latency_ms"]
    return {
        "question_id": question.question_id,
        "split": question.split,
        "query_type": question.query_type,
        "k": state["k"],
        "status": state["status"],
        "abstain": state["abstain"],
        "citations": state["citations"],
        "n_invalid_citations": state["n_invalid_citations"],
        "retrieved": retrieved,
        "truncated": state["truncated"],
        "n_retrieved": len(retrieved),
        "prompt_tokens": state["prompt_tokens"],
        "completion_tokens": state["completion_tokens"],
        "latency_ms": None if latency is None else round(latency, 3),
        "context_sha256": sha256_text(state["context_text"]),
        "n_attempts": state["n_attempts"],
        "context_chars": len(state["context_text"]),
        "answer": state["answer"],
    }


def run_graph_question(graph, question: data.Question, k: int) -> dict:
    """질문 하나를 그래프로 돌려 코어 `run_question`과 같은 형태의 행을 돌려준다."""
    return state_to_row(graph.invoke({"question": question.query, "k": k}), question)
