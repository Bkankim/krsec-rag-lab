"""LangGraph 그래프로 질문을 돌리는 CLI - 코어 파이프라인을 감싼 그래프(검색 -> 생성 -> 기권 분기).

    uv sync --locked --group langchain            # langchain-core·langgraph (CI의 dev 그룹에는 없다)
    ollama serve                                  # 별도 프로세스로 띄워 둔다(이 스크립트는 서버를 켜지 않는다)
    uv run --no-sync python scripts/run_langgraph.py --question "..." --k 3
    uv run --no-sync python scripts/run_langgraph.py --split test --limit 10 --k 3
    uv run --no-sync python scripts/run_langgraph.py --compare --n 10    # 커밋된 public_k3.jsonl과 대조

공개(NVD) 트랙만 돌린다. KISA 트랙은 그래프로 돌리지 않는다(답변·문맥이 공지 본문을 옮길 수 있다).
`--compare`는 #65 manifest의 모델 이름·digest·옵션·프롬프트가 지금 실행과 같은지(`run_id`) 확인한 뒤,
커밋된 결과 파일에서 test 질문을 파일 순서로 앞 N개 골라 그래프 결과와 abstain·citations·answer를 정확 일치로 비교한다.
결과는 표준 출력에만 쓴다(커밋 산출물을 만들지 않는다). 불일치가 있으면 exit 1이다.
"""

import argparse
import json
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

from krsec_rag_lab.generation import llm as llm_module
from krsec_rag_lab.generation import pipeline

ROOT = Path(__file__).resolve().parents[1]
TRACK = "public"
BASELINE_FILE = pipeline.RESULTS_DIR / "public_k3.jsonl"
COMPARE_FIELDS = ("abstain", "citations", "answer")
MISSING_GROUP = "langchain extras are not installed; run: uv sync --locked --group langchain"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--question", help="질문 문자열 하나")
    mode.add_argument(
        "--split", choices=("dev", "test", "all"), help="공개 질의셋을 그래프로 돌린다"
    )
    mode.add_argument(
        "--compare", action="store_true", help="커밋된 결과와 대조(test 앞 N개, 파일 순서)"
    )
    parser.add_argument("--k", type=int, default=3, choices=pipeline.KS)
    parser.add_argument("--limit", type=int, help="--split에서 앞 N개만(질의 파일 순서)")
    parser.add_argument("--n", type=int, default=10, help="--compare에서 비교할 질문 수")
    parser.add_argument("--baseline", type=Path, default=ROOT / BASELINE_FILE)
    parser.add_argument("--host", default=llm_module.DEFAULT_HOST)
    return parser


def load_manifest() -> dict:
    return json.loads((ROOT / pipeline.RESULTS_DIR / "manifest.json").read_text(encoding="utf-8"))


def pick_baseline_rows(rows: Sequence[Mapping], n: int) -> list[Mapping]:
    """저장 결과에서 test 질문을 파일 순서로 앞 n개 고른다."""
    if n < 1:
        raise ValueError(f"n must be positive, got {n}")
    picked = [row for row in rows if row["split"] == "test"][:n]
    if len(picked) < n:
        raise ValueError(f"baseline has only {len(picked)} test rows, need {n}")
    return picked


def compare_rows(graph_row: Mapping, stored: Mapping) -> dict:
    """한 질문의 비교: 필드별 정확 일치. 문맥 해시·검색 목록은 같은 입력이었는지 보는 참고 칸이다."""
    fields = {name: graph_row[name] == stored[name] for name in COMPARE_FIELDS}
    context_same = (
        graph_row["context_sha256"] == stored["context_sha256"]
        and graph_row["retrieved"] == stored["retrieved"]
    )
    return {
        "question_id": stored["question_id"],
        "match": all(fields.values()),
        "fields": fields,
        "same_context": context_same,
    }


def check_run_identity(llm: llm_module.OllamaLLM, manifest: Mapping, host: str) -> dict:
    """지금 실행 설정(모델 digest·옵션·프롬프트)의 run_id가 커밋된 manifest의 것과 같은지 확인한다."""
    if pipeline.prompt_fingerprint() != manifest["prompt"]["sha256"]:
        raise pipeline.GateFailure("prompt sha256 differs from the committed manifest")
    model = llm_module.model_info(llm.model, host)
    run_id = pipeline.make_run_id(pipeline.run_config(model, llm, ROOT))
    if run_id != manifest["run_id"]:
        raise pipeline.GateFailure(
            f"run_id {run_id} differs from the committed manifest {manifest['run_id']} "
            "(model digest, request options or prompt changed)"
        )
    return {"run_id": run_id, "model": model["name"], "digest": model["digest"]}


def baseline_name(path: Path) -> str:
    """결과에 적는 기준 파일 이름: 리포 안이면 상대 경로, 밖이면 파일명(절대 경로를 남기지 않는다)."""
    try:
        return str(path.resolve().relative_to(ROOT))
    except ValueError:
        return path.name


def run_compare(graph_module, args: argparse.Namespace) -> int:
    manifest = load_manifest()
    llm = llm_module.OllamaLLM(model=manifest["model"]["name"], host=args.host)
    identity = check_run_identity(llm, manifest, args.host)
    if not args.baseline.is_file():
        raise ValueError(f"baseline file not found: {baseline_name(args.baseline)}")
    stored_rows = pipeline.read_jsonl_rows(args.baseline)
    picked = pick_baseline_rows(stored_rows, args.n)
    questions = {q.question_id: q for q in pipeline.expected_questions(TRACK, ROOT)}
    unknown = [row["question_id"] for row in picked if row["question_id"] not in questions]
    if unknown:
        raise ValueError(f"baseline questions not in the public question set: {unknown}")
    index = pipeline.build_index(TRACK, ROOT)
    graph = graph_module.build_graph(index, llm)
    results = []
    for stored in picked:
        row = graph_module.run_graph_question(graph, questions[stored["question_id"]], stored["k"])
        results.append(compare_rows(row, stored))
        print(f"{stored['question_id']} match={results[-1]['match']}", file=sys.stderr, flush=True)
    mismatched = [item["question_id"] for item in results if not item["match"]]
    print(
        json.dumps(
            {
                "identity": identity,
                "baseline": baseline_name(args.baseline),
                "k": picked[0]["k"],
                "compared_fields": list(COMPARE_FIELDS),
                "question_ids": [item["question_id"] for item in results],
                "n_compared": len(results),
                "n_match": len(results) - len(mismatched),
                "mismatched": mismatched,
                "results": results,
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 1 if mismatched else 0


def run_queries(graph_module, args: argparse.Namespace) -> int:
    llm = llm_module.OllamaLLM(host=args.host)
    index = pipeline.build_index(TRACK, ROOT)
    graph = graph_module.build_graph(index, llm)
    if args.question is not None:
        state = graph_module.invoke_graph(graph, args.question, args.k)
        state = {key: value for key, value in state.items() if key != "context_text"}
        print(json.dumps(state, ensure_ascii=False, indent=2))
        return 0
    questions = pipeline.expected_questions(TRACK, ROOT)
    if args.split != "all":
        questions = [q for q in questions if q.split == args.split]
    if args.limit is not None:
        questions = questions[: args.limit]
    for question in questions:
        row = graph_module.run_graph_question(graph, question, args.k)
        print(json.dumps(row, ensure_ascii=False), flush=True)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.limit is not None and (args.limit < 1 or args.split is None):
        parser.error("--limit is a positive integer and needs --split")
    try:
        from krsec_rag_lab.integrations import langgraph_pipeline as graph_module
    except ModuleNotFoundError as error:
        if (error.name or "").split(".")[0] not in ("langgraph", "langchain_core"):
            raise
        print(f"error: {MISSING_GROUP}", file=sys.stderr)
        return 1
    try:
        if args.compare:
            return run_compare(graph_module, args)
        return run_queries(graph_module, args)
    except (llm_module.LLMError, pipeline.GateFailure, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
