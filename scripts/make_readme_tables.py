"""README 결과 표를 원시 결과에서 다시 계산해 만들고, README·metrics.json과 맞는지 검증한다.

    uv run python scripts/make_readme_tables.py            # 문서의 생성 구간 마커 사이를 다시 쓴다
    uv run python scripts/make_readme_tables.py --check    # 쓰지 않고 검증만 한다(일치 0, 아니면 1)

표의 숫자는 `results/baselines/manifest.json`이 가리키는 질문별 원시 결과(jsonl)와 `eval/**` 정답에서
`src/krsec_rag_lab/metrics.py`와 규약 v2 채점(condensed list)으로 다시 계산한 값이다. 이 값이
`results/baselines/metrics.json`과 모두 같고(abs 1e-9), README의 생성 구간이 이 값으로 만든 표와
같을 때만 검증이 통과한다. 필수 파일 누락, 빈 입력, 질문 ID 누락·중복·초과, 입력 해시 불일치는
비교하기 전에 종료 코드 1로 멈춘다. 결과 값은 어디에도 고치지 않는다(쓰는 곳은 README 생성 구간뿐이다).

M3 실험(`results/experiments/` 디렉터리가 있거나 README에 M3 구간 마커가 있을 때)은 `results/experiments/<exp>/`의 질문별 원시 결과·manifest와
질의셋 라벨에서 하네스(`krsec_rag_lab.experiments`)의 비교 함수로 `metrics.json`·`comparison.json`을 다시 계산해
저장된 파일과 abs 1e-9로 대조하고, 그 값으로 README의 M3 판정 구간, `docs/experiments/summary.md`의 표 구간,
`docs/release-v0.2.md`의 판정 구간을 만든다. 베이스라인 표 검증은 그대로이고 M3 구간은 마커 쌍이 따로다.
M3 재계산은 NVD 코퍼스 파일(`fixtures/nvd/cves.jsonl`)이 없는 릴리스 asset 사본에서도 돌도록, 그 파일이 없으면
manifest에 적힌 해시를 쓰되 기준선 manifest의 같은 해시와 대조한다.

`--summary`·`--note`로 M3 요약과 v0.2 노트 경로를 따로 줄 수 있다(문서가 없는 asset 사본을 `--root`로 줄 때).
M3 검증은 `results/experiments/`가 있거나 README에 M3 구간 마커가 있으면 돈다(데이터가 없으면 실패한다).

M4(`results/m4/`가 있거나 README에 M4 구간 마커가 있을 때, 데이터가 없으면 실패한다)는
`results/m4/collection/report.json`, `results/m4/idempotency/report.json`, `fixtures/kisa_full/{manifest.json,metadata.jsonl}`에서
README의 M4 구간과 `docs/release-v0.3.md`의 M4 구간(과 M3 구간)을 만든다. 보고서와 manifest가 서로 어긋나면(문서 수,
결과별 건수, 발견 계측, 메타데이터 ID) 문서와 비교하기 전에 불일치로 보고한다. `--note-v03`으로 v0.3 노트 경로를 따로 줄 수 있다.
M4 수치는 어디에도 고치지 않고 README와 v0.3 노트의 생성 구간만 쓴다. 본문 유출 점검(KISA 캐시 필요)은 이 스크립트의 일이 아니다.

M5(`results/m5/`가 있거나 README에 M5 구간 마커가 있을 때, 데이터가 없으면 실패한다)는
`results/m5/generation/{manifest.json,topk.json,public_k{1,3,5}.jsonl,kisa_k{1,3,5}.jsonl}`와
`results/m5/judgments/{manifest.json,summary.json,public.jsonl,kisa.jsonl}`를 저장본 검사(생성 쪽 `pipeline.check_stored`,
판정 쪽 `judge_gen.check_stored`: 행 키·집합, 해시, topk.json·summary.json 재계산 대조)로 먼저 확인하고, 그 값으로 README의 M5 구간과
`docs/release-v1.0.md`의 M5 구간(과 M3·M4 구간)을 만든다. `--note-v10`으로 v1.0 노트 경로를 따로 줄 수 있다.
M5 수치는 어디에도 고치지 않고 README와 v1.0 노트의 생성 구간만 쓴다. 모델·Ollama·외부 API·KISA 캐시를 쓰지 않는다.

`--root`로 리포 루트를 바꿀 수 있다(릴리스 asset 사본 검증용, scripts/check_release.py). README는 기본으로
`<root>/README.md`이고 `--readme`로 따로 정할 수 있다.
"""

import argparse
import json
import math
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path, PurePosixPath

from krsec_rag_lab.baselines import data, scoring
from krsec_rag_lab.baselines.runner import RETRIEVERS
from krsec_rag_lab.experiments import ExperimentError, harness
from krsec_rag_lab.experiments import compare as cmp
from krsec_rag_lab.generation import judge_gen, pipeline

ROOT = Path(__file__).resolve().parents[1]
RESULTS_DIR = Path("results/baselines")
BEGIN = "<!-- BEGIN GENERATED TABLES (scripts/make_readme_tables.py) -->"
END = "<!-- END GENERATED TABLES (scripts/make_readme_tables.py) -->"
ATOL = 1e-9
TRACK_TITLES = {
    "public": "공개 트랙 (NVD fixture, 문서 = CVE 레코드)",
    "kisa": "KISA 트랙 (문서 = nttId, 로컬 캐시로 만든 결과)",
}
NOTE = (
    "이 구간은 `scripts/make_readme_tables.py`가 질문별 원시 결과(`results/baselines/`)에서 다시 계산해 쓴다. "
    "손으로 고치지 않는다. 검증: `uv run python scripts/make_readme_tables.py --check`. "
    "macro는 정답이 있는 유형의 단순 평균이다. † 표시는 n_scored < 10이라 우열 판정 없이 관찰로만 읽는다."
)

# M3 실험. 하네스에는 실험 이름 목록이 없으므로 릴리스가 담는 실험은 여기서 정한다(판정 표의 행 순서).
EXPERIMENTS = ("hybrid", "rerank", "chunking", "crossling", "embedding")
EXPERIMENTS_DIR = Path("results/experiments")
SUMMARY_PATH = Path("docs/experiments/summary.md")
NOTE_V02_PATH = Path("docs/release-v0.2.md")
NOTE_V03_PATH = Path("docs/release-v0.3.md")
NOTE_V10_PATH = Path("docs/release-v1.0.md")
README_M3 = (
    "<!-- BEGIN M3 TABLES (scripts/make_readme_tables.py) -->",
    "<!-- END M3 TABLES (scripts/make_readme_tables.py) -->",
)
SUMMARY_RANGE = (
    "<!-- BEGIN SUMMARY TABLES (scripts/make_readme_tables.py) -->",
    "<!-- END SUMMARY TABLES (scripts/make_readme_tables.py) -->",
)
NOTE_RANGE = (
    "<!-- BEGIN M3 RESULTS (scripts/make_readme_tables.py) -->",
    "<!-- END M3 RESULTS (scripts/make_readme_tables.py) -->",
)
README_M4 = (
    "<!-- BEGIN M4 TABLES (scripts/make_readme_tables.py) -->",
    "<!-- END M4 TABLES (scripts/make_readme_tables.py) -->",
)
NOTE_M4_RANGE = (
    "<!-- BEGIN M4 RESULTS (scripts/make_readme_tables.py) -->",
    "<!-- END M4 RESULTS (scripts/make_readme_tables.py) -->",
)
README_M5 = (
    "<!-- BEGIN M5 TABLES (scripts/make_readme_tables.py) -->",
    "<!-- END M5 TABLES (scripts/make_readme_tables.py) -->",
)
NOTE_M5_RANGE = (
    "<!-- BEGIN M5 RESULTS (scripts/make_readme_tables.py) -->",
    "<!-- END M5 RESULTS (scripts/make_readme_tables.py) -->",
)
M5_DIR = Path("results/m5")
M5_GENERATION = M5_DIR / "generation"
M5_JUDGMENTS = M5_DIR / "judgments"
# 고정 목록: 하나라도 없으면 실패다(docs/m5-generation.md, docs/m5-generation-eval.md의 산출물)
M5_FILES = (
    M5_GENERATION / "manifest.json",
    M5_GENERATION / "topk.json",
    *[M5_GENERATION / f"{track}_k{k}.jsonl" for track in ("public", "kisa") for k in (1, 3, 5)],
    M5_JUDGMENTS / "manifest.json",
    M5_JUDGMENTS / "summary.json",
    M5_JUDGMENTS / "public.jsonl",
    M5_JUDGMENTS / "kisa.jsonl",
)
M5_PROBLEM = (
    "results/m5:"  # M5 저장본 검사 실패 항목의 접두어(쓰기 모드는 이때 문서를 건드리지 않는다)
)
M5_TRACK_TITLES = {"public": "공개 트랙 (NVD)", "kisa": "KISA 트랙"}
M5_NOTE = (
    "이 구간은 `scripts/make_readme_tables.py`가 `results/m5/generation/`과 `results/m5/judgments/`의 저장본"
    "(질문별 행, `topk.json`, `summary.json`)을 다시 검사하고 질의셋 라벨과 판정 행에서 지표를 다시 계산해 만든다. "
    "손으로 고치지 않는다. 검증: `uv run python scripts/make_readme_tables.py --check`. 세 축(faithfulness, 정답성, "
    "답 없음 처리)은 따로 보고하고 하나의 점수로 합치지 않는다. 분할 `all`은 dev와 test의 합이다. 판정은 두 모델의 "
    "교차 판정이고 사람 검수가 아니며, KISA 생성 답변 원문은 어디에도 없다."
)
M4_COLLECTION = Path("results/m4/collection/report.json")
M4_IDEMPOTENCY = Path("results/m4/idempotency/report.json")
M4_MANIFEST = Path("fixtures/kisa_full/manifest.json")
M4_METADATA = Path("fixtures/kisa_full/metadata.jsonl")
M4_DIR = Path("results/m4")
M4_PROBLEM = "results/m4:"  # M4 입력 데이터끼리 어긋난 항목의 접두어(쓰기 모드는 이때 문서를 건드리지 않는다)
# 보고서 키 표: docs/m4-collection.md, docs/m4-idempotency.md
COLLECTION_KEYS = (
    "schema_version",
    "parser_version",
    "discovery_complete",
    "complete",
    "discovered_ids",
    "list_pages",
    "list_pages_with_rows",
    "list_rows",
    "displayed_total",
    "displayed_total_gap",
    "rss_ids",
    "rss_only_ids",
    "rss_error",
    "discovery_error",
    "list_duplicate_in_page",
    "list_duplicate_across_pages",
    "list_duplicate_ids",
    "list_conflict_ids",
    "detail_ok",
    "detail_failed",
    "parse_failed",
    "failed_ids",
    "detail_pending",
    "missing_ids",
    "content_duplicate_group_count",
    "content_duplicate_doc_count",
    "content_duplicate_groups",
    "fixed_expected",
    "fixed_present",
    "fixed_missing_ids",
    "fixed_hash_match",
    "fixed_hash_mismatch_ids",
    "new_since_freeze",
    "rediscovery_pages",
    "rediscovery_complete",
    "aborted",
    "resumed",
    "retry_failed",
    "requests",
    "elapsed_seconds",
)
IDEMPOTENCY_KEYS = (
    "schema_version",
    "passed",
    "failed_step",
    "error",
    "started_at",
    "finished_at",
    "elapsed_seconds",
    "k",
    "seed",
    "tolerances",
    "corpus",
    "model",
    "qdrant",
    "runtime",
    "environment",
    "steps",
)
# manifest.discovery의 키는 보고서의 같은 이름 키와 같은 값이다(manifest의 `error`는 보고서의 `discovery_error`).
DISCOVERY_KEYS = (
    "list_pages",
    "list_pages_with_rows",
    "list_rows",
    "displayed_total",
    "list_duplicate_in_page",
    "list_duplicate_across_pages",
    "list_duplicate_ids",
    "list_conflict_ids",
    "rss_ids",
    "rss_only_ids",
    "rss_error",
)
M4_NOTE = (
    "이 구간은 `scripts/make_readme_tables.py`가 `results/m4/collection/report.json`, "
    "`results/m4/idempotency/report.json`, `fixtures/kisa_full/manifest.json`, `fixtures/kisa_full/metadata.jsonl`에서 "
    "다시 만들어 쓴다. 손으로 고치지 않는다. 검증: `uv run python scripts/make_readme_tables.py --check`. "
    "보고서와 manifest의 건수가 서로 맞는지 대조한 뒤에 표를 만든다."
)
M3_NOTE = (
    "이 구간은 `scripts/make_readme_tables.py`가 `results/experiments/`의 질문별 원시 결과와 질의셋 라벨에서 "
    "하네스의 비교 함수(`krsec_rag_lab.experiments.compare`)로 다시 계산해 쓴다. 손으로 고치지 않는다. "
    "검증: `uv run python scripts/make_readme_tables.py --check`. 지표는 test macro nDCG@10(condensed list, "
    "정답이 있는 유형의 단순 평균)이고 delta = 실험 - 기준이다. 95% 구간은 test 질문을 유형별로 층화 복원추출한 "
    "paired bootstrap(10000회, 시드 20261029)의 2.5/97.5 백분위이며, delta > 0 이고 구간 하한 > 0 일 때만 "
    "`hypothesis-confirmed`다."
)


class CheckError(Exception):
    """필수 파일 누락, 빈 입력, 질문 ID 오류처럼 비교 전에 멈춰야 하는 입력 문제."""


def _fmt(value: float | None, digits: int = 4) -> str:
    return "-" if value is None else f"{value:.{digits}f}"


def _read_json(path: Path, label: str) -> dict:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise CheckError(f"missing required file: {label}") from None
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CheckError(f"unreadable json: {label} ({type(error).__name__})") from None
    if not isinstance(payload, dict) or not payload:
        raise CheckError(f"empty or non-object json: {label}")
    return payload


def _read_jsonl(path: Path, label: str) -> list[dict]:
    try:
        rows = data.read_jsonl(path)
    except FileNotFoundError:
        raise CheckError(f"missing required file: {label}") from None
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CheckError(f"unreadable jsonl: {label} ({type(error).__name__})") from None
    if not rows:
        raise CheckError(f"empty input: {label}")
    return rows


def _relative_path(value: object, label: str) -> Path:
    if not isinstance(value, str) or not value:
        raise CheckError(f"{label}: path must be a non-empty string")
    posix = PurePosixPath(value)
    if posix.is_absolute() or ".." in posix.parts:
        raise CheckError(f"{label}: path must be relative inside the repo")
    return Path(*posix.parts)


def _load_questions(track: str, root: Path, key: str) -> list[data.Question]:
    try:
        questions = data.load_questions(track, root)
    except FileNotFoundError as error:
        name = Path(error.filename).name if error.filename else "?"
        raise CheckError(f"missing required file for {key}: {name}") from None
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError) as error:
        raise CheckError(f"unreadable question set for {key} ({type(error).__name__})") from None
    except ValueError as error:
        raise CheckError(f"invalid question set for {key}: {error}") from None
    if not questions:
        raise CheckError(f"empty input: question set for {key}")
    return questions


def _check_inputs(root: Path, key: str, entry: Mapping) -> None:
    """manifest가 적은 입력 파일 해시가 파일과 같은지 본다(파일이 있는 입력만, queries는 필수)."""
    inputs = entry.get("inputs")
    if not isinstance(inputs, dict) or "queries" not in inputs:
        raise CheckError(f"{key}: manifest has no inputs.queries")
    for name, item in inputs.items():
        if not isinstance(item, dict):
            raise CheckError(f"{key}: manifest inputs.{name} is not an object")
        path = root / _relative_path(item.get("path"), f"{key} inputs.{name}")
        if not path.is_file():
            if name == "queries":
                raise CheckError(f"missing required file: {item['path']}")
            continue
        if data.file_sha256(path) != item.get("sha256"):
            raise CheckError(f"{key}: input sha256 differs from manifest: {item['path']}")


def _load_records(root: Path, key: str, entry: Mapping, questions: list[data.Question]) -> dict:
    stored_results = entry.get("stored_results")
    if not isinstance(stored_results, dict):
        raise CheckError(f"{key}: manifest has no stored_results object")
    stored = stored_results.get("path")
    path = _relative_path(stored, f"{key} stored_results")
    rows = _read_jsonl(root / path, path.as_posix())
    records: dict[str, dict] = {}
    for row in rows:
        try:
            scoring.validate_record(row)
        except ValueError as error:
            raise CheckError(f"{path.as_posix()}: invalid record ({error})") from None
        if row["question_id"] in records:
            raise CheckError(f"{path.as_posix()}: duplicate question id {row['question_id']}")
        records[row["question_id"]] = row
    expected = {q.question_id for q in questions if not q.excluded}
    if missing := sorted(expected - set(records)):
        raise CheckError(f"{path.as_posix()}: missing question ids {missing[:5]} ({len(missing)})")
    if extra := sorted(set(records) - expected):
        raise CheckError(f"{path.as_posix()}: unknown question ids {extra[:5]} ({len(extra)})")
    for question in questions:
        if question.excluded:
            continue
        ranked = {item["doc_id"] for item in records[question.question_id]["results"]}
        if leaked := sorted(ranked & question.unjudged):
            raise CheckError(
                f"{path.as_posix()}: {question.question_id} keeps unjudged docs {leaked[:3]} "
                "(condensed list violated)"
            )
    return records


def recompute(root: Path) -> tuple[dict, dict]:
    """(manifest, 다시 계산한 metrics). 입력 문제가 있으면 CheckError."""
    manifest = _read_json(root / RESULTS_DIR / "manifest.json", "results/baselines/manifest.json")
    runs = manifest.get("runs")
    if not isinstance(runs, dict) or not runs:
        raise CheckError("empty input: results/baselines/manifest.json has no runs")
    recomputed: dict[str, dict] = {}
    for key in runs:
        track, _, retriever = key.partition("/")
        if track not in data.TRACKS or retriever not in RETRIEVERS:
            raise CheckError(f"unknown run key {key!r} in manifest")
    for key in sorted(runs, key=lambda k: (data.TRACKS.index(k.split("/")[0]), k)):
        track, _, retriever = key.partition("/")
        entry = runs[key]
        if not isinstance(entry, dict):
            raise CheckError(f"{key}: manifest run entry is not an object")
        questions = _load_questions(track, root, key)
        _check_inputs(root, key, entry)
        records = _load_records(root, key, entry, questions)
        try:
            tau = entry["selected"]["tau"]
        except (KeyError, TypeError):
            raise CheckError(f"{key}: manifest has no selected.tau") from None
        splits = {}
        for split in data.SPLITS:
            if any(
                q.split == split and not q.excluded for q in questions
            ):  # compute_run_metrics와 같다
                splits[split] = scoring.evaluate_split(records, questions, split, tau)
        recomputed[key] = splits
    return manifest, {"protocol_version": scoring.PROTOCOL_VERSION, "runs": recomputed}


def diff_values(expected: object, actual: object, where: str = "") -> list[str]:
    """metrics.json(actual)이 다시 계산한 값(expected)과 다른 위치. 실수는 abs ATOL 안이면 같다."""
    if isinstance(expected, dict) and isinstance(actual, dict):
        problems = []
        for name in sorted(set(expected) | set(actual)):
            if name not in actual:
                problems.append(f"{where}/{name}: missing in metrics.json")
            elif name not in expected:
                problems.append(f"{where}/{name}: not recomputed")
            else:
                problems += diff_values(expected[name], actual[name], f"{where}/{name}")
        return problems
    numeric = (int, float)
    if (
        isinstance(expected, numeric)
        and isinstance(actual, numeric)
        and not isinstance(expected, bool)
        and not isinstance(actual, bool)
    ):
        close = math.isclose(expected, actual, rel_tol=0.0, abs_tol=ATOL)
        return [] if close else [f"{where}: recomputed {expected!r} != metrics.json {actual!r}"]
    if expected == actual and type(expected) is type(actual):
        return []
    return [f"{where}: recomputed {expected!r} != metrics.json {actual!r}"]


def render_tables(metrics: Mapping) -> str:
    runs = metrics["runs"]
    lines: list[str] = [NOTE, ""]
    for track in data.TRACKS:
        names = sorted(
            (key.split("/", 1)[1] for key in runs if key.startswith(f"{track}/")),
            key=RETRIEVERS.index,
        )
        if not names:
            continue
        lines += [f"### {TRACK_TITLES[track]}", ""]
        lines += [
            "| 검색기 | split | 채점 질문 | 제외 | macro nDCG@10 | macro hit@10 | macro MRR@10 |",
            "|---|---|---|---|---|---|---|",
        ]
        for name in names:
            for split in data.SPLITS:
                block = runs[f"{track}/{name}"].get(split)
                if block is None:
                    continue
                macro = block["macro"]
                lines.append(
                    f"| {name} | {split} | {block['n_questions']} | {block['n_excluded']} "
                    f"| {_fmt(macro['ndcg@10'])} | {_fmt(macro['hit@10'])} "
                    f"| {_fmt(macro['mrr@10'])} |"
                )
        lines += ["", "유형별 (no_answer는 아래 기권 표):", ""]
        lines += [
            "| 검색기 | split | 유형 | n_scored | nDCG@10 | hit@1 | hit@10 | recall@10 | MRR@10 |",
            "|---|---|---|---|---|---|---|---|---|",
        ]
        for name in names:
            for split in data.SPLITS:
                block = runs[f"{track}/{name}"].get(split)
                if block is None:
                    continue
                for query_type in data.QUERY_TYPES:
                    item = block["by_type"].get(query_type)
                    if item is None or query_type == "no_answer":
                        continue
                    m = item["metrics"]
                    mark = "†" if item["observation_only"] else ""
                    lines.append(
                        f"| {name} | {split} | {query_type} | {item['n_scored']}{mark} "
                        f"| {_fmt(m['ndcg@10'])} | {_fmt(m['hit@1'])} | {_fmt(m['hit@10'])} "
                        f"| {_fmt(m['recall@10'])} | {_fmt(m['mrr@10'])} |"
                    )
        lines += ["", "no_answer (기권):", ""]
        lines += [
            "| 검색기 | split | n_no_answer | τ | abstain_rate | n_answerable | false_abstain_rate |",
            "|---|---|---|---|---|---|---|",
        ]
        for name in names:
            for split in data.SPLITS:
                block = runs[f"{track}/{name}"].get(split)
                if block is None:
                    continue
                na = block["no_answer"]
                lines.append(
                    f"| {name} | {split} | {na['n_no_answer']} | {_fmt(na['tau'])} "
                    f"| {_fmt(na['abstain_rate'])} | {na['n_answerable']} "
                    f"| {_fmt(na['false_abstain_rate'])} |"
                )
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _split_readme(
    text: str, label: str, markers: tuple[str, str] = (BEGIN, END)
) -> tuple[int, int]:
    """문서에서 BEGIN 끝 위치와 END 시작 위치. 마커가 없거나 순서·개수가 틀리면 CheckError."""
    begin, end = markers
    if text.count(begin) != 1 or text.count(end) != 1:
        raise CheckError(f"{label}: needs exactly one generated-table marker pair")
    start, stop = text.index(begin) + len(begin), text.index(end)
    if start > stop:
        raise CheckError(f"{label}: END marker is before BEGIN marker")
    return start, stop


def _read_readme(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise CheckError(f"missing required file: {path.name}") from None
    except (OSError, UnicodeDecodeError) as error:
        raise CheckError(f"unreadable file: {path.name} ({type(error).__name__})") from None


def verify(root: Path, readme: Path) -> tuple[list[str], dict]:
    """(불일치 목록, 다시 계산한 metrics). 입력 문제는 CheckError."""
    _, recomputed = recompute(root)
    stored = _read_json(root / RESULTS_DIR / "metrics.json", "results/baselines/metrics.json")
    problems = diff_values(recomputed, stored, "metrics.json")
    text = _read_readme(readme)
    start, stop = _split_readme(text, readme.name)
    expected = render_tables(recomputed).strip()
    if text[start:stop].strip() != expected:
        shown = text[start:stop].strip().splitlines()
        problems.append(
            f"{readme.name}: generated tables differ from recomputed tables "
            f"({len(shown)} lines in README, {len(expected.splitlines())} expected)"
        )
        for number, (have, want) in enumerate(zip(shown, expected.splitlines(), strict=False), 1):
            if have != want:
                problems.append(f"  first difference at table line {number}")
                break
    return problems, recomputed


def write_readme(readme: Path, recomputed: Mapping) -> None:
    text = _read_readme(readme)
    start, stop = _split_readme(text, readme.name)
    readme.write_text(
        text[:start] + "\n\n" + render_tables(recomputed) + "\n" + text[stop:], encoding="utf-8"
    )


# ------------------------------------------------------------ M3 실험: 재계산, 판정 표, 검증


def _m3_inputs(root: Path, track: str, recorded: Mapping, where: str) -> dict:
    """지금 리포(또는 asset 사본)의 입력 파일 해시. `data.input_fingerprints`와 같은 입력이다.

    릴리스 asset에는 NVD 코퍼스(`fixtures/nvd/cves.jsonl`)가 없으므로 그 파일만, 없으면 실험 manifest가 적은
    값을 쓴다. 이 값은 `compare_run`의 비교 전 검사에서 기준선 manifest의 값과 대조된다."""
    if track == "public":
        paths = {"queries": data.PUBLIC_QUERIES, "corpus": data.PUBLIC_CORPUS}
    else:
        paths = {
            "queries": data.KISA_GOLDEN,
            "corpus_manifest": data.KISA_MANIFEST,
            "corpus_metadata": data.KISA_METADATA,
        }
    if not isinstance(recorded, dict) or set(recorded) != set(paths):
        raise CheckError(f"{where}: manifest inputs are not {sorted(paths)}")
    current = {}
    for name, path in paths.items():
        full = root / path
        if full.is_file():
            current[name] = {"path": path.as_posix(), "sha256": data.file_sha256(full)}
        elif name == "corpus":
            current[name] = dict(recorded[name])
        else:
            raise CheckError(f"missing required file: {path.as_posix()}")
    return current


def recompute_experiment(root: Path, name: str) -> tuple[dict, dict]:
    """(metrics, comparison). manifest, 저장된 원시 결과, 질의셋 라벨, 기준선 저장본만으로 하네스의
    `compute_outputs`와 같은 값을 만든다. 모델·KISA 캐시를 읽지 않는다. 입력 문제는 CheckError."""
    try:
        return _recompute_experiment(root, name)
    except CheckError:
        raise
    except (ExperimentError, OSError, ValueError, KeyError, TypeError, AttributeError) as error:
        raise CheckError(f"{name}: {type(error).__name__}: {error}") from None


def _recompute_experiment(root: Path, name: str) -> tuple[dict, dict]:
    module = harness.load_experiment(name)
    exp_root = EXPERIMENTS_DIR / name
    manifest = _read_json(root / exp_root / "manifest.json", f"{exp_root.as_posix()}/manifest.json")
    runs = manifest.get("runs")
    expected_keys = {f"{track}/{v}" for track, names in module.VARIANTS.items() for v in names}
    if not isinstance(runs, dict) or set(runs) != expected_keys:
        raise CheckError(f"{name}: manifest runs are not exactly {sorted(expected_keys)}")
    baselines_manifest = _read_json(
        root / RESULTS_DIR / "manifest.json", "results/baselines/manifest.json"
    )
    metrics: dict = {"protocol_version": scoring.PROTOCOL_VERSION, "experiment": name, "runs": {}}
    blocks: dict[str, dict] = {}
    for track in data.TRACKS:
        if track not in module.VARIANTS:
            continue
        questions = _load_questions(track, root, f"{name}/{track}")
        for variant in module.VARIANTS[track]:
            key = f"{track}/{variant}"
            entry = runs[key]
            where = f"{name} {key}"
            stored_path = f"{exp_root.as_posix()}/{track}/{variant}.jsonl"
            if entry["stored_results"]["path"] != stored_path:
                raise CheckError(f"{where}: stored_results.path is not {stored_path}")
            baseline = harness.baseline_of(module, track, variant)
            if entry["baseline"]["retriever"] != baseline:
                raise CheckError(f"{where}: manifest baseline differs from the module's {baseline}")
            records = cmp.read_stored(root / stored_path)
            cmp.check_known(key, records, questions)
            tau = entry["selected"]["tau"]
            run_metrics = {}
            for split in data.SPLITS:
                split_questions = [q for q in questions if q.split == split and not q.excluded]
                if len({q.question_id for q in split_questions} & set(records)) != len(
                    split_questions
                ):
                    raise CheckError(f"{where}: {split} rows are not all stored")
                run_metrics[split] = scoring.evaluate_split(records, questions, split, tau)
            metrics["runs"][key] = run_metrics
            lock = entry.get("test")
            if lock is None:
                raise CheckError(f"{where}: no test lock in the manifest")
            if harness.entry_hash(name, entry) != lock["config_hash"]:
                raise CheckError(
                    f"{where}: manifest config_hash does not match its recorded config"
                )
            current = _m3_inputs(root, track, entry["inputs"], where)
            if entry["inputs"] != current:
                raise CheckError(f"{where}: manifest input hashes differ from the input files")
            for label, fingerprint in entry["reproduction_inputs"].items():
                path = root / _relative_path(fingerprint.get("path"), f"{where} reproduction input")
                if not path.is_file() or data.file_sha256(path) != fingerprint["sha256"]:
                    raise CheckError(f"{where}: reproduction input {label!r} differs or is missing")
            base_entry = cmp.check_baseline_entry(baselines_manifest, track, baseline)
            blocks[key] = cmp.compare_run(
                track=track,
                variant=variant,
                baseline=baseline,
                questions=questions,
                exp_records=records,
                exp_entry=entry,
                base_records=harness.read_baseline_records(root, track, baseline),
                base_entry=base_entry,
                current_inputs=current,
            )
    comparison = cmp.assemble_comparison(
        experiment=name, hypothesis=module.HYPOTHESIS, primary=tuple(module.PRIMARY), blocks=blocks
    )
    return metrics, comparison


def recompute_m3(root: Path) -> dict[str, dict]:
    """`{실험: {"metrics", "comparison"}}`, 다시 계산한 값. 입력 문제는 CheckError."""
    return {
        name: dict(zip(("metrics", "comparison"), recompute_experiment(root, name), strict=True))
        for name in EXPERIMENTS
    }


def diff_stored_m3(root: Path, recomputed: Mapping[str, Mapping]) -> list[str]:
    """저장된 `metrics.json`·`comparison.json`(실험마다)이 다시 계산한 값과 다른 위치(abs 1e-9)."""
    problems: list[str] = []
    for name, outputs in recomputed.items():
        for filename in ("metrics", "comparison"):
            relative = f"{EXPERIMENTS_DIR.as_posix()}/{name}/{filename}.json"
            stored = _read_json(root / relative, relative)
            normalized = json.loads(json.dumps(outputs[filename], ensure_ascii=False))
            problems += [f"{relative} {line}" for line in cmp.diff_values(stored, normalized)]
    return problems


def _signed(value: float) -> str:
    return f"{value:+.4f}"


def _interval(block: Mapping) -> str:
    return f"[{_signed(block['ci95']['low'])}, {_signed(block['ci95']['high'])}]"


def _cell(text: str) -> str:
    return text.replace("|", "\\|")


def _cve_regression(block: Mapping) -> str:
    cve = block["cve_explicit"]
    if cve["delta_ndcg@10"] is None:
        return "-"
    return f"{'예' if cve['regression'] else '아니오'} ({_signed(cve['delta_ndcg@10'])})"


def _primary_block(comparison: Mapping) -> Mapping:
    primary = comparison["primary"]
    return comparison["comparisons"][f"{primary['track']}/{primary['variant']}"]


def _secondary_blocks(comparison: Mapping) -> list[Mapping]:
    return [
        comparison["comparisons"][f"{s['track']}/{s['variant']}"] for s in comparison["secondary"]
    ]


def _verdict_counts(recomputed: Mapping[str, Mapping]) -> str:
    verdicts = [outputs["comparison"]["primary"]["verdict"] for outputs in recomputed.values()]
    return (
        f"주 판정 {len(verdicts)}건: {cmp.CONFIRMED} {verdicts.count(cmp.CONFIRMED)}, "
        f"{cmp.REJECTED} {verdicts.count(cmp.REJECTED)}."
    )


def render_m3_table(recomputed: Mapping[str, Mapping], link_prefix: str) -> str:
    """판정 표 구간(README·릴리스 노트용). 실험 이름은 `<link_prefix><실험>.md` 보고서로 링크한다."""
    lines = [
        M3_NOTE,
        "",
        _verdict_counts(recomputed),
        "",
        (
            "| 실험 | 주 트랙 (변형) | 기준 | test n | 기준 macro nDCG@10 | 실험 macro nDCG@10 "
            "| delta | 95% 구간 | 판정 |"
        ),
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for name in EXPERIMENTS:
        comparison = recomputed[name]["comparison"]
        block = _primary_block(comparison)
        lines.append(
            f"| [{name}]({link_prefix}{name}.md) | {block['track']} ({block['variant']}) "
            f"| {block['baseline']} | {block['n_test_questions']} | {_fmt(block['baseline_macro'])} "
            f"| {_fmt(block['experiment_macro'])} | {_signed(block['delta'])} "
            f"| {_interval(block)} | `{block['verdict']}` |"
        )
    return "\n".join(lines).rstrip() + "\n"


def render_summary_tables(recomputed: Mapping[str, Mapping]) -> str:
    """summary.md의 표 구간: 실험마다 한 행(가설, 주 판정, 보조 판정, cve_explicit 회귀)과 보조 비교 표."""
    lines = [
        M3_NOTE,
        "",
        _verdict_counts(recomputed),
        "",
        (
            "| 실험 | 가설 (사전 등록) | 주 트랙 (변형) | 기준 | test n | 기준 macro nDCG@10 "
            "| 실험 macro nDCG@10 | delta | 95% 구간 | 판정 | 보조 판정 | cve_explicit 회귀 |"
        ),
        "|---|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for name in EXPERIMENTS:
        comparison = recomputed[name]["comparison"]
        block = _primary_block(comparison)
        secondary = (
            "<br>".join(
                f"{s['track']}/{s['variant']}: `{s['verdict']}`" for s in comparison["secondary"]
            )
            or "-"
        )
        lines.append(
            f"| [{name}]({name}.md) | {_cell(comparison['hypothesis'])} "
            f"| {block['track']} ({block['variant']}) | {block['baseline']} | {block['n_test_questions']} "
            f"| {_fmt(block['baseline_macro'])} | {_fmt(block['experiment_macro'])} "
            f"| {_signed(block['delta'])} | {_interval(block)} | `{block['verdict']}` "
            f"| {secondary} | {_cve_regression(block)} |"
        )
    lines += [
        "",
        "보조 비교 (같은 규칙의 판정이고 이슈 라벨은 주 판정을 따른다):",
        "",
        (
            "| 실험 | 비교 (트랙/변형) | 기준 | test n | 기준 macro nDCG@10 | 실험 macro nDCG@10 "
            "| delta | 95% 구간 | 판정 | cve_explicit 회귀 |"
        ),
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for name in EXPERIMENTS:
        for block in _secondary_blocks(recomputed[name]["comparison"]):
            lines.append(
                f"| {name} | {block['track']}/{block['variant']} | {block['baseline']} "
                f"| {block['n_test_questions']} | {_fmt(block['baseline_macro'])} "
                f"| {_fmt(block['experiment_macro'])} | {_signed(block['delta'])} "
                f"| {_interval(block)} | `{block['verdict']}` | {_cve_regression(block)} |"
            )
    return "\n".join(lines).rstrip() + "\n"


def m3_documents(
    root: Path,
    readme: Path,
    summary: Path | None = None,
    note: Path | None = None,
    notes: Sequence[Path] | None = None,
) -> list[tuple[Path, tuple[str, str], str]]:
    """(문서 경로, 마커 쌍, 구간 종류). 문서를 따로 정하지 않으면 `<root>` 아래 고정 경로다.

    `notes`는 M3 판정 구간을 가진 릴리스 노트 전부다(주지 않으면 `note` 하나, 그것도 없으면 v0.2 노트)."""
    paths = list(notes) if notes is not None else [note or root / NOTE_V02_PATH]
    return [
        (readme, README_M3, "readme"),
        (summary or root / SUMMARY_PATH, SUMMARY_RANGE, "summary"),
        *[(path, NOTE_RANGE, "note") for path in paths],
    ]


def _render_range(kind: str, recomputed: Mapping[str, Mapping]) -> str:
    if kind == "readme":
        return render_m3_table(recomputed, "docs/experiments/")
    if kind == "summary":
        return render_summary_tables(recomputed)
    return render_m3_table(recomputed, "experiments/")


def verify_m3(
    root: Path,
    readme: Path,
    *,
    summary: Path | None = None,
    note: Path | None = None,
    notes: Sequence[Path] | None = None,
) -> tuple[list[str], Mapping[str, Mapping]]:
    """(불일치 목록, 다시 계산한 M3 값). 저장된 metrics·comparison과 문서(README, summary, 노트)의 생성 구간을 대조한다.

    `root`는 원시 결과·라벨을 읽는 곳(릴리스 asset 사본이면 그 사본), 문서 경로는 따로 줄 수 있다."""
    documents = []
    for path, markers, kind in m3_documents(
        root, readme, summary, note, notes
    ):  # 마커 오류는 재계산 전에 멈춘다
        text = _read_readme(path)
        documents.append((path, text, _split_readme(text, path.name, markers), kind))
    recomputed = recompute_m3(root)
    problems = diff_stored_m3(root, recomputed)
    for path, text, (start, stop), kind in documents:
        expected = _render_range(kind, recomputed).strip()
        if text[start:stop].strip() != expected:
            shown = text[start:stop].strip().splitlines()
            problems.append(
                f"{path.name}: M3 generated range differs from recomputed tables "
                f"({len(shown)} lines in file, {len(expected.splitlines())} expected)"
            )
            for number, (have, want) in enumerate(
                zip(shown, expected.splitlines(), strict=False), 1
            ):
                if have != want:
                    problems.append(f"  first difference at {path.name} range line {number}")
                    break
    return problems, recomputed


def write_m3(
    root: Path,
    readme: Path,
    recomputed: Mapping[str, Mapping],
    summary: Path | None = None,
    note: Path | None = None,
    notes: Sequence[Path] | None = None,
) -> None:
    for path, markers, kind in m3_documents(root, readme, summary, note, notes):
        text = _read_readme(path)
        start, stop = _split_readme(text, path.name, markers)
        path.write_text(
            text[:start] + "\n\n" + _render_range(kind, recomputed) + "\n" + text[stop:],
            encoding="utf-8",
        )


def m3_active(root: Path, readme: Path) -> bool:
    """실험 결과 디렉터리가 있거나 README가 M3 구간 마커를 갖고 있으면 M3를 검증한다(데이터가 사라져도 통과하지 않는다)."""
    if (root / EXPERIMENTS_DIR).is_dir():
        return True
    try:
        return README_M3[0] in readme.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return False


# ------------------------------------------------------------ M4: 전체 수집·멱등성 보고서, 표, 검증


def _ids(values: Sequence) -> str:
    return ", ".join(str(v) for v in values) if values else "없음"


def _by_reason(values: Mapping) -> str:
    return "; ".join(f"`{reason}`: {_ids(ids)}" for reason, ids in sorted(values.items())) or "없음"


def _m4_facts(
    collection: Mapping, idempotency: Mapping, manifest: Mapping, rows: list[dict]
) -> tuple[dict, list[str]]:
    """manifest·메타데이터에서 센 값(facts)과 보고서가 manifest와 어긋난 항목(problems)."""
    documents = manifest["documents"]
    target = manifest["target_ids"]
    ids = [str(d["nttId"]) for d in documents]
    failed: dict[str, list[str]] = {}
    for item in documents:
        if item["result"] != "ok":
            failed.setdefault(item["result"], []).append(str(item["nttId"]))
    failed = {reason: sorted(found, key=int) for reason, found in failed.items()}
    ok_ids = sorted((str(d["nttId"]) for d in documents if d["result"] == "ok"), key=int)
    unresolved = sorted((i for found in failed.values() for i in found), key=int)
    cves = {cve for row in rows for cve in row["cve_ids"]}
    facts = {
        "target": len(target),
        "ok": len(ok_ids),
        "metadata_rows": len(rows),
        "metadata_with_cve": sum(1 for row in rows if row["cve_ids"]),
        "metadata_distinct_cve": len(cves),
    }
    problems: list[str] = []

    def expect(label: str, got: object, want: object) -> None:
        if got != want:
            problems.append(f"{M4_PROBLEM} {label}: {got!r} != {want!r}")

    expect(
        "manifest documents vs target_ids", sorted(ids, key=int), sorted(map(str, target), key=int)
    )
    expect(
        "collection report discovered_ids vs manifest target_ids",
        collection["discovered_ids"],
        len(target),
    )
    expect(
        "collection report detail_ok vs manifest ok documents", collection["detail_ok"], len(ok_ids)
    )
    expect(
        "collection report parse_failed vs manifest",
        collection["parse_failed"],
        {r: len(v) for r, v in failed.items() if r.startswith("parse_failed:")},
    )
    expect(
        "collection report detail_failed vs manifest",
        collection["detail_failed"],
        {r: len(v) for r, v in failed.items() if r.startswith("fetch_failed:")},
    )
    expect("collection report failed_ids vs manifest", collection["failed_ids"], failed)
    expect(
        "collection report missing_ids vs manifest",
        sorted(collection["missing_ids"], key=int),
        unresolved,
    )
    expect(
        "collection report detail_pending vs manifest",
        collection["detail_pending"],
        len(target) - len(documents),
    )
    for key in ("complete", "discovery_complete", "parser_version"):
        expect(f"collection report {key} vs manifest", collection[key], manifest[key])
    discovery = manifest["discovery"]
    for key in DISCOVERY_KEYS:
        expect(f"collection report {key} vs manifest discovery", collection[key], discovery[key])
    expect(
        "collection report discovery_error vs manifest discovery",
        collection["discovery_error"],
        discovery["error"],
    )
    if collection["displayed_total"] is not None:
        expect(
            "collection report displayed_total_gap",
            collection["displayed_total_gap"],
            collection["displayed_total"] - len(target),
        )
    expect(
        "metadata nttIds vs manifest ok documents",
        sorted((str(r["nttId"]) for r in rows), key=int),
        ok_ids,
    )
    corpus = idempotency["corpus"]
    expect("idempotency report corpus target_ids vs manifest", corpus["target_ids"], len(target))
    expect("idempotency report corpus ok_docs vs manifest", corpus["ok_docs"], len(ok_ids))
    expect(
        "idempotency report corpus unresolved_ids vs manifest",
        corpus["unresolved_ids"],
        len(unresolved),
    )
    expect(
        "idempotency report corpus baseline_docs",
        corpus["baseline_docs"],
        len(ok_ids) - idempotency["k"],
    )
    expect(
        "idempotency report corpus parser_version vs manifest",
        corpus["parser_version"],
        manifest["parser_version"],
    )
    steps = idempotency["steps"]
    # 실패한 검증은 실패한 단계에서 멈추거나(그 단계까지 기록) 단계 안 예외로 그 앞 단계까지만 남는다
    expect(
        "idempotency report step numbers",
        [s["step"] for s in steps],
        list(range(1, len(steps) + 1)),
    )
    expect(
        "idempotency report passed vs step results",
        idempotency["passed"],
        len(steps) == 5 and all(s["passed"] for s in steps),
    )
    failed_here = next((s["step"] for s in steps if not s["passed"]), None)
    if failed_here is None and not idempotency["passed"]:
        failed_here = len(steps) + 1  # 단계 안 예외: 그 단계는 기록되지 않았다
    expect("idempotency report failed_step", idempotency["failed_step"], failed_here)
    return facts, problems


def load_m4(root: Path) -> dict:
    """M4 입력(두 보고서, kisa_full manifest·메타데이터)과 서로의 대조 결과. 입력 문제는 CheckError.

    `{"collection", "idempotency", "facts", "problems"}`. problems는 보고서가 manifest와 어긋난 항목이다."""
    collection = _read_json(root / M4_COLLECTION, M4_COLLECTION.as_posix())
    idempotency = _read_json(root / M4_IDEMPOTENCY, M4_IDEMPOTENCY.as_posix())
    manifest = _read_json(root / M4_MANIFEST, M4_MANIFEST.as_posix())
    rows = _read_jsonl(root / M4_METADATA, M4_METADATA.as_posix())
    for report, keys, path in (
        (collection, COLLECTION_KEYS, M4_COLLECTION),
        (idempotency, IDEMPOTENCY_KEYS, M4_IDEMPOTENCY),
    ):
        if missing := [key for key in keys if key not in report]:
            raise CheckError(f"{path.as_posix()}: missing keys {missing[:5]} ({len(missing)})")
    try:
        facts, problems = _m4_facts(collection, idempotency, manifest, rows)
    except (KeyError, TypeError, ValueError, AttributeError) as error:
        raise CheckError(f"M4 inputs are malformed ({type(error).__name__})") from None
    m4 = {
        "collection": collection,
        "idempotency": idempotency,
        "facts": facts,
        "problems": problems,
    }
    try:
        render_m4(m4, "")  # 표가 읽는 중첩 키가 없거나 형식이 틀리면 여기서 CheckError로 멈춘다
    except (KeyError, TypeError, ValueError, AttributeError) as error:
        raise CheckError(f"M4 reports are malformed ({type(error).__name__})") from None
    return m4


def _comparison_cell(comparison: Mapping) -> str:
    parts = []
    if "points_equal_snapshot_docs" in comparison:
        parts.append(
            "point 수 = 스냅샷 문서 수"
            if comparison["points_equal_snapshot_docs"]
            else "point 수 != 스냅샷 문서 수"
        )
    if "ids_equal" in comparison:
        same = comparison["ids_equal"] and comparison["payload_equal"]
        parts.append("ID 집합·payload 동일" if same else "ID 집합이나 payload 다름")
    if "vectors_max_abs_diff" in comparison:
        parts.append(f"벡터 최대 차 {comparison['vectors_max_abs_diff']}")
    if "unchanged_points" in comparison:
        parts.append(
            f"영향 없는 {comparison['unchanged_points']}건 중 {comparison['unchanged_points_identical']}건 동일"
        )
    if "updated_vectors_changed" in comparison:
        parts.append(f"갱신 벡터 변경 {comparison['updated_vectors_changed']}건")
    if "deleted_absent" in comparison:
        parts.append("삭제 확인" if comparison["deleted_absent"] else "삭제 안 됨")
    if "added_present" in comparison:
        parts.append("추가 확인" if comparison["added_present"] else "추가 안 됨")
    return ", ".join(parts) or "-"


def render_m4(m4: Mapping, link_prefix: str) -> str:
    """M4 구간(README·릴리스 노트용). 보고서 문서 링크는 `<link_prefix>m4-collection.md`·`<link_prefix>m4-idempotency.md`다."""
    c, i, f = m4["collection"], m4["idempotency"], m4["facts"]
    req = c["requests"]
    parse_failed = {r: v for r, v in c["failed_ids"].items() if r.startswith("parse_failed:")}
    model, runtime, env, corpus = i["model"], i["runtime"], i["environment"], i["corpus"]
    lines = [
        M4_NOTE,
        "",
        f"### 전체 수집: 규모, 누락, 중복, 파싱 실패 ([m4-collection.md]({link_prefix}m4-collection.md))",
        "",
        "| 항목 | 값 |",
        "|---|---|",
        f"| 발견 ID (고정 대상) | {c['discovered_ids']} |",
        f"| 게시판 표시 총수 / 차이 | {c['displayed_total']} / {c['displayed_total_gap']} |",
        f"| 상세 성공 | {c['detail_ok']} |",
        f"| 상세 실패 (fetch_failed) | {sum(c['detail_failed'].values())} |",
        f"| 파싱 실패 | {sum(c['parse_failed'].values())} ({_by_reason(parse_failed)}) |",
        f"| 미처리 | {c['detail_pending']} |",
        f"| 누락 (발견했지만 `ok` 아님) | {len(c['missing_ids'])} ({_ids(c['missing_ids'])}) |",
        f"| 목록 페이지 / 원시 행 | {c['list_pages']} / {c['list_rows']} |",
        f"| 목록 중복: 페이지 안 / 페이지 사이 | {c['list_duplicate_in_page']} / {c['list_duplicate_across_pages']} |",
        f"| 목록 중복 ID / 제목·날짜 충돌 ID | {len(c['list_duplicate_ids'])} ({_ids(c['list_duplicate_ids'])}) / {len(c['list_conflict_ids'])} |",
        f"| 내용 중복 (본문 sha256이 같은 묶음 / 문서) | {c['content_duplicate_group_count']} / {c['content_duplicate_doc_count']} |",
        f"| RSS 항목 / 목록에 없는 RSS 전용 ID | {c['rss_ids']} / {len(c['rss_only_ids'])} |",
        f"| 고정 50건 포함 / 본문 sha256 일치 | {c['fixed_present']} / {c['fixed_hash_match']} (기대 {c['fixed_expected']}) |",
        f"| 메타데이터 행 / CVE ID가 있는 행 / 서로 다른 CVE ID | {f['metadata_rows']} / {f['metadata_with_cve']} / {f['metadata_distinct_cve']} |",
        f"| 수집 완료 / 중단 | {'예' if c['complete'] else '아니오'} / {c['aborted'] or '없음'} |",
        f"| 요청 수 | {req['total']} (robots {req['robots']}, RSS {req['rss']}, 목록 {req['list']}, 상세 {req['detail']}) |",
        f"| 소요 시간 (초) | {c['elapsed_seconds']:.1f} |",
        "",
        f"### 멱등성 검증 1~5단계 ([m4-idempotency.md]({link_prefix}m4-idempotency.md))",
        "",
        (
            f"검증 {'통과' if i['passed'] else '실패'} (갱신·삭제·추가 각 {i['k']}건, 시드 {i['seed']}, "
            f"실패 단계 {i['failed_step'] or '없음'}, 소요 {i['elapsed_seconds']:.1f}초)."
        ),
        "",
        "| 항목 | 값 |",
        "|---|---|",
        f"| 스냅샷 | 대상 ID {corpus['target_ids']}, `ok` {corpus['ok_docs']}, `ok` 아님 {corpus['unresolved_ids']}, 기준 스냅샷 {corpus['baseline_docs']} |",
        f"| 모델 | `{model['name']}` revision `{model['revision']}` |",
        f"| pooling / dtype / 차원 | {model['pooling']} / {model['dtype']} / {model['dimension']} |",
        f"| `max_seq_length` / batch_size / 장치 | {model['max_seq_length']} / {model['batch_size']} / {model['device']} |",
        f"| Qdrant | 서버 {i['qdrant']['version']}, 이미지 `{i['qdrant']['image']}` |",
        (
            f"| 런타임 | Python {runtime['python']}, sentence-transformers {runtime['sentence_transformers']}, "
            f"torch {runtime['torch']}, numpy {runtime['numpy']}, qdrant-client {runtime['qdrant_client']} |"
        ),
        f"| 환경 | {env['system']} {env['machine']}, 코어 {env['cpu_count']}, `OMP_NUM_THREADS={env['omp_num_threads']}` |",
        f"| 허용오차 | 영향 없는 point {i['tolerances']['unchanged_points']}, 벡터 abs {i['tolerances']['vector_abs']} |",
        "",
        "| 단계 | 동작 | 계획 (추가/갱신/삭제) | point 수 | 인코딩 | 쓰기 (upsert/payload/delete) | 비교 | 통과 | 소요 (초) |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for step in i["steps"]:
        plan, writes = step["plan"], step["writes"]
        lines.append(
            f"| {step['step']} | `{step['name']}` | {plan['add']}/{plan['update']}/{plan['delete']} "
            f"| {step['points']} | {step['encoded_texts']} "
            f"| {writes['upsert']}/{writes['payload_update']}/{writes['delete']} "
            f"| {_comparison_cell(step['comparison'])} | {'예' if step['passed'] else '아니오'} "
            f"| {step['elapsed_seconds']:.1f} |"
        )
    return "\n".join(lines).rstrip() + "\n"


def m4_documents(
    root: Path, readme: Path, note: Path | None = None, notes: Sequence[Path] | None = None
) -> list[tuple[Path, tuple[str, str], str]]:
    """(문서 경로, 마커 쌍, 구간 종류). `notes`는 M4 구간을 가진 릴리스 노트 전부다(주지 않으면 `note` 하나, 없으면 v0.3 노트)."""
    paths = list(notes) if notes is not None else [note or root / NOTE_V03_PATH]
    return [(readme, README_M4, "readme"), *[(path, NOTE_M4_RANGE, "note") for path in paths]]


def _render_m4_range(kind: str, m4: Mapping) -> str:
    return render_m4(m4, "docs/" if kind == "readme" else "")


def verify_m4(
    root: Path,
    readme: Path,
    *,
    note: Path | None = None,
    notes: Sequence[Path] | None = None,
) -> tuple[list[str], Mapping]:
    """(불일치 목록, M4 입력). 보고서·manifest끼리의 대조와 README·v0.3 노트의 M4 구간을 본다.

    `root`는 보고서·manifest·메타데이터를 읽는 곳(릴리스 asset 사본이면 그 사본)이다."""
    documents = []
    for path, markers, kind in m4_documents(
        root, readme, note, notes
    ):  # 마커 오류는 입력을 읽기 전에 멈춘다
        text = _read_readme(path)
        documents.append((path, text, _split_readme(text, path.name, markers), kind))
    m4 = load_m4(root)
    problems = list(m4["problems"])
    for path, text, (start, stop), kind in documents:
        expected = _render_m4_range(kind, m4).strip()
        if text[start:stop].strip() != expected:
            shown = text[start:stop].strip().splitlines()
            problems.append(
                f"{path.name}: M4 generated range differs from recomputed tables "
                f"({len(shown)} lines in file, {len(expected.splitlines())} expected)"
            )
            for number, (have, want) in enumerate(
                zip(shown, expected.splitlines(), strict=False), 1
            ):
                if have != want:
                    problems.append(f"  first difference at {path.name} range line {number}")
                    break
    return problems, m4


def write_m4(
    root: Path,
    readme: Path,
    m4: Mapping,
    note: Path | None = None,
    notes: Sequence[Path] | None = None,
) -> None:
    for path, markers, kind in m4_documents(root, readme, note, notes):
        text = _read_readme(path)
        start, stop = _split_readme(text, path.name, markers)
        path.write_text(
            text[:start] + "\n\n" + _render_m4_range(kind, m4) + "\n" + text[stop:],
            encoding="utf-8",
        )


def m4_active(root: Path, readme: Path) -> bool:
    """`results/m4/`가 있거나 README가 M4 구간 마커를 갖고 있으면 M4를 검증한다(데이터가 사라져도 통과하지 않는다)."""
    if (root / M4_DIR).is_dir():
        return True
    try:
        return README_M4[0] in readme.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return False


# ------------------------------------------------------------ M5: 생성 평가 저장본, 표, 검증


def _m5_fmt(value: float | None, digits: int = 3) -> str:
    return "-" if value is None else f"{value:.{digits}f}"


def _m5_int(value: float | None) -> str:
    return "-" if value is None else f"{value:.0f}"


def _m5_seconds(value_ms: float | None) -> str:
    return "-" if value_ms is None else f"{value_ms / 1000:.2f}"


def load_m5(root: Path) -> dict:
    """M5 입력(생성·판정 저장본)과 저장본 검사 결과. 입력 파일 문제는 CheckError.

    `{"generation", "judgments", "topk", "summary", "rows", "problems"}`. problems는 저장본 검사
    (`pipeline.check_stored`, `judge_gen.check_stored`)와 입력 해시 대조의 실패 항목이다. problems가 있으면
    topk·summary·rows는 None이고 표를 만들 수 없다."""
    for relative in M5_FILES:
        if not (root / relative).is_file():
            raise CheckError(f"missing required file: {relative.as_posix()}")
    generation = _read_json(
        root / M5_GENERATION / "manifest.json", "results/m5/generation/manifest.json"
    )
    judgments = _read_json(
        root / M5_JUDGMENTS / "manifest.json", "results/m5/judgments/manifest.json"
    )
    problems: list[str] = []
    try:
        # 고정 구성: 트랙 2개 x k 3개. manifest에서 빠진 (트랙, k)의 파일은 저장본 검사 대상에서 빠지므로 여기서 먼저 본다
        wanted_outputs = {f"k{k}" for k in pipeline.KS}
        if set(generation["tracks"]) != set(data.TRACKS):
            problems.append(
                f"{M5_PROBLEM} generation manifest tracks differ from {list(data.TRACKS)}"
            )
        for track, block in generation["tracks"].items():
            if set(block["outputs"]) != wanted_outputs:
                problems.append(
                    f"{M5_PROBLEM} generation manifest {track} outputs "
                    f"{sorted(block['outputs'])} differ from {sorted(wanted_outputs)}"
                )
        if set(judgments["tracks"]) != set(data.TRACKS):
            problems.append(
                f"{M5_PROBLEM} judgments manifest tracks differ from {list(data.TRACKS)}"
            )
        if problems:  # 구성이 틀리면 아래 저장본 검사가 KeyError로 멈추기 전에 이 사유를 보고한다
            return {
                "generation": generation,
                "judgments": judgments,
                "topk": None,
                "summary": None,
                "rows": None,
                "problems": problems,
            }
        for track, block in generation["tracks"].items():
            try:
                _check_inputs(root, f"m5 generation {track}", block)
            except CheckError as error:
                problems.append(f"{M5_PROBLEM} {error}")
        problems += [
            f"{M5_PROBLEM} generation: {item}"
            for item in pipeline.check_stored(root, root / M5_GENERATION)
        ]
        problems += [
            f"{M5_PROBLEM} judgments: {item}"
            for item in judge_gen.check_stored(root, root / M5_JUDGMENTS, require_complete=True)
        ]
        if problems:
            return {
                "generation": generation,
                "judgments": judgments,
                "topk": None,
                "summary": None,
                "rows": None,
                "problems": problems,
            }
        stored = pipeline.load_stored_rows(root / M5_GENERATION, generation)
        questions = {track: data.load_questions(track, root) for track in generation["tracks"]}
        topk = pipeline.compute_topk(stored, questions)
        rows = {
            track: judge_gen.read_jsonl(root / M5_JUDGMENTS / block["file"])
            for track, block in judgments["tracks"].items()
        }
        summary = judge_gen.compute_summary(rows, topk)
    except (OSError, UnicodeDecodeError, ValueError, KeyError, TypeError, AttributeError) as error:
        raise CheckError(f"M5 results are malformed ({type(error).__name__})") from None
    m5 = {
        "generation": generation,
        "judgments": judgments,
        "topk": topk,
        "summary": summary,
        "rows": rows,
        "problems": [],
    }
    try:
        render_m5(m5, "")  # 표가 읽는 중첩 키가 없거나 형식이 틀리면 여기서 CheckError로 멈춘다
    except (KeyError, TypeError, ValueError, AttributeError, IndexError) as error:
        raise CheckError(f"M5 manifests are malformed ({type(error).__name__})") from None
    return m5


def _m5_config_rows(generation: Mapping, judgments: Mapping, summary: Mapping) -> list[str]:
    model, request = generation["model"], generation["request"]
    options = request["options"]
    tracks = generation["tracks"]
    retrieval = {
        track: f"{track} k1 {block['retrieval']['k1']}, b {block['retrieval']['b']}"
        for track, block in tracks.items()
    }
    cap = generation["context_rules"]["per_doc_char_cap"]
    judges = judgments["judges"]
    by_kind = judgments["calls"]["by_judge_kind"]
    retries = sum(item["n"] for item in by_kind if item["kind"] == "retry")
    judged = summary["tracks"]
    return [
        f"| 생성 모델 | `{model['name']}` ({model['parameter_size']}, {model['quantization']}, {model['license']}), Ollama {model['ollama_version']} |",
        f"| 모델 digest | `{model['digest']}` |",
        (
            f"| 요청 옵션 | temperature {options['temperature']}, seed {options['seed']}, num_ctx {options['num_ctx']}, "
            f"num_predict {options['num_predict']}, think {str(request['think']).lower()}, format {request['format']} |"
        ),
        f"| 프롬프트 sha256 / 실행 ID | `{generation['prompt']['sha256']}` / `{generation['run_id']}` |",
        f"| 검색 | BM25 (M2 선택 값, {'; '.join(retrieval.values())}), 문서당 {cap}자 상한 |",
        (
            "| 생성 질문 수 | "
            + ", ".join(f"{track} {block['n_questions']}" for track, block in tracks.items())
            + " (k 1, 3, 5) |"
        ),
        (
            f"| 판정자 | A `{judges['A']['model']}` ({judges['A']['vendor']}, {judges['A']['cli_version']}), "
            f"B `{judges['B']['model']}` ({judges['B']['vendor']}, {judges['B']['cli_version']}) |"
        ),
        (
            f"| 판정 범위 | k={judgments['k']}, "
            + ", ".join(
                f"{track} {'+'.join(splits)}"
                for track, splits in judgments["rules"]["scope"].items()
            )
            + " |"
        ),
        (
            "| 판정 대상 / 두 판정자 모두 유효 | "
            + ", ".join(
                f"{track} {stats['n_judged']} / {stats['n_valid_both']}"
                for track, stats in judged.items()
            )
            + " |"
        ),
        (
            f"| 판정자 호출 | {judgments['calls']['total']}회 (재질의 {retries}회), "
            f"한도 대기 {judgments['limit_waits']['n_events']}회, 상태 `{judgments['status']}` |"
        ),
    ]


def render_m5(m5: Mapping, link_prefix: str) -> str:
    """M5 구간(README·릴리스 노트용). 보고서 문서 링크는 `<link_prefix>m5-*.md`다."""
    gen, jm = m5["generation"], m5["judgments"]
    topk, summary, rows = m5["topk"], m5["summary"], m5["rows"]
    cells = {(c["track"], c["k"], c["split"], c["query_type"]): c for c in topk["cells"]}
    ks = sorted({key[1] for key in cells})
    link_gen = f"[m5-generation.md]({link_prefix}m5-generation.md)"
    link_eval = f"[m5-generation-eval.md]({link_prefix}m5-generation-eval.md)"
    lines = [
        M5_NOTE,
        "",
        f"### 실행 구성 ({link_gen}, {link_eval})",
        "",
        "| 항목 | 값 |",
        "|---|---|",
        *_m5_config_rows(gen, jm, summary),
    ]
    for track in data.TRACKS:
        total = cells[(track, ks[0], "all", "all")]["n_questions"]
        lines += [
            "",
            f"### top-k 기계 지표: {M5_TRACK_TITLES[track]}, {total}문항 dev+test ({link_gen})",
            "",
            (
                "| k | 계약 파싱 성공률 | 재질의 수 | 문맥 초과 | 올바른 기권률 | 잘못된 기권률 | 인용 적중률 "
                "| 무효 인용률 | 입력 토큰 중앙값 | 입력 토큰 최대 | 지연 중앙값(초) |"
            ),
            "|---|---|---|---|---|---|---|---|---|---|---|",
        ]
        for k in ks:
            c = cells[(track, k, "all", "all")]
            lines.append(
                f"| {k} | {_m5_fmt(c['parse_success_rate'])} | {c['n_retried']} | {c['n_context_overflow']} "
                f"| {_m5_fmt(c['correct_abstain_rate'])} | {_m5_fmt(c['false_abstain_rate'])} "
                f"| {_m5_fmt(c['citation_hit_rate'])} | {_m5_fmt(c['invalid_citation_rate'])} "
                f"| {_m5_int(c['prompt_tokens_median'])} | {_m5_int(c['prompt_tokens_max'])} "
                f"| {_m5_seconds(c['latency_ms_median'])} |"
            )
    scope = {track: judge_gen.SUMMARY_SPLITS[track][-1] for track in data.TRACKS}
    judged = [c for c in summary["cells"] if c["split"] == scope[c["track"]]]
    for axis, title in (
        (judge_gen.FAITHFULNESS, "faithfulness"),
        (judge_gen.CORRECTNESS, "정답성"),
    ):
        positive = judge_gen.POSITIVE[axis]
        lines += [
            "",
            f"### {title}: 두 판정자 교차 판정, k={jm['k']} ({link_eval})",
            "",
            f"| 트랙 (분할) | 유형 | 분모 | 확정 {positive} 비율 | 일치율 | 불일치율 | invalid | kappa |",
            "|---|---|---|---|---|---|---|---|",
        ]
        for c in judged:
            s = c[axis]
            if s["n"] == 0:
                continue
            lines.append(
                f"| {c['track']} ({c['split']}) | {c['query_type']} | {s['n']} "
                f"| {_m5_fmt(s['confirmed_positive_rate'])} | {_m5_fmt(s['agreement_rate'])} "
                f"| {_m5_fmt(s['disagreement_rate'])} | {s['n_invalid']} | {_m5_fmt(s['kappa']['value'])} |"
            )
    lines += [
        "",
        f"### 답 없음 처리와 판정 제외: k={jm['k']}, 기계 판정 ({link_eval})",
        "",
        "| 트랙 (분할) | 유형 | 행 수 | 판정 | 기권 제외 | 파싱 실패 제외 | 문맥 초과 제외 | 올바른 기권률 | 잘못된 기권률 | 인용 적중률 |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for c in judged:
        m = c["machine"] or {}
        lines.append(
            f"| {c['track']} ({c['split']}) | {c['query_type']} | {c['n_rows']} | {c['n_judged']} "
            f"| {c['n_skipped_abstain']} | {c['n_skipped_parse_failed']} | {c['n_skipped_context_overflow']} "
            f"| {_m5_fmt(m.get('correct_abstain_rate'))} | {_m5_fmt(m.get('false_abstain_rate'))} "
            f"| {_m5_fmt(m.get('citation_hit_rate'))} |"
        )
    lines += [
        "",
        "### 판정자 불일치 (확정되지 않은 질문-축 수)",
        "",
        "| 트랙 | 축 | 불일치 (`disagree`) | 무효 (`invalid`) |",
        "|---|---|---|---|",
    ]
    for track, track_rows in rows.items():
        for axis in judge_gen.AXES:
            decided = [r[axis] for r in track_rows if r["status"] == judge_gen.STATUS_JUDGED]
            lines.append(
                f"| {track} | {axis} | {decided.count(judge_gen.DISAGREE)} "
                f"| {decided.count(judge_gen.INVALID)} |"
            )
    return "\n".join(lines).rstrip() + "\n"


def m5_documents(
    root: Path, readme: Path, note: Path | None = None
) -> list[tuple[Path, tuple[str, str], str]]:
    return [
        (readme, README_M5, "readme"),
        (note or root / NOTE_V10_PATH, NOTE_M5_RANGE, "note"),
    ]


def _render_m5_range(kind: str, m5: Mapping) -> str:
    return render_m5(m5, "docs/" if kind == "readme" else "")


def verify_m5(root: Path, readme: Path, *, note: Path | None = None) -> tuple[list[str], Mapping]:
    """(불일치 목록, M5 입력). 저장본 검사와 README·v1.0 노트의 M5 구간을 본다.

    `root`는 M5 저장본과 질의셋을 읽는 곳(릴리스 asset 사본이면 그 사본)이다."""
    documents = []
    for path, markers, kind in m5_documents(
        root, readme, note
    ):  # 마커 오류는 입력을 읽기 전에 멈춘다
        text = _read_readme(path)
        documents.append((path, text, _split_readme(text, path.name, markers), kind))
    m5 = load_m5(root)
    problems = list(m5["problems"])
    if problems:
        return problems, m5
    for path, text, (start, stop), kind in documents:
        expected = _render_m5_range(kind, m5).strip()
        if text[start:stop].strip() != expected:
            shown = text[start:stop].strip().splitlines()
            problems.append(
                f"{path.name}: M5 generated range differs from recomputed tables "
                f"({len(shown)} lines in file, {len(expected.splitlines())} expected)"
            )
            for number, (have, want) in enumerate(
                zip(shown, expected.splitlines(), strict=False), 1
            ):
                if have != want:
                    problems.append(f"  first difference at {path.name} range line {number}")
                    break
    return problems, m5


def write_m5(root: Path, readme: Path, m5: Mapping, note: Path | None = None) -> None:
    for path, markers, kind in m5_documents(root, readme, note):
        text = _read_readme(path)
        start, stop = _split_readme(text, path.name, markers)
        path.write_text(
            text[:start] + "\n\n" + _render_m5_range(kind, m5) + "\n" + text[stop:],
            encoding="utf-8",
        )


def m5_active(root: Path, readme: Path) -> bool:
    """`results/m5/`가 있거나 README가 M5 구간 마커를 갖고 있으면 M5를 검증한다(데이터가 사라져도 통과하지 않는다)."""
    if (root / M5_DIR).is_dir():
        return True
    try:
        return README_M5[0] in readme.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return False


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="README를 쓰지 않고 검증만 한다")
    parser.add_argument(
        "--root", type=Path, default=ROOT, help="리포 루트(기본: 이 스크립트의 리포)"
    )
    parser.add_argument("--readme", type=Path, help="README 경로(기본: <root>/README.md)")
    parser.add_argument(
        "--summary", type=Path, help="M3 요약 경로(기본: <root>/docs/experiments/summary.md)"
    )
    parser.add_argument(
        "--note", type=Path, help="v0.2 노트 경로(기본: <root>/docs/release-v0.2.md)"
    )
    parser.add_argument(
        "--note-v03",
        type=Path,
        help="v0.3 노트 경로(기본: <root>/docs/release-v0.3.md). M4가 켜졌을 때만 쓴다",
    )
    parser.add_argument(
        "--note-v10",
        type=Path,
        help="v1.0 노트 경로(기본: <root>/docs/release-v1.0.md). M5가 켜졌을 때만 쓴다",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = args.root.resolve()
    readme = args.readme.resolve() if args.readme else root / "README.md"
    summary = args.summary.resolve() if args.summary else None
    note = args.note.resolve() if args.note else None
    note_v03 = args.note_v03.resolve() if args.note_v03 else root / NOTE_V03_PATH
    note_v10 = args.note_v10.resolve() if args.note_v10 else root / NOTE_V10_PATH
    try:
        problems, recomputed = verify(root, readme)
        m3 = m4 = m5 = None
        m4_on = m4_active(root, readme)
        m5_on = m5_active(root, readme)
        notes = [
            note or root / NOTE_V02_PATH,
            *([note_v03] if m4_on else []),
            *([note_v10] if m5_on else []),
        ]
        if m3_active(root, readme):
            m3_problems, m3 = verify_m3(root, readme, summary=summary, notes=notes)
            problems += m3_problems
        if m4_on:
            m4_notes = [note_v03, *([note_v10] if m5_on else [])]
            m4_problems, m4 = verify_m4(root, readme, notes=m4_notes)
            problems += m4_problems
        if m5_on:
            m5_problems, m5 = verify_m5(root, readme, note=note_v10)
            problems += m5_problems
        if args.check:
            if problems:
                for problem in problems:
                    print(f"MISMATCH {problem}", file=sys.stderr)
                return 1
            extra = f", {len(m3)} experiments" if m3 is not None else ""
            print(
                f"OK: {len(recomputed['runs'])} runs{extra}, metrics.json and README tables match"
            )
            if m4 is not None:
                facts = m4["facts"]
                print(
                    f"OK: M4 {facts['target']} target ids, {facts['ok']} ok, "
                    f"{len(m4['idempotency']['steps'])} idempotency steps; "
                    f"reports, manifest, README and {', '.join(n.stem for n in m4_notes)} ranges match"
                )
            if m5 is not None:
                steps = m5["topk"]["cells"]
                print(
                    f"OK: M5 {len(m5['generation']['tracks'])} tracks x {len(pipeline.KS)} k "
                    f"({len(steps)} top-k cells), "
                    f"{sum(t['n_judged'] for t in m5['summary']['tracks'].values())} judged rows; "
                    "generation, judgments, README and release-v1.0 ranges match"
                )
            return 0
        if any(
            p.startswith(("metrics.json", "results/experiments", M4_PROBLEM, M5_PROBLEM))
            for p in problems
        ):
            for problem in problems:
                print(f"MISMATCH {problem}", file=sys.stderr)
            print(
                "error: metrics.json differs from recomputed values; README untouched",
                file=sys.stderr,
            )
            return 1
        write_readme(readme, recomputed)
        if m3 is not None:
            write_m3(root, readme, m3, summary, notes=notes)
        if m4 is not None:
            write_m4(root, readme, m4, notes=m4_notes)
        if m5 is not None:
            write_m5(root, readme, m5, note_v10)
        print(f"README tables updated ({len(recomputed['runs'])} runs)")
        return 0
    except CheckError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
