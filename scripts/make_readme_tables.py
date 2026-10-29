"""README 결과 표를 원시 결과에서 다시 계산해 만들고, README·metrics.json과 맞는지 검증한다.

    uv run python scripts/make_readme_tables.py            # README의 생성 구간 마커 사이를 다시 쓴다
    uv run python scripts/make_readme_tables.py --check    # 쓰지 않고 검증만 한다(일치 0, 아니면 1)

표의 숫자는 `results/baselines/manifest.json`이 가리키는 질문별 원시 결과(jsonl)와 `eval/**` 정답에서
`src/krsec_rag_lab/metrics.py`와 규약 v2 채점(condensed list)으로 다시 계산한 값이다. 이 값이
`results/baselines/metrics.json`과 모두 같고(abs 1e-9), README의 생성 구간이 이 값으로 만든 표와
같을 때만 검증이 통과한다. 필수 파일 누락, 빈 입력, 질문 ID 누락·중복·초과, 입력 해시 불일치는
비교하기 전에 종료 코드 1로 멈춘다. 결과 값은 어디에도 고치지 않는다(쓰는 곳은 README 생성 구간뿐이다).

`--root`로 리포 루트를 바꿀 수 있다(릴리스 asset 사본 검증용, scripts/check_release.py). README는 기본으로
`<root>/README.md`이고 `--readme`로 따로 정할 수 있다.
"""

import argparse
import json
import math
import sys
from collections.abc import Mapping
from pathlib import Path, PurePosixPath

from krsec_rag_lab.baselines import data, scoring
from krsec_rag_lab.baselines.runner import RETRIEVERS

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


def _split_readme(text: str, label: str) -> tuple[int, int]:
    """README에서 BEGIN 끝 위치와 END 시작 위치. 마커가 없거나 순서·개수가 틀리면 CheckError."""
    if text.count(BEGIN) != 1 or text.count(END) != 1:
        raise CheckError(f"{label}: needs exactly one generated-table marker pair")
    start, stop = text.index(BEGIN) + len(BEGIN), text.index(END)
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="README를 쓰지 않고 검증만 한다")
    parser.add_argument(
        "--root", type=Path, default=ROOT, help="리포 루트(기본: 이 스크립트의 리포)"
    )
    parser.add_argument("--readme", type=Path, help="README 경로(기본: <root>/README.md)")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = args.root.resolve()
    readme = args.readme.resolve() if args.readme else root / "README.md"
    try:
        problems, recomputed = verify(root, readme)
        if args.check:
            if problems:
                for problem in problems:
                    print(f"MISMATCH {problem}", file=sys.stderr)
                return 1
            print(f"OK: {len(recomputed['runs'])} runs, metrics.json and README tables match")
            return 0
        if any(p.startswith("metrics.json") for p in problems):
            for problem in problems:
                print(f"MISMATCH {problem}", file=sys.stderr)
            print(
                "error: metrics.json differs from recomputed values; README untouched",
                file=sys.stderr,
            )
            return 1
        write_readme(readme, recomputed)
        print(f"README tables updated ({len(recomputed['runs'])} runs)")
        return 0
    except CheckError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
