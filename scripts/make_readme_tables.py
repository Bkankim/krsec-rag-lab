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
from krsec_rag_lab.experiments import ExperimentError, harness
from krsec_rag_lab.experiments import compare as cmp

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
    root: Path, readme: Path, summary: Path | None = None, note: Path | None = None
) -> list[tuple[Path, tuple[str, str], str]]:
    """(문서 경로, 마커 쌍, 구간 종류). 문서를 따로 정하지 않으면 `<root>` 아래 고정 경로다."""
    return [
        (readme, README_M3, "readme"),
        (summary or root / SUMMARY_PATH, SUMMARY_RANGE, "summary"),
        (note or root / NOTE_V02_PATH, NOTE_RANGE, "note"),
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
) -> tuple[list[str], Mapping[str, Mapping]]:
    """(불일치 목록, 다시 계산한 M3 값). 저장된 metrics·comparison과 세 문서의 생성 구간을 대조한다.

    `root`는 원시 결과·라벨을 읽는 곳(릴리스 asset 사본이면 그 사본), 문서 경로는 따로 줄 수 있다."""
    documents = []
    for path, markers, kind in m3_documents(
        root, readme, summary, note
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
) -> None:
    for path, markers, kind in m3_documents(root, readme, summary, note):
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
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = args.root.resolve()
    readme = args.readme.resolve() if args.readme else root / "README.md"
    summary = args.summary.resolve() if args.summary else None
    note = args.note.resolve() if args.note else None
    try:
        problems, recomputed = verify(root, readme)
        m3 = None
        if m3_active(root, readme):
            m3_problems, m3 = verify_m3(root, readme, summary=summary, note=note)
            problems += m3_problems
        if args.check:
            if problems:
                for problem in problems:
                    print(f"MISMATCH {problem}", file=sys.stderr)
                return 1
            extra = f", {len(m3)} experiments" if m3 is not None else ""
            print(
                f"OK: {len(recomputed['runs'])} runs{extra}, metrics.json and README tables match"
            )
            return 0
        if any(p.startswith(("metrics.json", "results/experiments")) for p in problems):
            for problem in problems:
                print(f"MISMATCH {problem}", file=sys.stderr)
            print(
                "error: metrics.json differs from recomputed values; README untouched",
                file=sys.stderr,
            )
            return 1
        write_readme(readme, recomputed)
        if m3 is not None:
            write_m3(root, readme, m3, summary, note)
        print(f"README tables updated ({len(recomputed['runs'])} runs)")
        return 0
    except CheckError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
