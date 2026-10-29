"""릴리스 v0.1 asset 목록 검사와 재현 결과 비교.

    uv run python scripts/check_release.py                        # docs/release-v0.1.md의 asset 목록 검사
    uv run python scripts/check_release.py --print-assets         # 리포 파일에서 asset 목록 표를 만들어 출력
    uv run python scripts/check_release.py --assets-dir DIR       # 내려받은 asset 파일(asset 이름)을 검사
    uv run python scripts/check_release.py --compare-results DIR  # run_baselines.py --out-dir DIR 결과와 비교

asset 목록 검사는 아래를 전부 확인하고 하나라도 어긋나면 종료 코드 1이다.

1. 목록의 모든 항목이 허용 목록에 있고, asset 이름이 리포 경로에서 정해진 이름이며, 파일이 있다.
2. `results/baselines/manifest.json`이 요구하는 원시 결과 파일(`stored_results.path`)과 질의셋(`inputs.queries`)이
   모두 목록에 있다.
3. asset 사본(임시 디렉터리에 복사)의 sha256이 목록과 같고 대응하는 리포 원본 파일의 sha256과 같다.
   manifest의 입력 해시도 리포 파일과 같다.
4. 허용 필드만 있다: 결과 파일은 질문 ID·문서 ID·순위·점수(와 지우기 전 1위 점수, 지운 문서 수)만, 질의·정답
   파일은 정해진 키만, 그 밖은 JSON manifest이고 긴 문자열(본문 인용 후보)이 없다.
5. asset 사본만으로 리포 레이아웃을 복원해 README 표를 다시 계산하면(scripts/make_readme_tables.py) README와 같다.

`--assets-dir DIR`을 주면 1, 3~5를 리포 파일이 아니라 DIR의 파일(노트 표의 asset 이름)에 대해 검사한다. 릴리스를
발행한 뒤 내려받은 파일을 검증하는 용도다. 목록에 없는 파일이 DIR에 있으면 실패하고, 리포 원본이 있으면 sha256도 대조한다.

`--compare-results`는 같은 입력으로 다시 돌린 결과(exact, BM25)가 커밋된 `results/baselines/<track>/`와 같은지
본다: 질문 ID 집합 동일, 문서 ID·순위 일치, 점수 abs 1e-9 이내. 실행 시각 같은 메타데이터는 비교하지 않는다.
"""

import argparse
import hashlib
import importlib.util
import json
import math
import re
import shutil
import sys
import tempfile
from collections.abc import Iterable
from pathlib import Path

from krsec_rag_lab.baselines import scoring

ROOT = Path(__file__).resolve().parents[1]
NOTE_PATH = Path("docs/release-v0.1.md")
BEGIN = "<!-- BEGIN ASSETS (scripts/check_release.py --print-assets) -->"
END = "<!-- END ASSETS -->"
RESULTS_DIR = Path("results/baselines")
ATOL = 1e-9
MAX_STRING_CHARS = 500  # JSON asset의 문자열 한 개 상한. 공지 본문 조각이 들어오면 넘는다

RESULT_PATH = re.compile(r"results/baselines/(public|kisa)/(exact|bm25|dense)\.jsonl")
ROW = re.compile(
    r"^\| `(?P<name>[^`]+)` \| `(?P<path>[^`]+)` \| (?P<size>\d+) \| `(?P<sha>[0-9a-f]{64})` \|$"
)
QUERY_KEYS = {"id", "query", "query_type", "gold", "unjudged", "split", "vendor_product"}
GOLDEN_KEYS = {
    "answers",
    "cve_ids",
    "excluded",
    "no_answer_reason",
    "query",
    "query_type",
    "question_id",
    "split",
    "surface_cve",
    "unjudged",
}
GOLDEN_OPTIONAL = {"no_answer_reason"}  # no_answer 질문에만 있다
GOLDEN_ANSWER_KEYS = {"doc_id", "doc_sha256", "evidence", "reason"}
GOLDEN_EVIDENCE_KEYS = {"end", "judge", "parser_version", "start"}
GOLDEN_REASON = re.compile(r"^[A-Z]:[a-z_]+( [A-Z]:[a-z_]+)*$")
METADATA_KEYS = {"url", "title", "date", "nttId", "cve_ids"}

# asset으로 낼 수 있는 파일과 그 허용 필드 검사 종류. 이 밖의 경로는 목록에 있으면 실패다.
JSON_ASSETS = (
    "results/baselines/manifest.json",
    "results/baselines/metrics.json",
    "eval/public/manifest.json",
    "eval/golden/judge_manifest.json",
    "eval/golden/agreement.json",
    "eval/golden/error_rates.json",
    "fixtures/kisa/manifest.json",
    "fixtures/nvd/manifest.json",
)
OTHER_ASSETS = {
    "eval/public/queries.jsonl": "queries",
    "eval/golden/golden_v1.jsonl": "golden",
    "fixtures/kisa/metadata.jsonl": "metadata",
}


def load_sibling(name: str):
    """scripts/<name>.py를 모듈로 읽는다(`python scripts/check_release.py`와 pytest 양쪽에서 같다)."""
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def asset_name(path: str) -> str:
    return path.replace("/", "__")


def asset_kind(path: str) -> str | None:
    if RESULT_PATH.fullmatch(path):
        return "result"
    if path in JSON_ASSETS:
        return "json"
    return OTHER_ASSETS.get(path)


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def required_paths(root: Path) -> list[str]:
    """manifest가 요구하는 원시 결과 파일과 질의셋. 이 파일들은 asset 목록에 반드시 있어야 한다."""
    manifest = json.loads((root / RESULTS_DIR / "manifest.json").read_text(encoding="utf-8"))
    paths = {(RESULTS_DIR / "manifest.json").as_posix(), (RESULTS_DIR / "metrics.json").as_posix()}
    for entry in manifest["runs"].values():
        paths.add(entry["stored_results"]["path"])
        paths.add(entry["inputs"]["queries"]["path"])
    return sorted(paths)


def default_assets(root: Path) -> list[str]:
    """리포에 있는 허용 asset 전부(필수 파일 포함), 목록에 낼 순서."""
    allowed = {*JSON_ASSETS, *OTHER_ASSETS, *required_paths(root)}
    return sorted(p for p in allowed if asset_kind(p) and (root / p).is_file())


def render_asset_table(root: Path, paths: Iterable[str]) -> str:
    lines = ["| asset 이름 | 리포 경로 | 크기(바이트) | sha256 |", "|---|---|---|---|"]
    for path in paths:
        full = root / path
        lines.append(
            f"| `{asset_name(path)}` | `{path}` | {full.stat().st_size} | `{sha256_of(full)}` |"
        )
    return "\n".join(lines) + "\n"


def parse_asset_table(note: str) -> list[dict]:
    if note.count(BEGIN) != 1 or note.count(END) != 1 or note.index(BEGIN) > note.index(END):
        raise ValueError("release note needs exactly one asset-list marker pair")
    block = note[note.index(BEGIN) + len(BEGIN) : note.index(END)]
    rows = []
    for line in block.strip().splitlines():
        if not line.strip() or line.startswith(("| asset", "|---")):
            continue
        match = ROW.match(line.strip())
        if match is None:
            raise ValueError(f"unparsable asset row: {line[:80]!r}")
        rows.append({**match.groupdict(), "size": int(match["size"])})
    if not rows:
        raise ValueError("asset list is empty")
    return rows


def _long_strings(value: object, limit: int = MAX_STRING_CHARS) -> int:
    if isinstance(value, str):
        return int(len(value) > limit)
    if isinstance(value, dict):
        return sum(_long_strings(v, limit) for v in value.values())
    if isinstance(value, list):
        return sum(_long_strings(v, limit) for v in value)
    return 0


def _jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def check_fields(kind: str, path: Path) -> list[str]:
    """한 asset의 허용 필드 위반 목록(비면 통과)."""
    problems: list[str] = []
    try:
        if kind == "json":
            payload = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(payload, dict):
                problems.append("not a json object")
            if n := _long_strings(payload):
                problems.append(f"{n} string(s) longer than {MAX_STRING_CHARS} chars")
            return problems
        rows = _jsonl(path)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        return [f"unreadable ({type(error).__name__})"]
    if not rows:
        return ["empty file"]
    for number, row in enumerate(rows, start=1):
        where = f"line {number}"
        if kind == "result":
            try:
                scoring.validate_record(row)  # 질문 ID·순위·문서 ID·점수 필드만
            except ValueError as error:
                problems.append(f"{where}: {error}")
        elif kind == "queries":
            if set(row) != QUERY_KEYS:
                problems.append(f"{where}: keys {sorted(set(row) ^ QUERY_KEYS)}")
        elif kind == "metadata":
            if set(row) != METADATA_KEYS:
                problems.append(f"{where}: keys {sorted(set(row) ^ METADATA_KEYS)}")
        elif kind == "golden":
            if not GOLDEN_KEYS - GOLDEN_OPTIONAL <= set(row) <= GOLDEN_KEYS:
                problems.append(f"{where}: keys {sorted(set(row) ^ GOLDEN_KEYS)}")
            for answer in row.get("answers", []):
                if set(answer) != GOLDEN_ANSWER_KEYS:
                    problems.append(
                        f"{where}: answer keys {sorted(set(answer) ^ GOLDEN_ANSWER_KEYS)}"
                    )
                    continue
                if not GOLDEN_REASON.fullmatch(str(answer["reason"])):
                    problems.append(f"{where}: reason is not a fixed code list")
                for item in answer["evidence"]:
                    if set(item) != GOLDEN_EVIDENCE_KEYS:
                        problems.append(
                            f"{where}: evidence keys {sorted(set(item) ^ GOLDEN_EVIDENCE_KEYS)}"
                        )
        if n := _long_strings(row):  # 결과 파일의 문서 ID·질문 ID에 본문이 실려도 걸린다
            problems.append(f"{where}: {n} string(s) longer than {MAX_STRING_CHARS} chars")
    return problems


def stage_assets(
    root: Path, rows: list[dict], staging: Path, assets_dir: Path | None = None
) -> tuple[Path, Path]:
    """asset 이름으로 사본을 만들고(`assets/`), 그 사본만으로 리포 레이아웃을 복원한다(`tree/`).

    `assets_dir`가 있으면 사본을 만들지 않고 그 디렉터리의 파일(업로드 뒤 내려받은 asset)을 쓴다."""
    tree = staging / "tree"
    if assets_dir is None:
        assets = staging / "assets"
        assets.mkdir(parents=True)
        for row in rows:
            shutil.copyfile(root / row["path"], assets / row["name"])
    else:
        assets = assets_dir
    for row in rows:
        target = tree / row["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(assets / row["name"], target)
    return assets, tree


def check_release(
    root: Path, note_path: Path | None = None, assets_dir: Path | None = None
) -> list[tuple[str, list[str]]]:
    """(검사 이름, 실패 목록) 목록. 실패 목록이 비면 그 검사는 통과다.

    `assets_dir`를 주면 존재·sha256·허용 필드·표 재생성을 리포 파일이 아니라 그 디렉터리의
    asset 파일(노트 표의 asset 이름)에 대해 검사한다. 리포 원본이 있으면 sha256도 대조한다."""
    note_path = note_path or root / NOTE_PATH
    results: list[tuple[str, list[str]]] = []

    def record(name: str, problems: list[str]) -> list[str]:
        results.append((name, problems))
        return problems

    try:
        rows = parse_asset_table(note_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        record("asset list parses", [str(error)])
        return results
    record("asset list parses", [])

    problems = []
    seen_paths: set[str] = set()
    for row in rows:
        path, name = row["path"], row["name"]
        if path in seen_paths:
            problems.append(f"duplicate asset path {path}")
        seen_paths.add(path)
        if asset_kind(path) is None:
            problems.append(f"{path}: not an allowed asset")
        if name != asset_name(path):
            problems.append(f"{path}: asset name {name!r} != {asset_name(path)!r}")
        if assets_dir is None and not (root / path).is_file():
            problems.append(f"{path}: file not found")
        if assets_dir is not None and not (assets_dir / name).is_file():
            problems.append(f"{name}: asset file not found in the assets dir")
    if len({row["name"] for row in rows}) != len(rows):
        problems.append("duplicate asset names")
    if assets_dir is not None:
        listed = {row["name"] for row in rows}
        problems += [
            f"{item.name}: file in the assets dir is not listed in the note"
            for item in sorted(assets_dir.iterdir())
            if item.name not in listed
        ]
    if record("listed assets exist and are allowed", problems):
        return results

    try:
        needed = required_paths(root)
    except (OSError, KeyError, TypeError, AttributeError, json.JSONDecodeError) as error:
        record("manifest-required files are listed", [f"manifest unreadable ({error!r})"])
        return results
    record(
        "manifest-required files are listed",
        [
            f"{path}: required by manifest.json but not listed"
            for path in needed
            if path not in seen_paths
        ],
    )

    problems = []
    with tempfile.TemporaryDirectory(prefix="krsec-release-") as tmp:
        assets, tree = stage_assets(root, rows, Path(tmp), assets_dir)
        for row in rows:
            copy_sha = sha256_of(assets / row["name"])
            if copy_sha != row["sha"]:
                problems.append(f"{row['name']}: listed sha256 != asset copy sha256")
            origin = root / row["path"]
            if origin.is_file() and copy_sha != sha256_of(origin):
                problems.append(f"{row['name']}: asset copy sha256 != repo file sha256")
            if (assets / row["name"]).stat().st_size != row["size"]:
                problems.append(f"{row['name']}: listed size != asset size")
        try:
            manifest = json.loads(
                (root / RESULTS_DIR / "manifest.json").read_text(encoding="utf-8")
            )
            for key, entry in manifest["runs"].items():
                for label, item in entry["inputs"].items():
                    origin = root / item["path"]
                    if origin.is_file() and sha256_of(origin) != item["sha256"]:
                        problems.append(f"{key} inputs.{label}: manifest sha256 != repo file")
        except (OSError, KeyError, TypeError, AttributeError, json.JSONDecodeError) as error:
            problems.append(f"manifest inputs unreadable ({type(error).__name__})")
        record("asset sha256 matches the repo files and manifest inputs", problems)

        problems = []
        for row in rows:
            for issue in check_fields(asset_kind(row["path"]) or "", assets / row["name"]):
                problems.append(f"{row['name']}: {issue}")
        record("only allowed fields", problems)

        tables = load_sibling("make_readme_tables")
        try:
            found, _ = tables.verify(tree, root / "README.md")
            problems = [f"README vs asset copy: {item}" for item in found]
        except tables.CheckError as error:
            problems = [f"README vs asset copy: {error}"]
        record("README tables rebuilt from the asset copies match", problems)
    return results


def _read_results(path: Path) -> dict[str, dict]:
    records: dict[str, dict] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line:
            continue
        row = json.loads(line)
        scoring.validate_record(row)
        if row["question_id"] in records:
            raise ValueError(f"duplicate question id {row['question_id']}")
        records[row["question_id"]] = row
    if not records:
        raise ValueError("empty results")
    return records


def compare_results(
    root: Path, other: Path, track: str, retrievers: Iterable[str], atol: float = ATOL
) -> list[str]:
    """`other/<track>/<retriever>.jsonl`이 커밋된 결과와 같은지 본다. 다른 점 목록(비면 같다)."""
    problems: list[str] = []
    for retriever in retrievers:
        name = f"{track}/{retriever}.jsonl"
        try:
            committed = _read_results(root / RESULTS_DIR / name)
            rerun = _read_results(other / name)
        except (OSError, ValueError, json.JSONDecodeError) as error:
            problems.append(f"{name}: {error}")
            continue
        if set(committed) != set(rerun):
            only = sorted(set(committed) ^ set(rerun))
            problems.append(f"{name}: question id sets differ ({len(only)}: {only[:3]})")
            continue
        for qid in sorted(committed):
            a, b = committed[qid], rerun[qid]
            ranked_a = [(item["rank"], item["doc_id"]) for item in a["results"]]
            ranked_b = [(item["rank"], item["doc_id"]) for item in b["results"]]
            if ranked_a != ranked_b:
                problems.append(f"{name}: {qid} doc ids or ranks differ")
                continue
            scores = [
                (x["score"], y["score"]) for x, y in zip(a["results"], b["results"], strict=True)
            ]
            if a["top1_score_raw"] is None or b["top1_score_raw"] is None:
                if a["top1_score_raw"] != b["top1_score_raw"]:
                    problems.append(f"{name}: {qid} top1_score_raw differs")
            else:
                scores.append((a["top1_score_raw"], b["top1_score_raw"]))
            if any(not math.isclose(x, y, rel_tol=0.0, abs_tol=atol) for x, y in scores):
                problems.append(f"{name}: {qid} score differs by more than {atol}")
            if a["n_unjudged_removed"] != b["n_unjudged_removed"]:
                problems.append(f"{name}: {qid} n_unjudged_removed differs")
    return problems


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--root", type=Path, default=ROOT, help="리포 루트(기본: 이 스크립트의 리포)"
    )
    parser.add_argument("--note", type=Path, help="릴리스 노트(기본: <root>/docs/release-v0.1.md)")
    parser.add_argument(
        "--assets-dir",
        type=Path,
        metavar="DIR",
        help="업로드 뒤 내려받은 asset 파일(노트 표의 asset 이름)이 있는 디렉터리. 주면 이 파일들을 검사한다",
    )
    parser.add_argument("--print-assets", action="store_true", help="asset 목록 표를 출력한다")
    parser.add_argument("--compare-results", type=Path, metavar="DIR", help="재실행 결과 디렉터리")
    parser.add_argument("--track", choices=("public", "kisa"), default="public")
    parser.add_argument("--retrievers", default="exact,bm25", help="쉼표로 구분(기본: exact,bm25)")
    parser.add_argument("--atol", type=float, default=ATOL, help="점수 허용 오차(기본 1e-9)")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = args.root.resolve()
    if args.print_assets:
        print(render_asset_table(root, default_assets(root)), end="")
        return 0
    if args.compare_results is not None:
        retrievers = [name for name in args.retrievers.split(",") if name]
        problems = compare_results(
            root, args.compare_results.resolve(), args.track, retrievers, args.atol
        )
        for problem in problems:
            print(f"DIFF {problem}", file=sys.stderr)
        if problems or not retrievers:
            return 1
        names = ", ".join(f"{args.track}/{r}" for r in retrievers)
        print(f"OK: {names} match the committed results (atol {args.atol})")
        return 0
    failed = False
    assets_dir = args.assets_dir.resolve() if args.assets_dir else None
    if assets_dir is not None and not assets_dir.is_dir():
        print(f"error: --assets-dir is not a directory: {args.assets_dir.name}", file=sys.stderr)
        return 1
    for name, problems in check_release(root, args.note, assets_dir):
        print(f"{'FAIL' if problems else 'OK  '} {name}")
        for problem in problems:
            print(f"     {problem}")
        failed = failed or bool(problems)
    print("check_release: FAILED" if failed else "check_release: OK")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
