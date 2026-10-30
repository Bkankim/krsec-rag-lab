"""릴리스(v0.1, v0.2, v0.3, v1.0) asset 목록 검사와 재현 결과 비교.

    uv run python scripts/check_release.py                        # docs/release-v0.1.md의 asset 목록 검사
    uv run python scripts/check_release.py --note docs/release-v0.2.md   # v0.2 노트의 asset 목록 검사
    uv run python scripts/check_release.py --print-assets         # 리포 파일에서 asset 목록 표를 만들어 출력
    uv run python scripts/check_release.py --print-assets --note docs/release-v0.2.md   # v0.2 목록
    uv run python scripts/check_release.py --note docs/release-v0.3.md   # v0.3 노트의 asset 목록 검사
    uv run python scripts/check_release.py --note docs/release-v1.0.md   # v1.0 노트의 asset 목록 검사
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

v0.2 노트(`--note`의 파일 이름이 `release-v0.2.md`)는 같은 검사에 아래를 더한다. v0.1 노트는 아래 항목을 허용하지 않는다.

- 허용 asset에 `results/experiments/<exp>/`의 원시 결과(`<track>/<variant>.jsonl`, `scoring.validate_record`),
  `manifest.json`·`metrics.json`·`comparison.json`(JSON, 긴 문자열 없음, 절대 경로 모양의 문자열 없음),
  한영 교차 `translations.jsonl`(정해진 키만)이 더해진다. 실험은 `make_readme_tables.EXPERIMENTS` 5개다.
- 필수 asset은 각 실험 manifest의 저장 결과 경로(`stored_results.path`), 재현 입력(`reproduction_inputs`), 입력
  파일 중 asset인 것, 그리고 실험 JSON 3종이다. 하나라도 목록에 없으면 실패한다.
- asset 사본만으로 M3 `metrics.json`·`comparison.json`을 하네스의 비교 함수로 다시 계산해 저장된 파일과 대조하고,
  README의 M3 판정 구간, `docs/experiments/summary.md`의 표 구간, 노트의 판정 구간을 그 값으로 만든 표와 대조한다.

v0.3 노트(`release-v0.3.md`)는 v0.2의 검사를 모두 물려받고(M3 asset 누락·변조도 실패) 아래를 더한다.

- 허용 asset에 `fixtures/kisa_full/{metadata.jsonl,manifest.json}`, `results/m4/collection/report.json`,
  `results/m4/idempotency/report.json`이 더해지고, 이 넷이 하나라도 목록에 없으면 실패한다.
- `kisa_full` 메타데이터는 `url`·`title`·`date`·`nttId`·`cve_ids`만 허용한다. manifest·보고서 JSON은 긴 문자열과
  `/`로 시작하는 모든 문자열(키 포함, POSIX 절대 경로)을 거부한다.
- asset 사본만으로 보고서·manifest·메타데이터끼리의 대조와 README, 노트의 M4 구간(`make_readme_tables.verify_m4`),
  README·summary·노트의 M3 구간을 다시 만들어 대조한다. 본문 유출 점검(KISA 캐시 필요)은 이 검사의 일이 아니다.

v1.0 노트(`release-v1.0.md`)는 v0.3의 필수 asset·검사를 모두 물려받고(M3·M4 asset 누락·변조도 실패) 아래를 더한다.

- 허용·필수 asset에 고정 목록 M5 파일 12개가 더해진다: `results/m5/generation/{manifest.json,topk.json,public_k1.jsonl,
  public_k3.jsonl,public_k5.jsonl,kisa_k1.jsonl,kisa_k3.jsonl,kisa_k5.jsonl}`,
  `results/m5/judgments/{manifest.json,summary.json,public.jsonl,kisa.jsonl}`. 파일과 노트 행을 함께 지워도 실패한다.
- M5 JSON(manifest, topk, summary)은 500자를 넘는 문자열과 `/`로 시작하는 모든 문자열(키 포함)을 거부한다. 생성 행의 키
  집합은 정확히 `pipeline.ROW_KEYS`(KISA)와 거기에 `answer`를 더한 것(공개만)이고, 판정 행의 키 집합은 정확히 판정 행 고정
  키 14개다. 알 수 없는 키, KISA 생성 행의 `answer`, 500자를 넘는 문자열(공개 `answer` 필드만 길이 예외), `/`로 시작하는 문자열은
  거부한다. 값 형식은 `pipeline.validate_row`, `judge_gen.validate_row`로 다시 본다.
- asset 사본만으로 M5 저장본 검사(`make_readme_tables.verify_m5`: 행 키·집합·해시, `topk.json`·`summary.json` 재계산 대조)와
  README, 노트의 M5 구간, README·노트의 M3·M4 구간을 다시 만들어 대조한다. 모델·Ollama·외부 API·KISA 캐시는 쓰지 않는다.

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
from krsec_rag_lab.generation import judge_gen, pipeline

ROOT = Path(__file__).resolve().parents[1]
NOTE_PATH = Path("docs/release-v0.1.md")
BEGIN = "<!-- BEGIN ASSETS (scripts/check_release.py --print-assets) -->"
END = "<!-- END ASSETS -->"
RESULTS_DIR = Path("results/baselines")
EXPERIMENTS_DIR = Path("results/experiments")
RELEASE_NOTE = re.compile(r"release-(v\d+\.\d+)\.md")
PROFILES = ("v0.1", "v0.2", "v0.3", "v1.0")
M3_PROFILES = ("v0.2", "v0.3", "v1.0")  # M3 실험 asset과 재계산 검사를 갖는 범위
M4_PROFILES = ("v0.3", "v1.0")  # M4 asset과 재계산 검사를 갖는 범위
M5_PROFILES = ("v1.0",)  # M5 asset과 저장본 검사를 갖는 범위
ATOL = 1e-9
MAX_STRING_CHARS = 500  # JSON asset의 문자열 한 개 상한. 공지 본문 조각이 들어오면 넘는다

RESULT_PATH = re.compile(r"results/baselines/(public|kisa)/(exact|bm25|dense)\.jsonl")
EXP_NAME = r"[a-z][a-z0-9_]*"
EXP_RESULT_PATH = re.compile(
    rf"results/experiments/(?P<exp>{EXP_NAME})/(public|kisa)/{EXP_NAME}\.jsonl"
)
EXP_JSON_PATH = re.compile(
    rf"results/experiments/(?P<exp>{EXP_NAME})/(manifest|metrics|comparison)\.json"
)
TRANSLATIONS_PATH = "results/experiments/crossling/translations.jsonl"
TRANSLATION_KEYS = {"model", "question_id", "revision", "source_sha256", "translation"}
ABSOLUTE_PATH = re.compile(r"^(/Users/|/home/|/private/|/var/folders/)")
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
M4_METADATA_PATH = "fixtures/kisa_full/metadata.jsonl"
M4_JSON_PATHS = (
    "fixtures/kisa_full/manifest.json",
    "results/m4/collection/report.json",
    "results/m4/idempotency/report.json",
)
M4_ASSETS = (M4_METADATA_PATH, *M4_JSON_PATHS)
# v1.0 필수 M5 asset: 고정 목록이다(manifest에서 유도하지 않는다). docs/m5-generation.md, docs/m5-generation-eval.md
M5_JSON_PATHS = (
    "results/m5/generation/manifest.json",
    "results/m5/generation/topk.json",
    "results/m5/judgments/manifest.json",
    "results/m5/judgments/summary.json",
)
M5_GENERATION_ROWS = {
    track: tuple(f"results/m5/generation/{track}_k{k}.jsonl" for k in (1, 3, 5))
    for track in ("public", "kisa")
}
M5_JUDGMENT_ROWS = ("results/m5/judgments/public.jsonl", "results/m5/judgments/kisa.jsonl")
M5_ASSETS = (
    *M5_JSON_PATHS[:2],
    *M5_GENERATION_ROWS["public"],
    *M5_GENERATION_ROWS["kisa"],
    *M5_JSON_PATHS[2:],
    *M5_JUDGMENT_ROWS,
)
# 행 허용 키: #65(생성 행), #66(판정 행) 본문의 고정 키 집합. 공개 생성 행만 `answer`를 더 갖는다.
M5_GENERATION_KEYS = frozenset(
    {
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
    }
)
M5_JUDGMENT_KEYS = frozenset(
    {
        "question_id",
        "split",
        "query_type",
        "status",
        "faithfulness_A",
        "faithfulness_B",
        "faithfulness",
        "correctness_A",
        "correctness_B",
        "correctness",
        "faithfulness_reason_A",
        "faithfulness_reason_B",
        "correctness_reason_A",
        "correctness_reason_B",
    }
)
M5_ROW_KINDS = ("m5_gen_public", "m5_gen_kisa", "m5_judge")

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


def experiments() -> tuple[str, ...]:
    """v0.2 릴리스가 담는 M3 실험(판정 표의 행 순서)."""
    return load_sibling("make_readme_tables").EXPERIMENTS


def profile_of(note_path: Path) -> str:
    """노트 파일 이름(`release-vX.Y.md`)이 정하는 검사 범위. 이름이 그 모양이 아니면 v0.1이다."""
    match = RELEASE_NOTE.fullmatch(note_path.name)
    profile = match[1] if match else "v0.1"
    if profile not in PROFILES:
        raise ValueError(f"unknown release profile {profile!r} (known: {', '.join(PROFILES)})")
    return profile


def asset_kind(path: str, profile: str = "v0.1") -> str | None:
    if RESULT_PATH.fullmatch(path):
        return "result"
    if path in JSON_ASSETS:
        return "json"
    if kind := OTHER_ASSETS.get(path):
        return kind
    if profile in M4_PROFILES:
        if path == M4_METADATA_PATH:
            return "metadata"
        if path in M4_JSON_PATHS:
            return "m4_json"
    if profile in M5_PROFILES:
        if path in M5_JSON_PATHS:
            return "m5_json"
        if path in M5_GENERATION_ROWS["public"]:
            return "m5_gen_public"
        if path in M5_GENERATION_ROWS["kisa"]:
            return "m5_gen_kisa"
        if path in M5_JUDGMENT_ROWS:
            return "m5_judge"
    if profile not in M3_PROFILES:
        return None
    if (match := EXP_RESULT_PATH.fullmatch(path)) and match["exp"] in experiments():
        return "result"
    if (match := EXP_JSON_PATH.fullmatch(path)) and match["exp"] in experiments():
        return "exp_json"
    return "translations" if path == TRANSLATIONS_PATH else None


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def experiment_manifest(root: Path, name: str) -> dict:
    return json.loads((root / EXPERIMENTS_DIR / name / "manifest.json").read_text(encoding="utf-8"))


def required_paths(root: Path, profile: str = "v0.1") -> list[str]:
    """manifest가 요구하는 원시 결과 파일과 질의셋. 이 파일들은 asset 목록에 반드시 있어야 한다.

    v0.2는 각 실험 manifest의 저장 결과 경로, 재현 입력(`reproduction_inputs`), 입력 파일 중 asset인 것과
    실험 JSON 3종을 더한다. v0.3은 v0.2의 것에 M4 파일 넷(`M4_ASSETS`)을, v1.0은 거기에 M5 파일 12개(`M5_ASSETS`)를 더한다."""
    manifest = json.loads((root / RESULTS_DIR / "manifest.json").read_text(encoding="utf-8"))
    paths = {(RESULTS_DIR / "manifest.json").as_posix(), (RESULTS_DIR / "metrics.json").as_posix()}
    for entry in manifest["runs"].values():
        paths.add(entry["stored_results"]["path"])
        paths.add(entry["inputs"]["queries"]["path"])
    if profile in M3_PROFILES:
        for name in experiments():
            for filename in ("manifest", "metrics", "comparison"):
                paths.add((EXPERIMENTS_DIR / name / f"{filename}.json").as_posix())
            for entry in experiment_manifest(root, name)["runs"].values():
                paths.add(entry["stored_results"]["path"])
                paths.update(item["path"] for item in entry["reproduction_inputs"].values())
                paths.update(
                    item["path"]
                    for item in entry["inputs"].values()
                    if asset_kind(item["path"], profile)
                )
    if profile in M4_PROFILES:
        paths.update(M4_ASSETS)
    if profile in M5_PROFILES:
        paths.update(M5_ASSETS)
    return sorted(paths)


def default_assets(root: Path, profile: str = "v0.1") -> list[str]:
    """리포에 있는 허용 asset 전부(필수 파일 포함), 목록에 낼 순서."""
    allowed = {*JSON_ASSETS, *OTHER_ASSETS, *required_paths(root, profile)}
    return sorted(p for p in allowed if asset_kind(p, profile) and (root / p).is_file())


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


def _absolute_paths(value: object) -> int:
    if isinstance(value, str):
        return int(ABSOLUTE_PATH.match(value) is not None)
    if isinstance(value, dict):
        return sum(_absolute_paths(v) for v in value.values())
    if isinstance(value, list):
        return sum(_absolute_paths(v) for v in value)
    return 0


def _bad_keys(value: object) -> int:
    """긴 문자열이거나 절대 경로 모양인 JSON 객체 키의 수(값 검사는 키를 보지 않는다)."""
    if isinstance(value, dict):
        own = sum(
            len(key) > MAX_STRING_CHARS or ABSOLUTE_PATH.match(key) is not None for key in value
        )
        return own + sum(_bad_keys(v) for v in value.values())
    if isinstance(value, list):
        return sum(_bad_keys(v) for v in value)
    return 0


def _slash_strings(value: object) -> int:
    """`/`로 시작하는 문자열(키 포함, 재귀)의 수. POSIX 절대 경로는 모두 걸린다."""
    if isinstance(value, str):
        return int(value.startswith("/"))
    if isinstance(value, dict):
        return sum(_slash_strings(k) + _slash_strings(v) for k, v in value.items())
    if isinstance(value, list):
        return sum(_slash_strings(v) for v in value)
    return 0


def m5_row_problems(kind: str, row: object, where: str = "row") -> list[str]:
    """M5 행 한 줄의 허용 필드 위반 목록. 키 집합은 정확히 같아야 하고(알 수 없는 키·KISA 생성 행의 `answer` 거부),
    `/`로 시작하는 문자열(공개 `answer` 포함)을 거부하며, 값 형식은 생성·판정 모듈의 `validate_row`로 다시 본다."""
    if not isinstance(row, dict):
        return [f"{where}: not a json object"]
    track = "public" if kind == "m5_gen_public" else "kisa"
    expected = (
        M5_JUDGMENT_KEYS
        if kind == "m5_judge"
        else M5_GENERATION_KEYS | ({"answer"} if kind == "m5_gen_public" else frozenset())
    )
    problems: list[str] = []
    if set(row) != expected:
        problems.append(f"{where}: keys {sorted(set(row) ^ expected)}")
    elif kind == "m5_judge":
        try:
            judge_gen.validate_row(row)
        except (ValueError, KeyError, TypeError) as error:
            problems.append(f"{where}: {error}")
    else:
        try:
            pipeline.validate_row(row, track)
        except (ValueError, KeyError, TypeError) as error:
            problems.append(f"{where}: {error}")
    # 공개 생성 행의 `answer`만 길이 예외다. 다른 필드에 본문이 실려도 걸린다
    measured = (
        {key: value for key, value in row.items() if key != "answer"}
        if kind == "m5_gen_public"
        else row
    )
    if n := _long_strings(measured):
        problems.append(f"{where}: {n} string(s) longer than {MAX_STRING_CHARS} chars")
    if n := _slash_strings(row):
        problems.append(f"{where}: {n} string(s) or key(s) starting with '/' (absolute path)")
    return problems


def check_fields(kind: str, path: Path) -> list[str]:
    """한 asset의 허용 필드 위반 목록(비면 통과)."""
    problems: list[str] = []
    try:
        if kind in ("json", "exp_json", "m4_json", "m5_json"):
            payload = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(payload, dict):
                problems.append("not a json object")
            if n := _long_strings(payload):
                problems.append(f"{n} string(s) longer than {MAX_STRING_CHARS} chars")
            if kind == "exp_json" and (n := _absolute_paths(payload)):
                problems.append(f"{n} string(s) shaped like an absolute path")
            if kind == "exp_json" and (n := _bad_keys(payload)):
                problems.append(
                    f"{n} key(s) longer than {MAX_STRING_CHARS} chars or shaped like an absolute path"
                )
            if kind in ("m4_json", "m5_json"):
                if n := _slash_strings(payload):
                    problems.append(f"{n} string(s) or key(s) starting with '/' (absolute path)")
                if n := _bad_keys(payload):
                    problems.append(
                        f"{n} key(s) longer than {MAX_STRING_CHARS} chars or shaped like an absolute path"
                    )
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
        elif kind == "translations":
            if set(row) != TRANSLATION_KEYS:
                problems.append(f"{where}: keys {sorted(set(row) ^ TRANSLATION_KEYS)}")
        elif kind == "metadata":
            if set(row) != METADATA_KEYS:
                problems.append(f"{where}: keys {sorted(set(row) ^ METADATA_KEYS)}")
        elif kind in M5_ROW_KINDS:
            problems += m5_row_problems(kind, row, where)
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
        if kind in M5_ROW_KINDS:  # M5 행은 m5_row_problems가 길이까지 본다(공개 `answer`만 예외)
            continue
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


def experiment_input_problems(root: Path) -> list[str]:
    """v0.2, v0.3: 실험 manifest의 입력·재현 입력 sha256이 리포 파일과 같은지(파일이 있는 입력만)."""
    problems: list[str] = []
    try:
        for name in experiments():
            for key, entry in experiment_manifest(root, name)["runs"].items():
                for group in ("inputs", "reproduction_inputs"):
                    for label, item in entry[group].items():
                        origin = root / item["path"]
                        if origin.is_file() and sha256_of(origin) != item["sha256"]:
                            problems.append(
                                f"{name} {key} {group}.{label}: manifest sha256 != repo file"
                            )
    except (OSError, KeyError, TypeError, AttributeError, json.JSONDecodeError) as error:
        problems.append(f"experiment manifest unreadable ({type(error).__name__})")
    return problems


def check_release(
    root: Path, note_path: Path | None = None, assets_dir: Path | None = None
) -> list[tuple[str, list[str]]]:
    """(검사 이름, 실패 목록) 목록. 실패 목록이 비면 그 검사는 통과다.

    `assets_dir`를 주면 존재·sha256·허용 필드·표 재생성을 리포 파일이 아니라 그 디렉터리의
    asset 파일(노트 표의 asset 이름)에 대해 검사한다. 리포 원본이 있으면 sha256도 대조한다."""
    note_path = note_path or root / NOTE_PATH
    results: list[tuple[str, list[str]]] = []
    try:
        profile = profile_of(note_path)
    except ValueError as error:
        return [("release profile", [str(error)])]

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
        if asset_kind(path, profile) is None:
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
        needed = required_paths(root, profile)
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
        if profile in M3_PROFILES:
            problems += experiment_input_problems(root)
        record("asset sha256 matches the repo files and manifest inputs", problems)

        problems = []
        for row in rows:
            for issue in check_fields(asset_kind(row["path"], profile) or "", assets / row["name"]):
                problems.append(f"{row['name']}: {issue}")
        record("only allowed fields", problems)

        tables = load_sibling("make_readme_tables")
        try:
            found, _ = tables.verify(tree, root / "README.md")
            problems = [f"README vs asset copy: {item}" for item in found]
        except tables.CheckError as error:
            problems = [f"README vs asset copy: {error}"]
        record("README tables rebuilt from the asset copies match", problems)

        if profile in M3_PROFILES:
            try:
                found, _ = tables.verify_m3(
                    tree,
                    root / "README.md",
                    summary=root / tables.SUMMARY_PATH,
                    note=note_path,
                )
                problems = [f"M3 vs asset copy: {item}" for item in found]
            except tables.CheckError as error:
                problems = [f"M3 vs asset copy: {error}"]
            record(
                "M3 metrics, comparison and tables rebuilt from the asset copies match", problems
            )

        if profile in M4_PROFILES:
            try:
                found, _ = tables.verify_m4(tree, root / "README.md", note=note_path)
                problems = [f"M4 vs asset copy: {item}" for item in found]
            except tables.CheckError as error:
                problems = [f"M4 vs asset copy: {error}"]
            record("M4 reports, manifest and tables rebuilt from the asset copies match", problems)

        if profile in M5_PROFILES:
            try:
                found, _ = tables.verify_m5(tree, root / "README.md", note=note_path)
                problems = [f"M5 vs asset copy: {item}" for item in found]
            except tables.CheckError as error:
                problems = [f"M5 vs asset copy: {error}"]
            record(
                "M5 generation, judgments and tables rebuilt from the asset copies match", problems
            )
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
    parser.add_argument(
        "--note",
        type=Path,
        help="릴리스 노트(기본: <root>/docs/release-v0.1.md). 파일 이름 release-v0.2.md, release-v0.3.md, release-v1.0.md는 그 버전의 검사 범위다",
    )
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
        try:
            profile = profile_of(args.note or Path(NOTE_PATH))
        except ValueError as error:
            print(f"error: {error}", file=sys.stderr)
            return 1
        print(render_asset_table(root, default_assets(root, profile)), end="")
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
