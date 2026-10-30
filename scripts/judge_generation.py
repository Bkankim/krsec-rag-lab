"""생성 평가 교차 판정 CLI - k=3 답의 faithfulness·정답성을 두 모델이 따로 판정한다(이슈 #66).

    uv run python scripts/judge_generation.py --kisa-root <KISA-ROOT>                 # 전체 판정 + 산출물
    uv run python scripts/judge_generation.py --track public --limit 3 --out-dir <빈 디렉터리>   # 소표본(형식 확인)
    uv run python scripts/judge_generation.py --summary-only        # 모델·API·KISA 캐시 없이 저장본 검사 + summary.json 대조
    uv run python scripts/judge_generation.py --render-docs         # summary.json -> docs/m5-generation-eval.md 표

판정자: A `claude -p`(claude-opus-5-5), B `codex exec -s read-only`(gpt-6.1-sol). 호출 결과는 라벨·reason code·
요청 해시만 `--cache-dir`(기본 data/m5/judgments/cache, gitignore)에 쌓이고, 같은 요청은 다시 부르지 않는다.
사용량 한도 오류는 상태를 저장하고 메시지의 재시도 시각까지(없으면 40분) 기다렸다 같은 캐시로 재개한다.
KISA 문맥·근거 구간·생성 답변은 `--kisa-root` 아래 로컬 캐시에서 읽어 판정용 API로만 보내고 어떤 출력에도 쓰지 않는다.

종료 코드: 0 완료 / 1 미완료(유효율 90% 미만, 판정 대상 20건 미만, 입력 불일치, --summary-only 대조 실패) /
2 판정자 호출 실패(다시 실행하면 캐시에서 재개) / 3 한도 대기 횟수 초과(다시 실행하면 재개).
"""

import argparse
import importlib.util
import json
import sys
from collections.abc import Mapping
from pathlib import Path

from krsec_rag_lab import judge
from krsec_rag_lab.baselines import data
from krsec_rag_lab.generation import judge_gen

ROOT = Path(__file__).resolve().parents[1]
CACHE_DIR = Path("data/m5/judgments/cache")
STATE_NAME = "limit_events.json"


def load_kisa_module():
    """scripts/fetch_kisa.py를 모듈로 읽는다(실행하지 않는다: load_cached_body만 쓴다)."""
    if "fetch_kisa" in sys.modules:
        return sys.modules["fetch_kisa"]
    spec = importlib.util.spec_from_file_location("fetch_kisa", ROOT / "scripts" / "fetch_kisa.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--track", choices=data.TRACKS, nargs="+", default=list(data.TRACKS))
    parser.add_argument(
        "--kisa-root", type=Path, help="KISA 캐시(data/kisa)가 있는 체크아웃 루트(kisa 트랙 필수)"
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=judge_gen.JUDGMENT_DIR,
        help="결과 디렉터리(기본값 results/m5/judgments). 다른 경로를 주면 커밋본을 건드리지 않는다",
    )
    parser.add_argument(
        "--cache-dir",
        type=Path,
        default=CACHE_DIR,
        help="판정 호출 캐시 위치(라벨·코드·요청 해시만). 기본값 data/m5/judgments/cache (gitignore). 그 아래 설정 해시별 하위 디렉터리를 쓴다",
    )
    parser.add_argument("--jobs", type=int, default=3, help="판정자마다 동시에 보내는 호출 수")
    parser.add_argument(
        "--max-limit-waits",
        type=int,
        default=judge_gen.MAX_LIMIT_WAITS,
        help="판정자마다 사용량 한도 대기를 몇 번까지 기다렸다 재개할지(넘으면 exit 3, 다시 실행하면 재개)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        help="판정 대상 N개만 질문 유형을 돌려 가며 판정하는 소표본(--out-dir 필수)",
    )
    parser.add_argument(
        "--summary-only",
        action="store_true",
        help="저장본만으로 summary.json을 다시 계산해 커밋본과 대조한다(모델·API·KISA 캐시 불필요)",
    )
    parser.add_argument(
        "--render-docs",
        action="store_true",
        help="summary.json의 표를 docs/m5-generation-eval.md의 표시 구간에 옮긴다(실행 없음)",
    )
    return parser


def resolve(path: Path) -> Path:
    return (path if path.is_absolute() else ROOT / path).resolve()


def summary_only(out_dir: Path) -> int:
    committed = out_dir == resolve(judge_gen.JUDGMENT_DIR)
    problems = judge_gen.check_stored(ROOT, out_dir, require_complete=committed)
    if problems:
        for problem in problems:
            print(f"error: {problem}", file=sys.stderr)
        return 1
    manifest = json.loads((out_dir / "manifest.json").read_text(encoding="utf-8"))
    summary = json.loads((out_dir / "summary.json").read_text(encoding="utf-8"))
    print(
        json.dumps(
            {
                "status": manifest["status"],
                "generation_run_id": manifest["generation"]["run_id"],
                "tracks": summary["tracks"],
                "n_cells": len(summary["cells"]),
                "summary": "recomputed == stored (abs 1e-9)",
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


def progress(name: str, seconds: int) -> None:
    print(
        f"judge {name}: usage limit, waiting {seconds}s then resuming", file=sys.stderr, flush=True
    )


def main(argv: list[str] | None = None, *, judges: Mapping[str, judge.Judge] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    out_dir = resolve(args.out_dir)
    if args.render_docs:
        judge_gen.render_docs(ROOT, out_dir)
        print(f"{judge_gen.DOC_PATH} tables updated")
        return 0
    if args.summary_only:
        return summary_only(out_dir)
    if args.limit is not None and args.limit < 1:
        parser.error("--limit must be a positive integer")
    if args.limit is not None and out_dir == resolve(judge_gen.JUDGMENT_DIR):
        parser.error("--limit needs --out-dir (a sample must not overwrite the committed results)")
    if out_dir == resolve(judge_gen.JUDGMENT_DIR) and set(args.track) != set(data.TRACKS):
        parser.error(
            "the committed results hold both tracks; a single-track run needs --out-dir "
            "(otherwise the other track silently drops out of manifest.json and summary.json)"
        )
    if "kisa" in args.track and args.kisa_root is None:
        parser.error("--kisa-root is required for the kisa track")

    load_body = None
    kisa = None
    if "kisa" in args.track:
        kisa = load_kisa_module()
        kisa_root = args.kisa_root

        def load_body(ntt_id: str, document: Mapping[str, str]) -> str:
            return kisa.load_cached_body(kisa_root, ntt_id, document)

    generation_manifest = json.loads(
        (ROOT / judge_gen.GENERATION_DIR / "manifest.json").read_text(encoding="utf-8")
    )
    try:
        plans = {
            track: judge_gen.sample_items(
                judge_gen.plan_track(track, ROOT, kisa_root=args.kisa_root, load_body=load_body),
                args.limit,
            )
            for track in data.TRACKS
            if track in args.track
        }
    except judge_gen.InputMismatch as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    except Exception as error:
        # KisaError 메시지는 본문·경로를 담지 않는다(cache_missing, cache_hash_mismatch 등)
        if kisa is not None and isinstance(error, kisa.KisaError):
            print(f"error: {error}", file=sys.stderr)
            return 1
        raise
    for track, items in plans.items():
        n_judged = sum(item.task is not None for item in items)
        print(f"{track}: {len(items)} rows, {n_judged} to judge", file=sys.stderr, flush=True)

    judges = judges or judge_gen.default_judges()
    # CallCache.key는 시스템 프롬프트·스키마·플래그를 덮지 않는다: 설정마다 캐시 디렉터리를 나눠 옛 라벨이 새 설정으로 재사용되지 않게 한다
    cache_dir = resolve(args.cache_dir) / f"cfg-{judge_gen.cache_config_sha256(judges)[:12]}"
    cache = judge.CallCache(cache_dir)
    log = judge_gen.LimitLog(cache_dir / STATE_NAME)
    try:
        rows_by_track = judge_gen.judge_plans(
            plans,
            judges,
            cache,
            log,
            jobs=args.jobs,
            max_waits=args.max_limit_waits,
            on_wait=progress,
        )
    except judge.JudgeUnavailable as error:
        print(f"STOP: judge usage limit: {error} (rerun resumes from the cache)", file=sys.stderr)
        return 3
    except judge.JudgeError as error:
        print(f"error: judge call failed (rerun resumes from the cache): {error}", file=sys.stderr)
        return 2

    topk = json.loads((ROOT / judge_gen.GENERATION_DIR / "topk.json").read_text(encoding="utf-8"))
    summary = judge_gen.compute_summary(rows_by_track, topk)
    sample = args.limit is not None
    problems = [] if sample else judge_gen.gate_problems(summary)
    manifest = judge_gen.new_manifest(
        judges=judges,
        generation_manifest=generation_manifest,
        generation_dir=judge_gen.GENERATION_DIR,
        root=ROOT,
        rows_by_track=rows_by_track,
        cache=cache,
        events=log.events(),
        problems=problems,
        sample=sample,
    )
    judge_gen.write_outputs(out_dir, rows_by_track, summary, manifest)
    print(
        json.dumps(
            {
                "status": manifest["status"],
                "tracks": summary["tracks"],
                "calls": manifest["calls"]["total"],
                "limit_wait_seconds": manifest["limit_waits"]["total_wait_seconds"],
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    for problem in problems:
        print(f"INCOMPLETE: {problem}", file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
