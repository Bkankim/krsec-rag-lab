"""로컬 LLM 생성 실행 CLI - 트랙 x k(1, 3, 5)마다 검색 -> 생성 -> 결과 행 -> top-k 지표.

    ollama serve                                  # 별도 프로세스로 띄워 둔다(이 스크립트는 서버를 켜지 않는다)
    uv run python scripts/run_generation.py --track public --k 1 3 5
    uv run python scripts/run_generation.py --track kisa --kisa-root <KISA-ROOT> --k 1 3 5
    uv run python scripts/run_generation.py --metrics-only          # 모델·Ollama·KISA 캐시 없이 저장본 검사
    uv run python scripts/run_generation.py --render-docs           # topk.json -> docs/m5-generation.md 표
    uv run python scripts/run_generation.py --track public --k 3 --limit 5 --out-dir <빈 디렉터리>   # 소표본

결과: results/m5/generation/{manifest.json, <track>_k<k>.jsonl, topk.json}. KISA 트랙의 답변 원문은
`<KISA-ROOT>/data/m5/generation/kisa_k<k>.jsonl`(gitignore)에만 쓰고, 커밋 행에는 `answer`가 없다.
`--metrics-only`는 저장본의 행 키·질문 집합·성공률·해시를 검사하고 topk.json을 다시 계산해 커밋본과
대조한다(abs 1e-9, 다르면 exit 1). 계약 파싱 성공률이 (트랙, k)마다 80% 미만이면 그 실행은 exit 1이다.
KISA 본문은 --kisa-root 아래 data/kisa에서 fetch_kisa.load_cached_body로만 읽고 어떤 출력에도 쓰지 않는다.
"""

import argparse
import importlib.util
import json
import sys
import time
from collections.abc import Mapping
from pathlib import Path

from krsec_rag_lab.baselines import data
from krsec_rag_lab.generation import llm as llm_module
from krsec_rag_lab.generation import pipeline

ROOT = Path(__file__).resolve().parents[1]


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


def local_cache_dir(track: str, kisa_root: Path | None, limit: int | None) -> Path:
    """답변 원문이 든 로컬 캐시 디렉터리. 항상 gitignore된 `data/` 아래이고 소표본은 `_sample`로 따로 둔다."""
    base = (kisa_root if track == "kisa" and kisa_root is not None else ROOT) / "data/m5/generation"
    return base / "_sample" if limit is not None else base


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--track", choices=data.TRACKS)
    parser.add_argument("--k", type=int, nargs="+", default=list(pipeline.KS), choices=pipeline.KS)
    parser.add_argument(
        "--kisa-root", type=Path, help="KISA 캐시(data/kisa)가 있는 체크아웃 루트(kisa 트랙 필수)"
    )
    parser.add_argument("--model", default=llm_module.DEFAULT_MODEL)
    parser.add_argument("--host", default=llm_module.DEFAULT_HOST)
    parser.add_argument(
        "--keep-alive",
        default=None,
        help="Ollama keep_alive(예: 0이면 요청마다 모델을 내려 KV 캐시를 쓰지 않는다)",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=pipeline.RESULTS_DIR,
        help="결과를 쓸 디렉터리(기본값: results/m5/generation). 다른 경로를 주면 커밋본을 건드리지 않는다",
    )
    parser.add_argument(
        "--limit",
        type=int,
        help="질문을 고르게 N개만 돌리는 소표본(성공률 하한을 적용하지 않는다). --out-dir 필수",
    )
    parser.add_argument(
        "--render-docs",
        action="store_true",
        help="topk.json의 표를 docs/m5-generation.md의 표시 구간에 옮긴다(실행 없음)",
    )
    parser.add_argument(
        "--metrics-only",
        action="store_true",
        help="저장본만으로 topk.json을 다시 계산해 커밋본과 대조한다(모델·Ollama·KISA 캐시 불필요)",
    )
    return parser


def progress_printer(track: str, k: int):
    started = time.perf_counter()

    def report(position: int, total: int, row: Mapping) -> None:
        if position % 10 == 0 or position == total:
            elapsed = time.perf_counter() - started
            print(
                f"{track} k={k} {position}/{total} elapsed={elapsed:.0f}s last={row['status']}",
                file=sys.stderr,
                flush=True,
            )

    return report


def metrics_only(out_dir: Path) -> int:
    problems = pipeline.check_stored(ROOT, out_dir)
    if problems:
        for problem in problems:
            print(f"error: {problem}", file=sys.stderr)
        return 1
    manifest = pipeline.load_manifest(out_dir)
    assert manifest is not None
    topk = json.loads((out_dir / "topk.json").read_text(encoding="utf-8"))
    print(
        json.dumps(
            {
                "run_id": manifest["run_id"],
                "tracks": {t: sorted(b["outputs"]) for t, b in manifest["tracks"].items()},
                "n_cells": len(topk["cells"]),
                "topk": "recomputed == stored (abs 1e-9)",
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    out_dir = args.out_dir if args.out_dir == pipeline.RESULTS_DIR else args.out_dir.resolve()
    if out_dir == pipeline.RESULTS_DIR:
        out_dir = ROOT / pipeline.RESULTS_DIR
    if args.render_docs:
        pipeline.render_docs(ROOT, out_dir)
        print("docs/m5-generation.md tables updated")
        return 0
    if args.metrics_only:
        return metrics_only(out_dir)
    if args.track is None:
        parser.error("--track is required unless --metrics-only")
    if args.limit is not None and args.limit < 1:
        parser.error("--limit must be a positive integer")
    if args.limit is not None and out_dir == ROOT / pipeline.RESULTS_DIR:
        parser.error("--limit needs --out-dir (a sample must not overwrite the committed results)")
    load_body = None
    kisa = None
    if args.track == "kisa":
        if args.kisa_root is None:
            parser.error("--kisa-root is required for the kisa track")
        kisa = load_kisa_module()
        kisa_root = args.kisa_root

        def load_body(ntt_id: str, document: Mapping[str, str]) -> str:
            return kisa.load_cached_body(kisa_root, ntt_id, document)

    local_dir = local_cache_dir(args.track, args.kisa_root, args.limit)

    llm = llm_module.OllamaLLM(model=args.model, host=args.host, keep_alive=args.keep_alive)
    try:
        model = llm_module.model_info(args.model, args.host)
        index = pipeline.build_index(args.track, ROOT, load_body)
        questions = pipeline.sample_questions(
            pipeline.expected_questions(args.track, ROOT), args.limit
        )
        repro = pipeline.check_token_repro(index, questions, max(args.k), llm)
        print(f"token repro check: {json.dumps(repro)}", file=sys.stderr, flush=True)
        if not repro["identical"]:
            raise pipeline.TokenReproError(
                "prompt_eval_count differs for the same prompt (prefix cache reuse?); "
                "rerun with --keep-alive 0"
            )
        manifest = pipeline.load_manifest(out_dir)
        fresh = pipeline.new_manifest(model, llm, ROOT, repro)
        if manifest is not None and manifest["run_id"] != fresh["run_id"]:
            raise pipeline.GateFailure(
                f"{out_dir.name}/manifest.json has run_id {manifest['run_id']} but this run is "
                f"{fresh['run_id']} (model, options, prompt or retrieval config changed)"
            )
        if manifest is None:
            manifest = fresh
        else:
            manifest.update({key: fresh[key] for key in ("created_at", "environment", "model")})
            manifest["token_counting"] = fresh["token_counting"]
        for k in args.k:
            pipeline.run_track(
                args.track,
                [k],
                ROOT,
                index,
                llm,
                manifest,
                out_dir,
                local_dir,
                limit=args.limit,
                on_row=progress_printer(args.track, k),
            )
            pipeline.write_json(out_dir / "manifest.json", manifest)
            pipeline.write_json(
                out_dir / "topk.json", pipeline.recompute_topk(ROOT, out_dir, manifest)
            )
    except (
        llm_module.LLMError,
        pipeline.GateFailure,
        pipeline.TokenReproError,
        pipeline.CacheConflict,
    ) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    except Exception as error:
        # KisaError 메시지는 본문·경로를 담지 않는다(cache_missing, cache_hash_mismatch 등)
        if kisa is not None and isinstance(error, kisa.KisaError):
            print(f"error: {error}", file=sys.stderr)
            return 1
        raise
    print(json.dumps(summary(manifest), ensure_ascii=False, indent=2))
    return 0


def summary(manifest: Mapping) -> dict:
    return {
        "run_id": manifest["run_id"],
        "tracks": {
            track: {key: out["parse_success_rate"] for key, out in block["outputs"].items()}
            for track, block in manifest["tracks"].items()
        },
    }


if __name__ == "__main__":
    sys.exit(main())
