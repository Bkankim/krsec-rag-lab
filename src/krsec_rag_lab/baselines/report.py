"""metrics.json -> 사람이 읽는 표. docs/baselines.md의 표시 구간(BEGIN/END)을 이 출력으로 바꾼다.

표의 숫자는 results/baselines/metrics.json과 manifest.json에서만 오고, 문서의 서술은 사람이 쓴다.
"""

import json
from collections.abc import Mapping
from pathlib import Path

from krsec_rag_lab.baselines.data import QUERY_TYPES, SPLITS, TRACKS
from krsec_rag_lab.baselines.runner import RESULTS_DIR
from krsec_rag_lab.baselines.scoring import KS

DOC_PATH = Path("docs/baselines.md")
BEGIN = "<!-- BEGIN GENERATED TABLES (scripts/run_baselines.py --render-docs) -->"
END = "<!-- END GENERATED TABLES -->"
TRACK_TITLES = {"public": "공개 트랙 (NVD, 문서 = CVE 레코드)", "kisa": "KISA 트랙 (문서 = nttId)"}
RETRIEVER_ORDER = ("exact", "bm25", "dense")


def _fmt(value: float | None, digits: int = 4) -> str:
    return "-" if value is None else f"{value:.{digits}f}"


def summary(run_metrics: Mapping[str, Mapping]) -> dict:
    """CLI 출력용 요약: 분할별 macro, 유형별 nDCG@10·hit@10·n_scored, no_answer 표."""
    out = {}
    for split, block in run_metrics.items():
        out[split] = {
            "macro_ndcg@10": block["macro"]["ndcg@10"],
            "macro_hit@10": block["macro"]["hit@10"],
            "n_excluded": block["n_excluded"],
            "by_type": {
                name: {
                    "n_scored": item["n_scored"],
                    "ndcg@10": item["metrics"]["ndcg@10"],
                    "hit@10": item["metrics"]["hit@10"],
                }
                for name, item in block["by_type"].items()
            },
            "no_answer": block["no_answer"],
        }
    return out


def _ordered(runs: Mapping, track: str) -> list[str]:
    names = [key.split("/", 1)[1] for key in runs if key.startswith(f"{track}/")]
    return sorted(names, key=RETRIEVER_ORDER.index)


def render_tables(metrics: Mapping, manifest: Mapping) -> str:
    runs = metrics["runs"]
    lines: list[str] = []
    for track in TRACKS:
        retrievers = _ordered(runs, track)
        if not retrievers:
            continue
        lines += [f"### {TRACK_TITLES[track]}", ""]
        lines += ["#### 요약 (macro = 정답이 있는 유형의 단순 평균)", ""]
        lines += [
            "| 검색기 | split | n_scored | macro nDCG@10 | macro hit@10 | macro MRR@10 |",
            "|---|---|---|---|---|---|",
        ]
        for retriever in retrievers:
            for split in SPLITS:
                block = runs[f"{track}/{retriever}"].get(split)
                if block is None:
                    continue
                n_scored = sum(item["n_scored"] for item in block["by_type"].values())
                macro = block["macro"]
                lines.append(
                    f"| {retriever} | {split} | {n_scored} | {_fmt(macro['ndcg@10'])} "
                    f"| {_fmt(macro['hit@10'])} | {_fmt(macro['mrr@10'])} |"
                )
        lines += ["", "#### 유형별", ""]
        lines += [
            (
                "| 검색기 | split | 유형 | n_scored | n_skipped | n_excluded | nDCG@10 | hit@1 | hit@5 "
                "| hit@10 | recall@10 | MRR@10 | tie_at_cutoff@1/5/10 |"
            ),
            "|---|---|---|---|---|---|---|---|---|---|---|---|---|",
        ]
        for retriever in retrievers:
            for split in SPLITS:
                block = runs[f"{track}/{retriever}"].get(split)
                if block is None:
                    continue
                for query_type in QUERY_TYPES:
                    item = block["by_type"].get(query_type)
                    if item is None or query_type == "no_answer":
                        continue
                    m = item["metrics"]
                    ties = item["tie_at_cutoff"]
                    tie_text = "-" if ties is None else "/".join(str(ties[f"@{k}"]) for k in KS)
                    mark = "†" if item["observation_only"] else ""
                    lines.append(
                        f"| {retriever} | {split} | {query_type} | {item['n_scored']}{mark} "
                        f"| {item['n_skipped']} | {item['n_excluded']} | {_fmt(m['ndcg@10'])} "
                        f"| {_fmt(m['hit@1'])} | {_fmt(m['hit@5'])} | {_fmt(m['hit@10'])} "
                        f"| {_fmt(m['recall@10'])} | {_fmt(m['mrr@10'])} | {tie_text} |"
                    )
        lines += ["", "† n_scored < 10: 우열 판정 없이 관찰로만 읽는다(eval-protocol 5절).", ""]
        lines += ["#### no_answer (기권)", ""]
        lines += [
            "| 검색기 | split | n_no_answer | τ | abstain_rate | n_answerable | false_abstain_rate |",
            "|---|---|---|---|---|---|---|",
        ]
        for retriever in retrievers:
            for split in SPLITS:
                block = runs[f"{track}/{retriever}"].get(split)
                if block is None:
                    continue
                na = block["no_answer"]
                lines.append(
                    f"| {retriever} | {split} | {na['n_no_answer']} | {_fmt(na['tau'])} "
                    f"| {_fmt(na['abstain_rate'])} | {na['n_answerable']} "
                    f"| {_fmt(na['false_abstain_rate'])} |"
                )
        lines += ["", "#### 색인 시간과 질의 지연", ""]
        lines += [
            "| 검색기 | 문서 수 | 색인 시간(초) | 질의 지연 중앙값(ms) | 측정한 질의 수 |",
            "|---|---|---|---|---|",
        ]
        for retriever in retrievers:
            entry = manifest["runs"][f"{track}/{retriever}"]
            timing = entry["timing"]
            latency = timing["query_latency_median_seconds"]
            lines.append(
                f"| {retriever} | {entry['n_documents']} | {timing['index_seconds']:.4f} "
                f"| {'-' if latency is None else f'{latency * 1000:.4f}'} "
                f"| {timing['n_queries_timed']} |"
            )
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_docs(root: Path) -> None:
    """docs/baselines.md의 BEGIN/END 사이를 현재 metrics.json·manifest.json의 표로 바꾼다."""
    metrics = json.loads((root / RESULTS_DIR / "metrics.json").read_text(encoding="utf-8"))
    manifest = json.loads((root / RESULTS_DIR / "manifest.json").read_text(encoding="utf-8"))
    path = root / DOC_PATH
    text = path.read_text(encoding="utf-8")
    start, stop = text.index(BEGIN), text.index(END)
    path.write_text(
        text[: start + len(BEGIN)] + "\n\n" + render_tables(metrics, manifest) + "\n" + text[stop:],
        encoding="utf-8",
    )
