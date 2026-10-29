"""자체 지표 구현(krsec_rag_lab.metrics)을 검증된 구현(ranx)과 합성 순위·라벨로 대조한다.

CI에는 검증 패키지가 없다. 이 스크립트는 pytest가 import하지 않고, ranx도 main() 안에서만 import한다.
실행 (정확한 버전 고정, pyproject.toml·uv.lock은 건드리지 않음):

    uv run --with ranx==0.3.21 python scripts/crosscheck_metrics.py

비교는 질의 단위로 한다(평균만 비교하면 질의 간 오차 상쇄가 가려진다). 허용 오차는 실행 전에 정한
ABS_TOL이다. 두 구현 모두 float64 산술이라 차이는 1e-15 수준이어야 하고, 규약 7절 표의 허용오차(1e-4)는
소수 4자리 반올림 때문이어서 여기에는 쓰지 않는다. 입력은 전부 합성이다.

대조 범위는 규약이 ranx와 같은 정의를 쓰는 부분이다: 정답이 있는 질의의 hit@k, recall@k, RR/MRR@k, nDCG@k.
규약과 ranx의 동작이 다른 곳(답 없음, 동점, 빈 결과 입력 방식 등)은 아래 probe_differences가 관측해 출력한다.
"""

import importlib.metadata
import random
import sys

ABS_TOL = 1e-9
KS = (1, 5, 10)
SEED = 20261029
N_RANDOM_QUERIES = 300
UNIVERSE = [f"d{i:02d}" for i in range(1, 31)]

# (우리 지표 이름, ranx 지표 이름)
METRIC_PAIRS = (
    ("hit", "hit_rate"),
    ("recall", "recall"),
    ("rr", "mrr"),
    ("ndcg", "ndcg"),
)

# docs/eval-protocol.md 7.2 B1~B8 (k는 아래 KS 전부로 다시 대조하므로 입력만 쓴다)
BOUNDARY_INPUTS = (
    (["d2", "d7", "d9"], {"d2"}),
    (["d7", "d9", "d2"], {"d2"}),
    (["d7", "d2", "d9"], {"d2", "d4"}),
    (["d4", "d2", "d9"], {"d2", "d4"}),
    (["d7", "d4", "d2"], {"d2", "d4"}),
    (["d1", "d2", "d3"], {"d1", "d2", "d3", "d4"}),
    (["d7", "d8", "d9", "d2"], {"d2"}),
    (["d7", "d2"], {"d2"}),
    ([], {"d2"}),
)


def synthetic_queries():
    """(ranked, gold) 목록. 순위 길이 0~15(k보다 짧은 목록·빈 목록 포함), 정답 1~6개, 정답이 목록 밖일 수 있다."""
    rng = random.Random(SEED)
    queries = list(BOUNDARY_INPUTS)
    for _ in range(N_RANDOM_QUERIES):
        gold = set(rng.sample(UNIVERSE, rng.randint(1, 6)))
        length = rng.choice([0, 1, 2, 3, 5, 8, 10, 12, 15])
        ranked = rng.sample(UNIVERSE, length)
        queries.append((ranked, gold))
    return queries


def to_ranx(queries):
    from ranx import Qrels, Run

    qrels = {f"q{i:04d}": {doc: 1 for doc in gold} for i, (_, gold) in enumerate(queries)}
    # 점수는 순위에 대해 strictly decreasing: 동점이 없어 구현 간 동점 규칙 차이가 끼지 않는다.
    # 빈 결과는 빈 dict로 넣는다. ranx는 질의를 query id 문자열 순으로 정렬하므로 id를 0 채움해
    # 입력 순서와 같게 맞춘다(그래야 질의 단위로 대응된다).
    run = {
        f"q{i:04d}": {doc: float(len(ranked) - pos) for pos, doc in enumerate(ranked)}
        for i, (ranked, _) in enumerate(queries)
    }
    return Qrels(qrels), Run(run)


def compare(queries):
    from ranx import evaluate

    from krsec_rag_lab import metrics

    ours = {
        "hit": metrics.hit_at_k,
        "recall": metrics.recall_at_k,
        "rr": metrics.reciprocal_rank_at_k,
        "ndcg": metrics.ndcg_at_k,
    }
    qrels, run = to_ranx(queries)
    failures = 0
    print(f"{'metric':<12}{'k':>3}{'n':>6}{'max|per-query diff|':>24}{'|mean diff|':>16}  result")
    for our_name, ranx_name in METRIC_PAIRS:
        for k in KS:
            theirs = evaluate(qrels, run, f"{ranx_name}@{k}", return_mean=False)
            mine = [ours[our_name](ranked, gold, k) for ranked, gold in queries]
            assert len(theirs) == len(mine)
            max_diff = max(abs(a - float(b)) for a, b in zip(mine, theirs, strict=True))
            mean_diff = abs(sum(mine) / len(mine) - float(sum(theirs)) / len(theirs))
            ok = max_diff <= ABS_TOL and mean_diff <= ABS_TOL
            failures += 0 if ok else 1
            label = f"{our_name}@{k}"
            print(
                f"{label:<12}{k:>3}{len(mine):>6}{max_diff:>24.3e}{mean_diff:>16.3e}  "
                f"{'OK' if ok else 'MISMATCH'}"
            )
    mrr = metrics.mrr_at_k(queries, 10).mean
    their_mrr = float(evaluate(qrels, run, "mrr@10"))
    ok = abs(mrr - their_mrr) <= ABS_TOL
    failures += 0 if ok else 1
    print(
        f"mrr_at_k (aggregate) @10: ours={mrr:.12f} ranx={their_mrr:.12f}  {'OK' if ok else 'MISMATCH'}"
    )
    return failures


def probe_differences():
    """규약과 ranx가 다르게 동작하는 입력을 관측해 출력한다. 판정에는 쓰지 않는다(INFO).

    probe 하나가 예외로 실패해도 INFO 줄에 사유를 적고 PASS/FAIL 판정까지 진행한다.
    """
    from ranx import Qrels, Run, evaluate

    from krsec_rag_lab import metrics

    def no_answer():
        # 규약은 None(평균 제외), ranx는 정답이 없는 질의를 평가하지 못한다.
        try:
            value = evaluate(Qrels({"q": {}}), Run({"q": {"d7": 1.0}}), "ndcg@3")
            theirs = f"returns {float(value)}"
        except Exception as exc:  # noqa: BLE001 - 관측이 목적이라 넓게 잡는다
            theirs = f"raises {type(exc).__name__}: {exc}"
        return f"no-answer query: ours={metrics.ndcg_at_k(['d7'], set(), 3)!r} ranx {theirs}"

    def ties():
        # 규약은 (-score, doc_id)를 하네스가 정렬하고, ranx는 입력 순서에 의존한다.
        qrels = Qrels({"q": {"d2": 1}})
        ranx_a = float(evaluate(qrels, Run({"q": {"d7": 1.0, "d2": 1.0}}), "mrr@2"))
        ranx_b = float(evaluate(qrels, Run({"q": {"d2": 1.0, "d7": 1.0}}), "mrr@2"))
        ranked = metrics.sort_by_score({"d7": 1.0, "d2": 1.0})
        ours = metrics.reciprocal_rank_at_k(ranked, {"d2"}, 2)
        return (
            f"tie d2=d7, gold d2, mrr@2: ours={ours} (sorted by doc_id), "
            f"ranx insertion order d7,d2 -> {ranx_a}, d2,d7 -> {ranx_b}"
        )

    def empty_result():
        # 규약은 빈 목록이 곧 0점. ranx는 빈 dict면 0점이고, query id 자체가 빠지면 거부한다.
        empty_run = float(
            evaluate(
                Qrels({"q": {"d2": 1}, "p": {"d2": 1}}), Run({"q": {}, "p": {"d2": 1.0}}), "ndcg@3"
            )
        )
        try:
            evaluate(Qrels({"q": {"d2": 1}}), Run({"other": {"d9": 1.0}}), "ndcg@3")
            missing = "accepts"
        except Exception as exc:  # noqa: BLE001 - 관측이 목적이라 넓게 잡는다
            missing = f"raises {type(exc).__name__}"
        return (
            f"empty result: ours={metrics.ndcg_at_k([], {'d2'}, 3)}, "
            f"ranx empty dict (mean with a perfect 2nd query) -> {empty_run}, "
            f"query id missing from run {missing} (make_comparable=True would fill 0)"
        )

    def k_zero():
        # 규약은 k <= 0이면 ValueError. ranx는 dict라 중복을 표현할 수 없고 k=0은 관측만 한다.
        try:
            value = evaluate(Qrels({"q": {"d2": 1}}), Run({"q": {"d2": 1.0}}), "ndcg@0")
            theirs = f"returns {float(value)}"
        except Exception as exc:  # noqa: BLE001 - 관측이 목적이라 넓게 잡는다
            theirs = f"raises {type(exc).__name__}"
        try:
            metrics.ndcg_at_k(["d2"], {"d2"}, 0)
            ours_k0 = "returns"
        except ValueError:
            ours_k0 = "raises ValueError"
        return f"k=0: ours {ours_k0}, ranx {theirs}"

    def burges():
        # ranx의 ndcg는 gain=rel, ndcg_burges가 2^rel-1. 이진 라벨에서는 같은 값이다.
        qrels = Qrels({"q": {"d2": 1, "d4": 1}})
        run = Run({"q": {"d7": 3.0, "d2": 2.0}})
        plain = float(evaluate(qrels, run, "ndcg@3"))
        burges = float(evaluate(qrels, run, "ndcg_burges@3"))
        return f"binary labels, ndcg vs ndcg_burges: {plain:.12f} vs {burges:.12f}"

    print("\nbehavior differences (INFO, not part of PASS/FAIL):")
    for probe in (no_answer, ties, empty_result, k_zero, burges):
        try:
            line = probe()
        except Exception as exc:  # noqa: BLE001 - probe 실패가 판정을 막지 않게 한다
            line = f"{probe.__name__}: probe failed ({type(exc).__name__}: {exc})"
        print(f"  {line}")


def main():
    try:
        ranx_version = importlib.metadata.version("ranx")
    except importlib.metadata.PackageNotFoundError:
        print(
            "ranx is not installed. Run:\n"
            "  uv run --with ranx==0.3.21 python scripts/crosscheck_metrics.py",
            file=sys.stderr,
        )
        return 2

    queries = synthetic_queries()
    print(f"ranx=={ranx_version}  seed={SEED}  queries={len(queries)}  abs_tol={ABS_TOL}")
    failures = compare(queries)
    probe_differences()
    print(f"\n{'PASS' if failures == 0 else 'FAIL'}: {failures} mismatching comparison(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
