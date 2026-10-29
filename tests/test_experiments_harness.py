"""실험 하네스·비교·판정 테스트 - 합성 코퍼스·합성 결과·합성 실험 모듈만 쓰고 모델을 부르지 않는다.

확인하는 것: 합성 실험 모듈이 하네스 파일 수정 없이 CLI로 실행·비교되는지(확장 계약), `--variant`, 질문별 paired
delta와 층화 bootstrap의 재현성·기대 구간, 판정 경계(하한 0 이하는 rejected), test 잠금(`--split test`와
`--split all`, dev 재실행 뒤에도), 비교 전 필수 검사, `--compare` 불일치 시 exit 1, `primary`·`secondary`
필드, 결과 파일 허용 필드와 절대 경로·본문 비유출.
"""

import copy
import importlib.util
import json
import random
import shutil
import subprocess
import sys
import types
from pathlib import Path

import pytest

from krsec_rag_lab.baselines import data, runner, scoring
from krsec_rag_lab.baselines.bm25 import BM25Index
from krsec_rag_lab.experiments import (
    ComparisonError,
    ContractError,
    ExperimentError,
    LockError,
    harness,
)
from krsec_rag_lab.experiments import compare as cmp

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "run_experiment.py"
SPEC = importlib.util.spec_from_file_location("run_experiment", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
run_experiment = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = run_experiment
SPEC.loader.exec_module(run_experiment)

OUT = Path("results/experiments")
N_DOCS = 40

# ------------------------------------------------------------ 합성 공개 트랙
# 문서 i의 ID는 CVE-2026-(1000+i). 쉬운 질문(cve_explicit)은 ID를 적어 BM25가 1위로 찾고, 어려운 질문은 코퍼스에
# 없는 낱말만 적어 BM25 결과가 비어 있다(nDCG 0). 그래서 정답 문서를 알려 주는 합성 실험은 어려운 질문에서만 오른다.


def doc_id(i):
    return f"CVE-2026-{1000 + i}"


def public_query(qid, query, query_type, split, gold=(), unjudged=()):
    return {
        "id": qid,
        "query": query,
        "query_type": query_type,
        "split": split,
        "gold": list(gold),
        "unjudged": list(unjudged),
        "vendor_product": None,
    }


def easy(qid, i, split):
    return public_query(qid, f"{doc_id(i)} 취약점 설명", "cve_explicit", split, [doc_id(i)])


def hard(qid, i, split, query_type="product_symptom"):
    return public_query(qid, f"zzqx{i} 질문", query_type, split, [doc_id(i)])


def na(qid, split):
    return public_query(qid, "CVE-2026-9999 찾아줘", "no_answer", split)


QUERIES = [
    easy("d-cve-1", 0, "dev"),
    easy("d-cve-2", 1, "dev"),
    hard("d-prod-1", 2, "dev"),
    hard("d-prod-2", 3, "dev"),
    hard("d-exp-1", 4, "dev", "explanation_comparison"),
    na("d-na-1", "dev"),
    *(easy(f"t-cve-{n}", 10 + n, "test") for n in range(4)),
    *(hard(f"t-prod-{n:02d}", 20 + n, "test") for n in range(12)),
    *(hard(f"t-exp-{n}", 34 + n, "test", "explanation_comparison") for n in range(2)),
    na("t-na-1", "test"),
    na("t-na-2", "test"),
]
EASY_TEST = {f"t-cve-{n}" for n in range(4)}
HARD_TEST = {f"t-prod-{n:02d}" for n in range(12)} | {f"t-exp-{n}" for n in range(2)}
DOC_TEXTS = {doc_id(i): f"gadget{i} vendor{i % 5} firmware" for i in range(N_DOCS)}


def write_jsonl(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + "\n", encoding="utf-8"
    )


def write_fixture(root, queries=None):
    rows = [{"id": cve, "description_en": text} for cve, text in DOC_TEXTS.items()]
    write_jsonl(root / data.PUBLIC_CORPUS, rows)
    write_jsonl(root / data.PUBLIC_QUERIES, QUERIES if queries is None else queries)


@pytest.fixture
def root(tmp_path):
    """합성 입력과 실제 베이스라인 실행기로 만든 BM25 기준선 저장본이 있는 리포 루트."""
    write_fixture(tmp_path)
    runner.run_baseline("public", "bm25", tmp_path)
    return tmp_path


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path, payload):
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", "utf-8"
    )


# ------------------------------------------------------------ 합성 실험 모듈


def make_synth(name="synth"):
    """하네스·CLI 파일을 고치지 않고 쓰는 가짜 실험 모듈. 변형: oracle(정답 문서에 점수), copy(BM25 그대로),
    mixed(쉬운 질문은 비우고 나머지는 정답), worse(정답을 뺀 문서만)."""
    module = types.ModuleType(f"krsec_rag_lab.experiments.{name}")
    module.NAME = name
    module.HYPOTHESIS = "합성 실험: 정답 문서를 알려 주면 BM25보다 높다"
    module.PRIMARY = ("public", "oracle")
    module.VARIANTS = {"public": ("oracle", "copy", "mixed", "worse")}
    module.BASELINES = {"public": "bm25"}
    module.FIXED = {"seed": 1}
    module.GRID = [{"boost": 1.0}, {"boost": 2.0}]
    module.REPRO = {}
    module.NOTE = "synthetic"
    module.calls = {"setup": 0}

    def grid(track, variant):
        return list(module.GRID)

    def fixed_config(track, variant, baselines_manifest):
        return dict(module.FIXED)

    def reproduction_inputs(track, variant):
        return dict(module.REPRO)

    def setup(ctx):
        module.calls["setup"] += 1
        params = ctx.baselines_manifest["runs"]["public/bm25"]["selected"]
        return {
            "variant": ctx.variant,
            "texts": ctx.corpus.texts,
            "bm25": BM25Index(ctx.corpus.texts, k1=params["k1"], b=params["b"]),
        }

    def make_scorer(state, config):
        variant = state["variant"]

        def score(question):
            if variant == "copy":
                return state["bm25"].score(question.query)
            if variant == "oracle":
                return dict.fromkeys(question.gold, config["boost"])
            if variant == "mixed":
                if question.query_type == "cve_explicit":
                    return {}
                return dict.fromkeys(question.gold, config["boost"])
            return {d: 1.0 for d in state["texts"] if d not in question.gold}

        return score

    def describe(state, config):
        return {"note": module.NOTE}

    module.grid = grid
    module.fixed_config = fixed_config
    module.reproduction_inputs = reproduction_inputs
    module.setup = setup
    module.make_scorer = make_scorer
    module.describe = describe
    return module


@pytest.fixture
def synth(monkeypatch):
    module = make_synth()
    monkeypatch.setitem(sys.modules, f"krsec_rag_lab.experiments.{module.NAME}", module)
    return module


@pytest.fixture
def cli(monkeypatch, root):
    """`scripts/run_experiment.py`의 main을 합성 루트에서 돌린다."""
    monkeypatch.setattr(run_experiment, "ROOT", root)
    return run_experiment.main


def run_synth(root, synth, variants=None, split="all", track="public"):
    return harness.run_experiment(synth.NAME, track, root, variants=variants, split=split)


def exp_dir(root, name="synth"):
    return root / OUT / name


def snapshot(root, name="synth"):
    return {
        p.relative_to(root).as_posix(): p.read_bytes()
        for p in sorted(exp_dir(root, name).rglob("*"))
        if p.is_file()
    }


# ------------------------------------------------------------ 확장 계약: 합성 실험을 CLI로


def test_synthetic_experiment_runs_and_compares_through_the_cli_without_harness_changes(
    cli, synth, root, capsys
):
    assert cli(["--exp", "synth", "--track", "public"]) == 0
    printed = json.loads(capsys.readouterr().out)
    assert printed["primary"] == {
        "track": "public",
        "variant": "oracle",
        "baseline": "bm25",
        "verdict": "hypothesis-confirmed",
    }
    directory = exp_dir(root)
    for variant in synth.VARIANTS["public"]:
        assert (directory / "public" / f"{variant}.jsonl").exists()
    for filename in ("manifest.json", "metrics.json", "comparison.json"):
        assert (directory / filename).exists()
    before = snapshot(root)
    assert cli(["--exp", "synth", "--compare"]) == 0
    assert "compare OK" in capsys.readouterr().out
    assert snapshot(root) == before  # --compare는 파일을 쓰지 않는다


def test_compare_does_not_build_indexes_or_models(cli, synth, root):
    run_synth(root, synth)
    calls = synth.calls["setup"]
    assert cli(["--exp", "synth", "--compare"]) == 0
    assert synth.calls["setup"] == calls  # setup(= 모델·인덱스 생성)을 부르지 않는다


@pytest.mark.parametrize(
    ("args", "message"),
    [
        (["--exp", "nope", "--track", "public"], "unknown experiment"),
        (["--exp", "Bad-Name", "--track", "public"], "bad experiment name"),
        (["--exp", "harness", "--track", "public"], "missing"),
        (["--exp", "synth", "--track", "public", "--variant", "nope"], "unknown variant"),
        (["--exp", "synth", "--track", "kisa", "--kisa-root", "x"], "no track"),
    ],
)
def test_cli_rejects_bad_experiment_or_variant_with_exit_1(cli, synth, capsys, args, message):
    assert cli(args) == 1
    assert message in capsys.readouterr().err


def test_cli_argument_errors(cli, synth, capsys):
    with pytest.raises(SystemExit):
        cli(["--exp", "synth"])  # --track 없음
    assert "--track" in capsys.readouterr().err
    with pytest.raises(SystemExit):
        cli(["--exp", "synth", "--compare", "--track", "public"])
    assert "--compare" in capsys.readouterr().err


@pytest.mark.parametrize(
    "broken",
    ["NAME", "HYPOTHESIS", "PRIMARY", "VARIANTS", "BASELINES", "grid", "setup", "make_scorer"],
)
def test_module_missing_a_required_attribute_is_a_contract_error(monkeypatch, broken):
    module = make_synth("brokenmod")
    delattr(module, broken)
    monkeypatch.setitem(sys.modules, "krsec_rag_lab.experiments.brokenmod", module)
    with pytest.raises(ContractError):
        harness.load_experiment("brokenmod")


def test_module_name_and_primary_must_match(monkeypatch):
    module = make_synth("othername")
    module.PRIMARY = ("public", "nothing")
    monkeypatch.setitem(sys.modules, "krsec_rag_lab.experiments.othername", module)
    with pytest.raises(ContractError, match="PRIMARY"):
        harness.load_experiment("othername")
    module.PRIMARY = ("public", "oracle")
    module.NAME = "different"
    with pytest.raises(ContractError, match="NAME"):
        harness.load_experiment("othername")


def test_harness_has_no_experiment_specific_branches():
    for filename in ("harness.py", "compare.py"):
        source = (ROOT / "src/krsec_rag_lab/experiments" / filename).read_text("utf-8")
        for experiment in ("hybrid", "rerank", "chunking", "crossling", "embedding"):
            assert experiment not in source.lower(), (filename, experiment)


# ------------------------------------------------------------ --variant


def test_variant_selects_only_that_variant_and_default_runs_all(root, synth):
    run_synth(root, synth, variants=["copy"])
    stored = sorted(p.name for p in (exp_dir(root) / "public").iterdir())
    assert stored == ["copy.jsonl"]
    manifest = read_json(exp_dir(root) / "manifest.json")
    assert sorted(manifest["runs"]) == ["public/copy"]
    comparison = read_json(exp_dir(root) / "comparison.json")
    assert comparison["primary"] is None  # 주 변형(oracle)은 아직 돌리지 않았다
    assert [item["variant"] for item in comparison["secondary"]] == ["copy"]

    run_synth(root, synth)  # 변형 생략 = 트랙의 모든 변형
    stored = sorted(p.name for p in (exp_dir(root) / "public").iterdir())
    assert stored == ["copy.jsonl", "mixed.jsonl", "oracle.jsonl", "worse.jsonl"]
    comparison = read_json(exp_dir(root) / "comparison.json")
    assert comparison["primary"]["variant"] == "oracle"
    assert [item["variant"] for item in comparison["secondary"]] == ["copy", "mixed", "worse"]


def test_variant_run_leaves_other_variants_files_untouched(root, synth):
    run_synth(root, synth, variants=["oracle"])
    first = (exp_dir(root) / "public" / "oracle.jsonl").read_bytes()
    run_synth(root, synth, variants=["copy"])
    assert (exp_dir(root) / "public" / "oracle.jsonl").read_bytes() == first
    assert sorted(read_json(exp_dir(root) / "manifest.json")["runs"]) == [
        "public/copy",
        "public/oracle",
    ]


# ------------------------------------------------------------ 판정: 합성 결과로 기대값 확인


def test_oracle_is_confirmed_and_copy_is_rejected_with_zero_delta(root, synth):
    comparison = run_synth(root, synth)
    blocks = comparison["comparisons"]
    oracle = blocks["public/oracle"]
    assert oracle["verdict"] == "hypothesis-confirmed"
    # 쉬운 4건은 1.0 -> 1.0, 어려운 14건은 0.0 -> 1.0: 유형 평균 delta (0, 1, 1)의 macro
    assert oracle["delta"] == pytest.approx(2 / 3)
    assert oracle["ci95"]["low"] > 0
    assert blocks["public/copy"]["delta"] == 0.0
    assert blocks["public/copy"]["verdict"] == "hypothesis-rejected"
    assert blocks["public/worse"]["delta"] < 0
    assert blocks["public/worse"]["verdict"] == "hypothesis-rejected"


def test_failure_lists_and_rank_fields(root, synth):
    block = run_synth(root, synth)["comparisons"]["public/mixed"]
    degraded = {item["question_id"]: item for item in block["degraded"]}
    assert set(degraded) == EASY_TEST  # 기준선이 1위로 맞춘 질문이 전부 악화
    for item in degraded.values():
        assert (item["rank_before"], item["rank_after"]) == (1, None)
        assert (item["ndcg_before"], item["ndcg_after"], item["delta"]) == (1.0, 0.0, -1.0)
        assert item["query_type"] == "cve_explicit"
    assert [i["question_id"] for i in block["degraded"]] == sorted(EASY_TEST)  # 동점은 ID 순
    assert block["n_degraded"] == 4
    assert block["n_improved"] == len(HARD_TEST) == 14
    improved = block["improved_top10"]
    assert len(improved) == 10  # 개선 상위 10건만
    assert {i["question_id"] for i in improved} <= HARD_TEST
    for item in improved:
        assert (item["rank_before"], item["rank_after"]) == (None, 1)
    assert block["n_unchanged"] == 0
    assert block["cve_explicit"] == {"delta_ndcg@10": -1.0, "regression": True}


def test_by_type_deltas_and_secondary_metrics(root, synth):
    block = run_synth(root, synth)["comparisons"]["public/oracle"]
    by_type = block["by_type"]
    assert by_type["cve_explicit"]["metrics"]["ndcg@10"]["delta"] == 0.0
    assert by_type["product_symptom"]["metrics"]["ndcg@10"]["delta"] == 1.0
    assert by_type["product_symptom"]["n_scored"] == 12
    assert by_type["explanation_comparison"]["observation_only"] is True  # n_scored 2 < 10
    assert by_type["product_symptom"]["observation_only"] is False
    for name in ("hit@10", "mrr@10"):
        assert block["secondary_metrics"][name]["delta"] == pytest.approx(2 / 3)
        assert name in by_type["product_symptom"]["metrics"]
    assert block["cve_explicit"] == {"delta_ndcg@10": 0.0, "regression": False}
    assert block["no_answer"]["experiment"]["n_no_answer"] == 2
    assert "tau" in block["no_answer"]["baseline"]
    assert block["bootstrap"]["n_per_type"] == {
        "cve_explicit": 4,
        "product_symptom": 12,
        "explanation_comparison": 2,
    }


def test_primary_and_secondary_fields(root, synth):
    comparison = run_synth(root, synth)
    assert comparison["primary"] == {
        "track": "public",
        "variant": "oracle",
        "baseline": "bm25",
        "verdict": "hypothesis-confirmed",
    }
    for item in comparison["secondary"]:
        assert set(item) == {"track", "variant", "baseline", "verdict"}
    assert comparison["primary"]["verdict"] == comparison["comparisons"]["public/oracle"]["verdict"]
    assert comparison["experiment"] == "synth"
    assert set(comparison) >= {"primary", "secondary", "comparisons", "hypothesis", "rule"}


def test_dev_selection_uses_the_default_tie_rule_and_records_the_grid(root, synth):
    run_synth(root, synth, variants=["oracle"])
    entry = read_json(exp_dir(root) / "manifest.json")["runs"]["public/oracle"]
    assert entry["selected"]["config"] == {
        "boost": 1.0
    }  # 두 설정이 같은 점수 -> 격자 순서에서 앞선 쪽
    assert entry["selected"]["selected_on"] == "dev"
    assert [row["config"] for row in entry["grid"]["rows"]] == synth.GRID
    assert entry["grid"]["selection_rule"]
    assert entry["selected"]["tau_selection"]["tau"] == entry["selected"]["tau"]
    for field in (
        "inputs",
        "stored_results",
        "timing",
        "environment",
        "fixed",
        "description",
        "reproduction_inputs",
        "test",
        "baseline",
    ):
        assert field in entry
    assert entry["test"]["config_hash"] and entry["test"]["executed_at"]
    assert entry["stored_results"]["path"] == "results/experiments/synth/public/oracle.jsonl"
    assert {"index_seconds", "query_latency_median_seconds", "n_queries_timed"} <= set(
        entry["timing"]
    )


def test_custom_select_hook_decides_the_config(root, synth):
    synth.select = lambda rows: len(rows) - 1
    run_synth(root, synth, variants=["oracle"])
    entry = read_json(exp_dir(root) / "manifest.json")["runs"]["public/oracle"]
    assert entry["selected"]["config"] == {"boost": 2.0}


def test_tau_and_config_come_from_dev_only(tmp_path, monkeypatch):
    """test 질문만 바꿔도 dev에서 고른 설정·τ는 그대로다."""
    selected = []
    for label, extra in (("base", []), ("changed", [hard("t-extra", 30, "test")])):
        base = tmp_path / label
        write_fixture(base, QUERIES + extra)
        runner.run_baseline("public", "bm25", base)
        module = make_synth()
        monkeypatch.setitem(sys.modules, "krsec_rag_lab.experiments.synth", module)
        harness.run_experiment("synth", "public", base, variants=["oracle"])
        selected.append(
            read_json(base / OUT / "synth/manifest.json")["runs"]["public/oracle"]["selected"]
        )
    assert selected[0] == selected[1]


# ------------------------------------------------------------ bootstrap과 판정 경계


def reference_interval(deltas_by_type, resamples, seed):
    """스펙 문장 그대로 다시 쓴 구현(테스트용 독립 구현)."""
    rng = random.Random(seed)
    groups = [
        [deltas_by_type[t][q] for q in sorted(deltas_by_type[t])]
        for t in data.QUERY_TYPES
        if t in deltas_by_type
    ]
    values = []
    for _ in range(resamples):
        macro = []
        for group in groups:
            macro.append(sum(group[rng.randrange(len(group))] for _ in group) / len(group))
        values.append(sum(macro) / len(macro))
    values.sort()
    return values[int(0.025 * resamples)], values[int(0.975 * resamples) - 1]


UNEVEN = {
    "cve_explicit": {"q1": 0.5, "q2": 0.0, "q3": 0.25, "q4": 0.125, "q5": -0.5},
    "product_symptom": {"q6": 0.3, "q7": -0.2},
    "explanation_comparison": {"q8": 1.0},
}


def test_bootstrap_matches_the_spec_formula_and_is_reproducible():
    first = cmp.bootstrap_macro_delta(UNEVEN)
    again = cmp.bootstrap_macro_delta(UNEVEN)
    assert first == again  # 같은 시드 -> 같은 구간
    low, high = reference_interval(UNEVEN, 10000, 20261029)
    assert (first["low"], first["high"]) == (low, high)
    assert first["resamples"] == 10000
    assert first["seed"] == 20261029
    other = cmp.bootstrap_macro_delta(UNEVEN, seed=1)
    assert (other["low"], other["high"]) != (first["low"], first["high"])


def test_bootstrap_ignores_input_order_and_types_follow_query_types_order():
    shuffled = {
        "explanation_comparison": {"q8": 1.0},
        "product_symptom": {"q7": -0.2, "q6": 0.3},
        "cve_explicit": dict(reversed(list(UNEVEN["cve_explicit"].items()))),
    }
    assert cmp.bootstrap_macro_delta(shuffled, resamples=2000) == cmp.bootstrap_macro_delta(
        UNEVEN, resamples=2000
    )


def test_bootstrap_is_stratified_and_keeps_per_type_sample_sizes():
    # 유형 A는 전부 +0.2, 유형 B는 한 건 -0.1: 유형별 표본 수를 지키는 층화 복원추출이면 어떤 재표집도
    # macro = (0.2 + -0.1) / 2 = 0.05로 같아 구간이 한 점이다(질문을 섞어 뽑으면 이 값이 흔들린다)
    deltas = {"cve_explicit": dict.fromkeys("abcd", 0.2), "product_symptom": {"x": -0.1}}
    result = cmp.bootstrap_macro_delta(deltas)
    assert result["low"] == pytest.approx(0.05)
    assert result["high"] == pytest.approx(0.05)


def test_bootstrap_expected_interval_for_types_of_different_sizes():
    # 유형 A(n=2): delta {0, 1}, 유형 B(n=1): 0.5. 유형 A의 재표집 평균은 {0, .5, 1}이 확률 1/4, 1/2, 1/4이고
    # macro = (그 평균 + 0.5) / 2 는 {0.25, 0.5, 0.75}다. 2.5/97.5 백분위는 양 끝 값이다.
    deltas = {"cve_explicit": {"a": 0.0, "b": 1.0}, "product_symptom": {"c": 0.5}}
    result = cmp.bootstrap_macro_delta(deltas)
    assert result["low"] == pytest.approx(0.25)
    assert result["high"] == pytest.approx(0.75)


def test_bootstrap_rejects_empty_and_unknown_types():
    with pytest.raises(ValueError, match="at least one"):
        cmp.bootstrap_macro_delta({})
    with pytest.raises(ValueError, match="unknown query types"):
        cmp.bootstrap_macro_delta({"other": {"a": 1.0}})


@pytest.mark.parametrize(
    ("delta", "low", "verdict"),
    [
        (0.2, 0.05, "hypothesis-confirmed"),
        (0.2, 1e-12, "hypothesis-confirmed"),
        (0.2, 0.0, "hypothesis-rejected"),  # 하한이 정확히 0이면 기각
        (0.2, -0.01, "hypothesis-rejected"),
        (0.0, 0.1, "hypothesis-rejected"),  # delta가 0이면 기각
        (-0.1, -0.3, "hypothesis-rejected"),
        (-0.1, 0.1, "hypothesis-rejected"),
    ],
)
def test_decide_boundary(delta, low, verdict):
    assert cmp.decide(delta, low) == verdict


def test_end_to_end_lower_bound_at_or_below_zero_is_rejected_even_when_delta_is_positive(
    root, synth
):
    """어려운 질문 하나만 오르면 delta는 양수지만 구간이 0을 지난다 -> 기각."""
    synth.PRIMARY = ("public", "oracle")
    module = synth

    def make_scorer(state, config):
        def score(question):
            if question.question_id == "t-prod-00":
                return dict.fromkeys(question.gold, 1.0)
            return state["bm25"].score(question.query)

        return score

    module.make_scorer = make_scorer
    block = run_synth(root, synth, variants=["oracle"])["comparisons"]["public/oracle"]
    assert block["delta"] > 0
    assert block["ci95"]["low"] <= 0
    assert block["verdict"] == "hypothesis-rejected"


def test_first_gold_rank_uses_the_stored_condensed_list():
    record = {"results": [{"doc_id": "a", "rank": 1}, {"doc_id": "b", "rank": 2}]}
    assert cmp.first_gold_rank(record, {"b", "z"}) == 2
    assert cmp.first_gold_rank(record, {"z"}) is None


def test_diff_values_tolerance_and_types():
    assert cmp.diff_values({"a": [1.0, 2.0]}, {"a": [1.0 + 1e-10, 2.0]}) == []
    assert cmp.diff_values({"a": 1.0}, {"a": 1.0 + 1e-6})
    assert cmp.diff_values({"a": "x"}, {"a": "y"})
    assert cmp.diff_values({"a": 1}, {"b": 1})
    assert cmp.diff_values([1, 2], [1])
    assert cmp.diff_values({"a": True}, {"a": 1})  # bool은 숫자와 다르다
    assert cmp.diff_values({"a": None}, {"a": 0.0})


# ------------------------------------------------------------ 비교 전 필수 검사 (단위)


def good_pair(root):
    """`check_comparable`에 넘길 (실험 항목, 기준 항목, 현재 입력, 질문, 실험 레코드, 기준 레코드)."""
    questions = data.load_questions("public", root)
    base_manifest = read_json(root / "results/baselines/manifest.json")
    base_entry = base_manifest["runs"]["public/bm25"]
    exp_entry = copy.deepcopy(base_entry)
    inputs = data.input_fingerprints("public", root)
    records = cmp.read_stored(root / "results/baselines/public/bm25.jsonl")
    return {
        "exp_entry": exp_entry,
        "base_entry": copy.deepcopy(base_entry),
        "current_inputs": inputs,
        "questions": questions,
        "exp_records": copy.deepcopy(records),
        "base_records": copy.deepcopy(records),
    }


def test_check_comparable_accepts_matching_inputs(root):
    cmp.check_comparable(**good_pair(root))


def _change_protocol(args, side):
    args[side]["protocol_version"] = "eval-protocol-v1"


def _change_inputs(args, side):
    args[side]["inputs"]["queries"]["sha256"] = "0" * 64


def _drop_test(args, side):
    del args[side][next(iter(sorted(q for q in args[side] if q.startswith("t-prod"))))]


def _extra_question(args, side):
    record = copy.deepcopy(args[side]["t-cve-0"])
    record["question_id"] = "t-unknown"
    args[side]["t-unknown"] = record


@pytest.mark.parametrize(
    ("mutate", "side", "message"),
    [
        (_change_protocol, "exp_entry", "protocol_version differs"),
        (_change_protocol, "base_entry", "protocol_version differs"),
        (_change_inputs, "exp_entry", "experiment input hashes"),
        (_change_inputs, "base_entry", "baseline input hashes"),
        (_drop_test, "exp_records", "experiment: missing 1 test question"),
        (_drop_test, "base_records", "baseline: missing 1 test question"),
        (_extra_question, "exp_records", "experiment: unknown question id"),
        (_extra_question, "base_records", "baseline: unknown question id"),
    ],
)
def test_check_comparable_fails_on_each_mismatch(root, mutate, side, message):
    args = good_pair(root)
    mutate(args, side)
    with pytest.raises(ComparisonError, match=message):
        cmp.check_comparable(**args)


def test_check_comparable_fails_when_the_current_input_files_differ(root):
    args = good_pair(root)
    args["current_inputs"] = copy.deepcopy(args["current_inputs"])
    args["current_inputs"]["corpus"]["sha256"] = "1" * 64
    with pytest.raises(ComparisonError, match="input hashes"):
        cmp.check_comparable(**args)  # 실험과 기준이 서로 같아도 지금 파일과 다르면 실패


@pytest.mark.parametrize("duplicate_in", ["experiment", "baseline"])
def test_duplicate_question_rows_fail_when_reading_stored_results(root, tmp_path, duplicate_in):
    source = root / "results/baselines/public/bm25.jsonl"
    lines = source.read_text("utf-8").splitlines()
    copy_path = tmp_path / f"{duplicate_in}.jsonl"
    copy_path.write_text("\n".join([*lines, lines[-1]]) + "\n", encoding="utf-8")
    with pytest.raises(ComparisonError, match="duplicate question id"):
        cmp.read_stored(copy_path)


def test_stored_row_with_a_disallowed_field_fails(root, tmp_path):
    row = json.loads(
        (root / "results/baselines/public/bm25.jsonl").read_text("utf-8").splitlines()[0]
    )
    row["query_text"] = "본문이 새는 경로"
    path = tmp_path / "bad.jsonl"
    path.write_text(json.dumps(row) + "\n", encoding="utf-8")
    with pytest.raises(ComparisonError, match="record fields"):
        cmp.read_stored(path)


# ------------------------------------------------------------ 비교 전 필수 검사 (통합)


def mutate_json(path, change):
    payload = read_json(path)
    change(payload)
    write_json(path, payload)


def mutate_jsonl(path, change):
    rows = data.read_jsonl(path)
    rows = change(rows)
    write_jsonl(path, rows)


def drop_row(rows, question_id="t-prod-00"):
    return [r for r in rows if r["question_id"] != question_id]


def duplicate_row(rows):
    return [*rows, rows[-1]]


@pytest.mark.parametrize(
    ("target", "change", "error"),
    [
        (
            "results/baselines/manifest.json",
            lambda p: p["runs"]["public/bm25"].__setitem__("protocol_version", "eval-protocol-v1"),
            ComparisonError,
        ),
        (
            "results/baselines/manifest.json",
            lambda p: p["runs"]["public/bm25"]["inputs"]["queries"].__setitem__("sha256", "0" * 64),
            ComparisonError,
        ),
        (
            "results/experiments/synth/manifest.json",
            lambda p: p["runs"]["public/oracle"].__setitem__(
                "protocol_version", "eval-protocol-v1"
            ),
            ComparisonError,
        ),
        (
            "results/experiments/synth/manifest.json",
            lambda p: p["runs"]["public/oracle"]["inputs"]["corpus"].__setitem__(
                "sha256", "0" * 64
            ),
            ExperimentError,  # 잠금 해시에 입력 해시가 들어 있어 먼저 걸린다
        ),
    ],
)
def test_integration_mismatched_manifests_fail_the_comparison(root, synth, target, change, error):
    run_synth(root, synth, variants=["oracle"])
    mutate_json(root / target, change)
    with pytest.raises(error):
        harness.compute_outputs(synth, root, OUT)


@pytest.mark.parametrize(
    ("target", "change"),
    [
        ("results/baselines/public/bm25.jsonl", drop_row),
        ("results/baselines/public/bm25.jsonl", duplicate_row),
        ("results/experiments/synth/public/oracle.jsonl", drop_row),
        ("results/experiments/synth/public/oracle.jsonl", duplicate_row),
    ],
)
def test_integration_missing_or_duplicate_test_rows_fail(root, synth, cli, capsys, target, change):
    run_synth(root, synth, variants=["oracle"])
    mutate_jsonl(root / target, change)
    with pytest.raises(ComparisonError):
        harness.compute_outputs(synth, root, OUT)
    assert cli(["--exp", "synth", "--compare"]) == 1
    assert "error:" in capsys.readouterr().err


def test_current_input_file_change_fails_the_comparison(root, synth):
    run_synth(root, synth, variants=["oracle"])
    with (root / data.PUBLIC_QUERIES).open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(public_query("t-new", "새 질문", "no_answer", "test")) + "\n")
    with pytest.raises(ExperimentError):
        harness.compute_outputs(synth, root, OUT)


def test_run_fails_before_testing_when_the_baseline_is_not_comparable(root, synth):
    mutate_json(
        root / "results/baselines/manifest.json",
        lambda p: p["runs"]["public/bm25"]["inputs"]["queries"].__setitem__("sha256", "0" * 64),
    )
    with pytest.raises(ComparisonError):
        run_synth(root, synth, variants=["oracle"])
    assert not exp_dir(root).exists()  # 아무것도 쓰지 않았고 setup도 부르지 않았다
    assert synth.calls["setup"] == 0


# ------------------------------------------------------------ --compare 불일치와 종료 코드


def set_path(payload, path, delta):
    node = payload
    for part in path[:-1]:
        node = node[part]
    node[path[-1]] += delta


NUMERIC_TARGETS = [
    ("metrics.json", ("runs", "public/oracle", "test", "macro", "ndcg@10")),
    ("metrics.json", ("runs", "public/oracle", "dev", "n_questions")),
    ("comparison.json", ("comparisons", "public/oracle", "delta")),
    ("comparison.json", ("comparisons", "public/oracle", "ci95", "low")),
    ("comparison.json", ("comparisons", "public/oracle", "n_test_questions")),
]


@pytest.mark.parametrize(("filename", "path"), NUMERIC_TARGETS)
def test_compare_exits_1_when_a_number_changes_and_0_within_tolerance(
    cli, synth, root, capsys, filename, path
):
    run_synth(root, synth)
    target = exp_dir(root) / filename
    original = read_json(target)
    changed = copy.deepcopy(original)
    set_path(changed, path, 1e-12)
    write_json(target, changed)
    assert cli(["--exp", "synth", "--compare"]) == 0  # abs 1e-9 안의 차이는 허용
    changed = copy.deepcopy(original)
    set_path(changed, path, 1e-6)
    write_json(target, changed)
    capsys.readouterr()
    assert cli(["--exp", "synth", "--compare"]) == 1
    err = capsys.readouterr().err
    assert "compare FAILED" in err
    assert "mismatch: " + filename in err
    assert read_json(target) == changed  # 불일치여도 파일을 덮어쓰지 않는다


@pytest.mark.parametrize(
    "change",
    [
        lambda p: p["comparisons"]["public/oracle"].__setitem__("verdict", "hypothesis-rejected"),
        lambda p: p["primary"].__setitem__("verdict", "hypothesis-rejected"),
        lambda p: p["secondary"][0].__setitem__("verdict", "hypothesis-confirmed"),
        lambda p: p["comparisons"]["public/mixed"]["degraded"].pop(),
        lambda p: p["comparisons"]["public/mixed"]["improved_top10"][0].__setitem__(
            "rank_after", 7
        ),
        lambda p: p.__setitem__("primary", None),
    ],
)
def test_compare_exits_1_when_a_verdict_or_list_differs(cli, synth, root, change):
    run_synth(root, synth)
    mutate_json(exp_dir(root) / "comparison.json", change)
    assert cli(["--exp", "synth", "--compare"]) == 1


def test_compare_exits_1_when_stored_results_no_longer_reproduce_the_files(cli, synth, root):
    run_synth(root, synth)

    def lower_one_score(rows):
        for row in rows:
            if row["question_id"] == "t-prod-03":
                row["results"][0]["doc_id"] = "CVE-2026-1039"  # 다른 문서로 바꿔 순위를 깬다
        return rows

    mutate_jsonl(exp_dir(root) / "public/oracle.jsonl", lower_one_score)
    assert cli(["--exp", "synth", "--compare"]) == 1


def test_compare_exits_1_when_the_committed_files_are_missing(cli, synth, root):
    run_synth(root, synth)
    (exp_dir(root) / "comparison.json").unlink()
    assert cli(["--exp", "synth", "--compare"]) == 1


def test_compare_fails_when_the_manifest_lock_hash_was_edited(cli, synth, root):
    run_synth(root, synth)
    mutate_json(
        exp_dir(root) / "manifest.json",
        lambda p: p["runs"]["public/oracle"]["selected"]["config"].__setitem__("boost", 9.0),
    )
    assert cli(["--exp", "synth", "--compare"]) == 1


# ------------------------------------------------------------ test 잠금


def lock_hash(root):
    return read_json(exp_dir(root) / "manifest.json")["runs"]["public/oracle"]["test"][
        "config_hash"
    ]


@pytest.mark.parametrize("split", ["test", "all"])
def test_test_is_locked_against_a_different_config(root, synth, split):
    run_synth(root, synth, variants=["oracle"])
    before = snapshot(root)
    synth.FIXED = {"seed": 2}  # test를 돈 설정과 다른 고정 설정
    with pytest.raises(LockError):
        run_synth(root, synth, variants=["oracle"], split=split)
    assert snapshot(root) == before  # 실패하면 아무 파일도 건드리지 않는다


@pytest.mark.parametrize("split", ["test", "all"])
def test_lock_survives_a_dev_rerun(root, synth, split):
    run_synth(root, synth, variants=["oracle"])
    held = lock_hash(root)
    run_synth(root, synth, variants=["oracle"], split="dev")  # 같은 설정의 dev 재실행
    entry = read_json(exp_dir(root) / "manifest.json")["runs"]["public/oracle"]
    assert entry["test"]["config_hash"] == held  # 잠금이 지워지지 않았다
    assert entry["splits_stored"] == ["dev", "test"]
    ids = {r["question_id"] for r in data.read_jsonl(exp_dir(root) / "public/oracle.jsonl")}
    assert {q["id"] for q in QUERIES} == ids  # test 결과도 남아 있다
    comparison = read_json(exp_dir(root) / "comparison.json")
    assert comparison["primary"]["verdict"] == "hypothesis-confirmed"
    before = snapshot(root)
    synth.FIXED = {"seed": 2}
    with pytest.raises(LockError):
        run_synth(root, synth, variants=["oracle"], split=split)
    assert snapshot(root) == before


def test_dev_rerun_that_selects_another_config_is_refused_after_test(root, synth):
    run_synth(root, synth, variants=["oracle"])
    before = snapshot(root)
    synth.GRID = [{"boost": 3.0}]
    for split in ("dev", "all"):
        with pytest.raises(LockError, match="dev reselected"):
            run_synth(root, synth, variants=["oracle"], split=split)
    assert snapshot(root) == before


def test_same_config_rerun_is_a_reproduction_and_keeps_the_first_test_time(root, synth):
    run_synth(root, synth, variants=["oracle"])
    first = read_json(exp_dir(root) / "manifest.json")["runs"]["public/oracle"]["test"]
    results = (exp_dir(root) / "public/oracle.jsonl").read_bytes()
    run_synth(root, synth, variants=["oracle"], split="all")
    run_synth(root, synth, variants=["oracle"], split="test")
    again = read_json(exp_dir(root) / "manifest.json")["runs"]["public/oracle"]["test"]
    assert again == first
    assert (exp_dir(root) / "public/oracle.jsonl").read_bytes() == results


def test_lock_is_per_variant(root, synth):
    run_synth(root, synth, variants=["oracle"])
    synth.FIXED = {"seed": 2}
    run_synth(
        root, synth, variants=["copy"]
    )  # 다른 변형은 아직 test를 돌지 않았으니 새 설정으로 돈다
    with pytest.raises(LockError):
        run_synth(root, synth, variants=["oracle"])


def test_changed_queries_after_test_are_locked_and_before_test_are_refused(root, synth):
    run_synth(root, synth, variants=["oracle"], split="dev")
    with (root / data.PUBLIC_QUERIES).open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(public_query("t-new", "새 질문", "no_answer", "test")) + "\n")
    runner.run_baseline("public", "bm25", root)  # 기준선도 새 질의셋으로 맞춘다
    with pytest.raises(ExperimentError, match="inputs changed"):
        run_synth(root, synth, variants=["oracle"], split="test")
    run_synth(
        root, synth, variants=["oracle"], split="all"
    )  # 처음부터 돌리면 통과(아직 test 안 돌림)
    with (root / data.PUBLIC_QUERIES).open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(public_query("t-new2", "새 질문2", "no_answer", "test")) + "\n")
    runner.run_baseline("public", "bm25", root)
    with pytest.raises(LockError):
        run_synth(root, synth, variants=["oracle"], split="all")


def test_split_test_needs_a_dev_selection(root, synth):
    with pytest.raises(ExperimentError, match="dev-selected"):
        run_synth(root, synth, variants=["oracle"], split="test")


def test_split_dev_stores_only_dev_and_test_uses_the_frozen_config(root, synth):
    run_synth(root, synth, variants=["oracle"], split="dev")
    path = exp_dir(root) / "public/oracle.jsonl"
    dev_ids = {r["question_id"] for r in data.read_jsonl(path)}
    assert dev_ids == {q["id"] for q in QUERIES if q["split"] == "dev"}
    entry = read_json(exp_dir(root) / "manifest.json")["runs"]["public/oracle"]
    assert entry["splits_stored"] == ["dev"]
    assert "test" not in entry  # test를 돌기 전에는 잠금이 없다
    metrics = read_json(exp_dir(root) / "metrics.json")["runs"]["public/oracle"]
    assert set(metrics) == {"dev"}
    comparison = read_json(exp_dir(root) / "comparison.json")
    assert comparison["comparisons"] == {}  # test 전에는 비교하지 않는다
    selected = entry["selected"]
    synth.GRID = [{"boost": 5.0}]  # test 전용 실행은 격자를 다시 보지 않는다
    run_synth(root, synth, variants=["oracle"], split="test")
    after = read_json(exp_dir(root) / "manifest.json")["runs"]["public/oracle"]
    assert after["selected"] == selected
    assert after["test"]["config"] == selected["config"]
    assert after["splits_stored"] == ["dev", "test"]


def test_reproduction_inputs_are_recorded_hashed_and_locked(root, synth):
    write_jsonl(root / "fixtures/synth/translations.jsonl", [{"id": "a", "text": "한 번"}])
    synth.REPRO = {"translations": "fixtures/synth/translations.jsonl"}
    run_synth(root, synth, variants=["oracle"])
    entry = read_json(exp_dir(root) / "manifest.json")["runs"]["public/oracle"]
    recorded = entry["reproduction_inputs"]["translations"]
    assert recorded["path"] == "fixtures/synth/translations.jsonl"
    assert recorded["sha256"] == data.file_sha256(root / recorded["path"])
    write_jsonl(root / "fixtures/synth/translations.jsonl", [{"id": "a", "text": "두 번"}])
    with pytest.raises(LockError):
        run_synth(root, synth, variants=["oracle"], split="test")
    with pytest.raises(ComparisonError, match="reproduction input"):
        harness.compute_outputs(synth, root, OUT)


@pytest.mark.parametrize("bad", ["/etc/hosts", "../outside.jsonl", "missing.jsonl"])
def test_reproduction_input_paths_must_be_repo_relative_files(root, synth, bad):
    synth.REPRO = {"x": bad}
    with pytest.raises(ContractError):
        run_synth(root, synth, variants=["oracle"])


# ------------------------------------------------------------ 결과 파일 허용 필드, 경로·본문 비유출


def all_output_text(root):
    return "".join(p.read_text("utf-8") for p in sorted(exp_dir(root).rglob("*")) if p.is_file())


def test_results_files_have_only_allowed_fields_and_no_text(root, synth):
    run_synth(root, synth)
    for variant in synth.VARIANTS["public"]:
        rows = data.read_jsonl(exp_dir(root) / "public" / f"{variant}.jsonl")
        assert {r["question_id"] for r in rows} == {q["id"] for q in QUERIES}
        for row in rows:
            assert set(row) == scoring.RECORD_FIELDS
            scoring.validate_record(row)
            for item in row["results"]:
                assert set(item) == scoring.RESULT_FIELDS
    text = all_output_text(root)
    for query in QUERIES:
        assert query["query"] not in text
    for body in DOC_TEXTS.values():
        assert body not in text
    assert "취약점 설명" not in text


def test_outputs_contain_only_relative_paths(root, synth):
    run_synth(root, synth)
    text = all_output_text(root)
    assert str(root) not in text
    assert "/Users" not in text
    for filename in ("manifest.json", "metrics.json", "comparison.json"):
        assert harness.find_absolute_paths(read_json(exp_dir(root) / filename)) == []
    manifest = read_json(exp_dir(root) / "manifest.json")
    for entry in manifest["runs"].values():
        assert not Path(entry["stored_results"]["path"]).is_absolute()
        assert entry["baseline"]["stored_results"].startswith("results/baselines/")


def test_absolute_out_dir_is_recorded_as_the_default_relative_path(root, synth, tmp_path_factory):
    out = tmp_path_factory.mktemp("elsewhere")
    harness.run_experiment("synth", "public", root, variants=["oracle"], out_dir=out)
    entry = read_json(out / "synth/manifest.json")["runs"]["public/oracle"]
    assert entry["stored_results"]["path"] == "results/experiments/synth/public/oracle.jsonl"
    assert str(out) not in (out / "synth/manifest.json").read_text("utf-8")
    assert not exp_dir(root).exists()  # 다른 --out-dir은 기본 위치를 건드리지 않는다
    assert harness.verify_outputs(harness.load_experiment("synth"), root, out) == []


@pytest.mark.parametrize(
    "path", ["/Users/someone/cache", "/private/tmp/x", "C:\\Users\\x", "see /home/user/data now"]
)
def test_find_absolute_paths_flags_path_like_strings(path):
    assert harness.find_absolute_paths({"a": [path]}) == ["$.a[0]"]


@pytest.mark.parametrize("text", ["1 / (k + rank)", "results/experiments/x", "a/b", ""])
def test_find_absolute_paths_ignores_formulas_and_relative_paths(text):
    assert harness.find_absolute_paths({"a": text}) == []


def test_module_description_with_an_absolute_path_aborts_without_writing(root, synth):
    synth.NOTE = "/Users/someone/.cache/model"
    with pytest.raises(ContractError, match="absolute paths"):
        run_synth(root, synth, variants=["oracle"])
    assert not exp_dir(root).exists()


def test_scorer_output_with_invalid_scores_is_a_contract_error(root, synth):
    def make_scorer(state, config):
        return lambda question: {"CVE-2026-1000": float("nan")}

    synth.make_scorer = make_scorer
    with pytest.raises(ValueError, match="NaN"):
        run_synth(root, synth, variants=["oracle"])
    assert not exp_dir(root).exists()


# ------------------------------------------------------------ 모델·KISA 비접촉, import 규칙


def test_experiments_modules_do_not_import_model_packages():
    code = (
        "import sys\n"
        "import krsec_rag_lab.experiments.harness, krsec_rag_lab.experiments.compare\n"
        "import krsec_rag_lab.experiments.hybrid\n"
        "bad = [m for m in ('numpy', 'torch', 'sentence_transformers') if m in sys.modules]\n"
        "assert not bad, bad\n"
    )
    done = subprocess.run(
        [sys.executable, "-I", "-c", code], check=False, capture_output=True, text=True
    )
    assert done.returncode == 0, done.stderr


def test_kisa_track_without_kisa_root_is_a_parser_error(cli, synth, capsys):
    synth.VARIANTS = {"public": synth.VARIANTS["public"], "kisa": ("oracle",)}
    synth.BASELINES = {"public": "bm25", "kisa": "bm25"}
    with pytest.raises(SystemExit):
        cli(["--exp", "synth", "--track", "kisa"])
    assert "--kisa-root" in capsys.readouterr().err


def test_kisa_cache_failure_is_exit_1_without_leaking_the_path(monkeypatch, cli, synth, capsys):
    class FakeKisaError(Exception):
        pass

    class FakeKisa:
        KisaError = FakeKisaError

        @staticmethod
        def load_cached_body(root, ntt_id, document):
            raise FakeKisaError("cache_missing")

    synth.VARIANTS = {"public": synth.VARIANTS["public"], "kisa": ("oracle",)}
    synth.BASELINES = {"public": "bm25", "kisa": "bm25"}
    monkeypatch.setattr(run_experiment, "load_kisa_module", lambda: FakeKisa)
    write_kisa = {
        "documents": [{"nttId": "90001", "sha256": "0" * 64}],
    }
    (run_experiment.ROOT / "fixtures/kisa").mkdir(parents=True)
    (run_experiment.ROOT / data.KISA_MANIFEST).write_text(json.dumps(write_kisa), "utf-8")
    write_jsonl(run_experiment.ROOT / data.KISA_METADATA, [{"nttId": "90001", "title": "t"}])
    write_jsonl(run_experiment.ROOT / data.KISA_GOLDEN, [])
    code = cli(["--exp", "synth", "--track", "kisa", "--kisa-root", "/nowhere/secret-cache"])
    captured = capsys.readouterr()
    assert code == 1
    assert "error:" in captured.err
    assert "secret-cache" not in captured.err + captured.out


# ------------------------------------------------------------ final-review 수정: 저장 원자성, 오래된 입력


def test_lock_violation_in_a_later_variant_changes_no_files_and_runs_no_earlier_test(root, synth):
    run_synth(root, synth, variants=["copy"])
    before = snapshot(root)
    synth.GRID = [{"boost": 3.0}]  # copy가 test를 돈 설정과 다른 설정을 고르게 된다
    with pytest.raises(LockError):
        run_synth(root, synth)  # 변형 순서: oracle 먼저, copy에서 잠금 위반
    assert snapshot(root) == before  # oracle의 결과·manifest·잠금도 저장되지 않았다
    assert not (exp_dir(root) / "public/oracle.jsonl").exists()


def test_failure_while_regenerating_outputs_rolls_back_the_written_files(root, synth):
    run_synth(root, synth, variants=["worse"], split="dev")  # 잠금 없는 dev 전용 항목
    with (root / data.PUBLIC_QUERIES).open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(public_query("t-new", "새 질문", "no_answer", "test")) + "\n")
    runner.run_baseline("public", "bm25", root)  # 기준선도 새 질의셋에 맞춘다
    before = snapshot(root)
    with pytest.raises(ComparisonError, match="input hashes"):
        run_synth(root, synth, variants=["oracle"])  # worse 항목의 입력이 오래돼 재계산이 실패한다
    assert snapshot(root) == before  # oracle의 jsonl·manifest 항목이 남지 않았다


def test_dev_only_entries_are_checked_against_the_current_input_files(root, synth):
    run_synth(root, synth, variants=["oracle"], split="dev")
    rows = data.read_jsonl(root / data.PUBLIC_QUERIES)
    for row in rows:
        if row["id"] == "d-prod-1":
            row["gold"] = [doc_id(30)]  # 같은 질문 ID, 바뀐 정답 라벨
    write_jsonl(root / data.PUBLIC_QUERIES, rows)
    with pytest.raises(ComparisonError, match="input hashes"):
        harness.compute_outputs(synth, root, OUT)


# ------------------------------------------------------------ 변형별 기준선 (#47, 하위 호환)


class OracleDense:
    """가짜 dense 기준선: 정답 문서에 1.0, 나머지에 0.0을 준다(BM25와 다른 저장본). 모델을 부르지 않는다."""

    def __init__(self, texts):
        self.texts = texts
        self.meta = {
            "model": {"name": "fake", "revision": "fake", "n_truncated_docs": 0},
            "runtime": {"python": "fake"},
            "doc_encode_seconds": 0.0,
        }

    def score(self, query):
        gold = next(set(q["gold"]) for q in QUERIES if q["query"] == query)
        return {doc_id: 1.0 if doc_id in gold else 0.0 for doc_id in self.texts}


def run_dense_baseline(root):
    runner.run_baseline("public", "dense", root, dense_factory=OracleDense)


def per_variant_baselines(synth):
    """copy 변형은 BM25, 나머지는 dense 기준선과 비교하는 `{변형: 기준}` 형태."""
    synth.BASELINES = {
        "public": {"oracle": "dense", "copy": "bm25", "mixed": "dense", "worse": "bm25"}
    }


def test_baselines_may_map_variants_to_different_baselines(root, synth):
    run_dense_baseline(root)
    per_variant_baselines(synth)
    comparison = run_synth(root, synth)
    expected = synth.BASELINES["public"]
    assert comparison["primary"]["baseline"] == "dense"
    for variant, baseline in expected.items():
        block = comparison["comparisons"][f"public/{variant}"]
        assert block["baseline"] == baseline
    secondary = {item["variant"]: item["baseline"] for item in comparison["secondary"]}
    assert secondary == {"copy": "bm25", "mixed": "dense", "worse": "bm25"}
    manifest = read_json(exp_dir(root) / "manifest.json")["runs"]
    for variant, baseline in expected.items():
        assert manifest[f"public/{variant}"]["baseline"] == {
            "retriever": baseline,
            "stored_results": f"results/baselines/public/{baseline}.jsonl",
        }
    # 각 변형의 기준 값은 그 변형 기준선의 저장본에서 나온다(유형별 nDCG@10으로 확인)
    questions = data.load_questions("public", root)
    base_manifest = read_json(root / "results/baselines/manifest.json")["runs"]
    per_baseline = {}
    for baseline in ("dense", "bm25"):
        records = cmp.read_stored(root / f"results/baselines/public/{baseline}.jsonl")
        tau = base_manifest[f"public/{baseline}"]["selected"]["tau"]
        evaluated = scoring.evaluate_split(records, questions, "test", tau)
        per_baseline[baseline] = {
            t: v["metrics"]["ndcg@10"] for t, v in evaluated["by_type"].items() if v["n_scored"]
        }
    assert per_baseline["dense"] != per_baseline["bm25"]  # 두 기준선이 구별되는 입력이다
    for variant, baseline in expected.items():
        by_type = comparison["comparisons"][f"public/{variant}"]["by_type"]
        got = {t: v["metrics"]["ndcg@10"]["baseline"] for t, v in by_type.items()}
        assert got == per_baseline[baseline], variant
    assert harness.verify_outputs(synth, root, OUT) == []  # --compare도 변형별 기준선을 쓴다


def test_per_variant_baseline_mapping_equals_the_track_wide_name_when_all_agree(root, synth):
    track_wide = run_synth(root, synth)
    mapped_root = root / "mapped"
    mapped_root.mkdir()
    shutil.copytree(root / "eval", mapped_root / "eval")
    shutil.copytree(root / "fixtures", mapped_root / "fixtures")
    shutil.copytree(root / "results/baselines", mapped_root / "results/baselines")
    synth.BASELINES = {"public": dict.fromkeys(synth.VARIANTS["public"], "bm25")}
    mapped = harness.run_experiment(synth.NAME, "public", mapped_root)

    def strip_times(comparison):
        blocks = json.loads(json.dumps(comparison["comparisons"]))
        for block in blocks.values():
            block.pop("timing")
        return blocks

    assert strip_times(mapped) == strip_times(track_wide)


@pytest.mark.parametrize(
    ("baselines", "message"),
    [
        ({"public": {"oracle": "bm25"}}, "no baseline for variant"),
        (
            {"public": {"oracle": "bm25", "copy": 3, "mixed": "bm25", "worse": "bm25"}},
            "no baseline",
        ),
        ({"public": 3}, "bad baseline"),
        ({"public": {}}, "no baseline for variant"),
    ],
)
def test_a_baselines_mapping_must_cover_every_variant_with_names(monkeypatch, baselines, message):
    module = make_synth("badbase")
    module.BASELINES = baselines
    monkeypatch.setitem(sys.modules, "krsec_rag_lab.experiments.badbase", module)
    with pytest.raises(ContractError, match=message):
        harness.load_experiment("badbase")


def test_a_variant_baseline_that_is_not_stored_fails_before_any_test_run(root, synth):
    per_variant_baselines(synth)  # dense 기준선 저장본이 없다
    with pytest.raises(ExperimentError, match="dense"):
        run_synth(root, synth)
    assert not exp_dir(root).exists()


def test_the_pre_run_baseline_check_covers_only_the_selected_variants(root, synth):
    per_variant_baselines(synth)  # dense 기준선이 없지만 copy·worse는 bm25만 쓴다
    comparison = run_synth(root, synth, variants=["copy", "worse"])
    assert {block["baseline"] for block in comparison["comparisons"].values()} == {"bm25"}
