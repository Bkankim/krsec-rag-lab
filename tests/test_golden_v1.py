"""골든셋 v1 스키마 확장(excluded, unjudged)과 커밋된 교차 판정 산출물 검사. 모델도 KISA 본문도 쓰지 않는다."""

import json
from pathlib import Path

import pytest

from krsec_rag_lab import golden, judge
from krsec_rag_lab.golden import JUDGE_OUTPUT_FIELDS
from krsec_rag_lab.splits import assert_disjoint

ROOT = Path(__file__).resolve().parents[1]
SHA = "a" * 64
PARSER = "kisa-html-v1"


def read_jsonl(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def answer(doc_id="1", **extra):
    return {
        "doc_id": doc_id,
        "doc_sha256": SHA,
        "evidence": [{"parser_version": PARSER, "start": 0, "end": 5}],
        "reason": "A:cve_discussed B:cve_discussed",
        **extra,
    }


def record(**overrides):
    base = {
        "question_id": "q1",
        "query": "제품 질문입니다",
        "query_type": "product_symptom",
        "answers": [answer()],
    }
    return {**base, **overrides}


CATALOG = [
    {"nttId": "1", "title": "공지 1", "date": "2026-01-01", "cve_ids": []},
    {"nttId": "2", "title": "공지 2", "date": "2026-02-01", "cve_ids": []},
]


def errors_of(*records, **kwargs):
    return golden.validate_golden(list(records), notices=CATALOG, **kwargs)


# ------------------------------------------------------------ excluded, unjudged


def test_an_excluded_record_with_empty_answers_is_valid_and_lists_its_unjudged_docs():
    assert errors_of(record(answers=[], excluded=True, unjudged=["1", "2"])) == []


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"answers": []}, "needs at least one answer"),
        ({"answers": [], "excluded": False}, "needs at least one answer"),
        ({"excluded": True}, "excluded record must have empty answers"),
        ({"answers": [], "excluded": "yes"}, "excluded must be a bool"),
        ({"answers": [], "excluded": True, "unjudged": "1"}, "unjudged must be a list"),
        (
            {"answers": [], "excluded": True, "unjudged": [1]},
            "unjudged entries must be non-empty strings",
        ),
        ({"answers": [], "excluded": True, "unjudged": ["9"]}, "not in notice catalog"),
        ({"answers": [], "excluded": True, "unjudged": ["1", "1"]}, "duplicate doc_id in unjudged"),
        ({"unjudged": ["1"]}, "both in answers and unjudged"),
        (
            {"query_type": "no_answer", "answers": [], "no_answer_reason": "r", "excluded": True},
            "no_answer is never excluded",
        ),
        (
            {
                "answers": [
                    answer(
                        evidence=[{"parser_version": PARSER, "start": 0, "end": 5, "judge": "C"}]
                    )
                ]
            },
            "judge must be A or B",
        ),
    ],
)
def test_excluded_and_unjudged_rules(overrides, message):
    assert any(message in e for e in errors_of(record(**overrides))), message


def test_both_judges_evidence_spans_are_valid_in_one_answer():
    spans = [
        {"parser_version": PARSER, "start": 3, "end": 9, "judge": "A"},
        {"parser_version": PARSER, "start": 5, "end": 20, "judge": "B"},
    ]
    assert errors_of(record(answers=[answer(evidence=spans)], unjudged=["2"])) == []


def test_unjudged_may_be_empty_on_a_scored_record():
    assert errors_of(record(unjudged=[])) == []


def test_body_text_fields_are_still_rejected_next_to_the_new_fields():
    errors = errors_of(record(answers=[], excluded=True, unjudged=[], excerpt="x"))
    assert any("body text field not allowed: excerpt" in e for e in errors)


def test_validate_cli_accepts_an_excluded_record(tmp_path):
    root = tmp_path
    (root / "fixtures" / "kisa").mkdir(parents=True)
    (root / "fixtures" / "kisa" / "metadata.jsonl").write_text(
        "".join(json.dumps(n) + "\n" for n in CATALOG), encoding="utf-8"
    )
    (root / "fixtures" / "kisa" / "manifest.json").write_text(
        json.dumps(
            {
                "parser_version": PARSER,
                "documents": [{"nttId": n["nttId"], "sha256": SHA} for n in CATALOG],
            }
        ),
        encoding="utf-8",
    )
    path = tmp_path / "golden.jsonl"
    path.write_text(
        json.dumps(record(answers=[], excluded=True, unjudged=["1"])) + "\n", encoding="utf-8"
    )
    assert golden.main(["validate", str(path), "--root", str(root)]) == 0


# ------------------------------------------------------------ v1 요구


def v1_records(n_dev=21, n_test=31, mix=None):
    """채점 대상 52건: cve 18, product 12, explanation 12, no_answer 10 (유형 수는 mix로 바꾼다)."""
    mix = mix or {
        "cve_explicit": 18,
        "product_symptom": 12,
        "explanation_comparison": 12,
        "no_answer": 10,
    }
    types = [t for t, n in mix.items() for _ in range(n)]
    return [
        {
            "question_id": f"q{i}",
            "query_type": t,
            "split": "dev" if i < n_dev else "test",
            "excluded": False,
        }
        for i, t in enumerate(types)
    ]


def test_check_golden_v1_passes_a_conforming_set():
    assert golden.check_golden_v1(v1_records()) == []


@pytest.mark.parametrize(
    ("mix", "message"),
    [
        (
            {
                "cve_explicit": 14,
                "product_symptom": 14,
                "explanation_comparison": 14,
                "no_answer": 10,
            },
            "cve_explicit records 14 < 15",
        ),
        (
            {
                "cve_explicit": 15,
                "product_symptom": 9,
                "explanation_comparison": 18,
                "no_answer": 10,
            },
            "product_symptom records 9 < 10",
        ),
        (
            {
                "cve_explicit": 15,
                "product_symptom": 18,
                "explanation_comparison": 9,
                "no_answer": 10,
            },
            "explanation_comparison records 9 < 10",
        ),
        (
            {
                "cve_explicit": 15,
                "product_symptom": 15,
                "explanation_comparison": 15,
                "no_answer": 9,
            },
            "no_answer records 9 < 10",
        ),
        (
            {
                "cve_explicit": 15,
                "product_symptom": 10,
                "explanation_comparison": 10,
                "no_answer": 14,
            },
            "scored records 49 < 50",
        ),
    ],
)
def test_check_golden_v1_per_type_minimums_and_total(mix, message):
    records = v1_records(n_dev=sum(mix.values()) * 2 // 5, mix=mix)
    assert any(message in e for e in golden.check_golden_v1(records)), message


@pytest.mark.parametrize(
    ("n_dev", "ok"),
    [(15, False), (16, True), (21, True), (26, True), (27, False)],
)
def test_check_golden_v1_dev_share_is_thirty_to_fifty_percent_of_scored(n_dev, ok):
    # 52건 기준: 15/52 = 28.8%, 16/52 = 30.8%, 26/52 = 50%, 27/52 = 51.9%
    errors = golden.check_golden_v1(v1_records(n_dev=n_dev))
    assert (errors == []) is ok, errors


def test_check_golden_v1_ignores_excluded_records_in_every_count():
    records = v1_records()
    records += [
        {"question_id": f"x{i}", "query_type": "cve_explicit", "split": "test", "excluded": True}
        for i in range(30)
    ]
    assert golden.check_golden_v1(records) == []


def test_check_golden_v1_requires_a_split_on_every_record():
    records = v1_records()
    del records[3]["split"]
    assert any("q3" in e and "split is missing" in e for e in golden.check_golden_v1(records))


# ------------------------------------------------------------ 커밋된 산출물


GOLDEN = ROOT / golden.GOLDEN_V1_FILE


def committed_notices():
    notices = golden.load_notices(ROOT / golden.KISA_METADATA)
    parser_version, versions = golden.load_doc_versions(ROOT / golden.KISA_MANIFEST)
    return notices, versions, parser_version


def test_committed_golden_v1_passes_the_validate_command(capsys):
    assert golden.main(["validate", str(GOLDEN), "--root", str(ROOT)]) == 0
    assert capsys.readouterr().err == ""


def test_committed_golden_v1_meets_the_v1_requirements():
    records = read_jsonl(GOLDEN)
    assert golden.check_golden_v1(records) == []
    scored = [r for r in records if not r["excluded"]]
    assert len(scored) >= 50
    for query_type, minimum in golden.V1_MIN_PER_TYPE.items():
        assert sum(1 for r in scored if r["query_type"] == query_type) >= minimum
    dev = sum(1 for r in scored if r["split"] == "dev") / len(scored)
    assert 0.30 <= dev <= 0.50


def test_committed_golden_v1_split_is_disjoint():
    notices, _, _ = committed_notices()
    records = read_jsonl(GOLDEN)
    assert all(r.get("split") in ("dev", "test") for r in records)
    assert_disjoint(
        [
            {
                "id": r["question_id"],
                "split": r["split"],
                "ntt_ids": [a["doc_id"] for a in r["answers"]],
                "cve_ids": r.get("cve_ids", []),
                "query": r["query"],
            }
            for r in records
        ],
        notices,
    )


@pytest.mark.parametrize("rel", sorted(JUDGE_OUTPUT_FIELDS))
def test_committed_judge_outputs_are_on_the_judge_allowlist(rel):
    assert golden.check_output_fields(ROOT / rel, JUDGE_OUTPUT_FIELDS[rel]) == []


def test_judge_and_candidate_allowlists_cover_different_files_and_no_body_text_fields():
    assert not set(JUDGE_OUTPUT_FIELDS) & set(golden.OUTPUT_FIELDS)
    assert not golden.FORBIDDEN_TEXT_FIELDS & set().union(*JUDGE_OUTPUT_FIELDS.values())


def test_committed_judge_outputs_hold_no_nvd_text():
    paths = [ROOT / rel for rel in JUDGE_OUTPUT_FIELDS]
    assert golden.check_no_nvd_text(paths, ROOT / golden.NVD_CVES) == []


def load_judgments():
    rows = {
        name: read_jsonl(ROOT / rel)
        for name, rel in (("A", golden.JUDGMENTS_A_FILE), ("B", golden.JUDGMENTS_B_FILE))
    }

    def as_judgment(row):
        return judge.Judgment(
            row["question_id"],
            row["doc_id"],
            row["relevance"],
            row["reason_code"],
            tuple((e["start"], e["end"]) for e in row["evidence"]),
            row["truncated"],
            row["status"],
        )

    return {
        name: {(r["question_id"], r["doc_id"]): as_judgment(r) for r in rs}
        for name, rs in rows.items()
    }


def test_judgment_files_cover_the_same_pairs_and_use_only_fixed_codes():
    judgments = load_judgments()
    assert set(judgments["A"]) == set(judgments["B"])
    for per_judge in judgments.values():
        for item in per_judge.values():
            assert item.status in (judge.STATUS_OK, judge.STATUS_NO_EVIDENCE, judge.STATUS_INVALID)
            assert item.reason_code in (*judge.REASON_CODE_NAMES, None)
            if item.status == judge.STATUS_OK and item.relevance == judge.RELEVANT:
                assert item.evidence and all(0 <= s < e for s, e in item.evidence)


def test_error_rates_recompute_from_the_committed_judgments():
    judgments = load_judgments()
    pairs = read_jsonl(ROOT / golden.PAIRS_FILE)
    keys = [(p["candidate_question_id"], p["doc_id"]) for p in pairs]
    resolutions = [judge.resolve_pair(judgments["A"][k], judgments["B"][k]) for k in keys]
    in_candidate = {k: p["in_candidate_set"] for k, p in zip(keys, pairs, strict=True)}
    stored = json.loads((ROOT / golden.ERROR_RATES_FILE).read_text(encoding="utf-8"))
    summary = judge.summarize(resolutions)

    assert stored["counts"]["attempted_pairs"] == summary["n_pairs"] == len(pairs)
    assert stored["counts"]["valid_pairs"] == summary["n_valid_pairs"] >= 30
    assert stored["counts"]["agree_pairs"] == summary["n_agree"]
    assert stored["counts"]["disagree_pairs"] == summary["n_disagree"]
    assert stored["counts"]["unjudged_pairs"] == summary["n_unjudged"]
    assert stored["kappa"] == summary["kappa"]
    rates = judge.error_rate(resolutions, in_candidate)
    assert stored["mislabel"] == rates["mislabel"] and stored["omission"] == rates["omission"]
    assert stored["mislabel"]["denominator"] > 0 and stored["omission"]["denominator"] > 0
    assert stored["meets_min_valid_pairs"] is True


def test_zero_strata_keep_the_candidate_manifest_reason_verbatim():
    stored = json.loads((ROOT / golden.ERROR_RATES_FILE).read_text(encoding="utf-8"))
    candidates = json.loads((ROOT / golden.MANIFEST_FILE).read_text(encoding="utf-8"))
    expected = {s["stratum"]: s["zero_reason"] for s in candidates["sampling"]["strata"]}
    assert {s["stratum"]: s["zero_reason"] for s in stored["sample"]["strata"]} == expected
    assert expected[golden.STRATUM_A]


def test_golden_records_are_exactly_what_the_two_judges_agreed_on():
    judgments = load_judgments()
    by_question: dict[str, list[str]] = {}
    for question_id, doc_id in judgments["A"]:
        by_question.setdefault(question_id, []).append(doc_id)
    versions = committed_notices()[1]
    for record in read_jsonl(GOLDEN):
        docs = by_question[record["question_id"]]
        resolutions = {
            d: judge.resolve_pair(
                judgments["A"][(record["question_id"], d)],
                judgments["B"][(record["question_id"], d)],
            )
            for d in docs
        }
        if record["query_type"] == "no_answer":
            assert all(
                r.valid and r.a.label() == judge.NOT_RELEVANT == r.b.label()
                for r in resolutions.values()
            )
            assert record["answers"] == [] and record["excluded"] is False
            assert set(record["unjudged"]) == {
                d for d, r in resolutions.items() if r.outcome == judge.UNJUDGED
            }
            continue
        gold = {d for d, r in resolutions.items() if r.outcome == judge.GOLD}
        assert {a["doc_id"] for a in record["answers"]} == gold
        assert set(record["unjudged"]) == {
            d for d, r in resolutions.items() if r.outcome == judge.UNJUDGED
        }
        assert record["excluded"] is (not gold)
        for item in record["answers"]:
            r = resolutions[item["doc_id"]]
            assert item["doc_sha256"] == versions[item["doc_id"]]
            assert {(e["judge"], e["start"], e["end"]) for e in item["evidence"]} == {
                *(("A", s, e) for s, e in r.a.evidence),
                *(("B", s, e) for s, e in r.b.evidence),
            }
            assert item["reason"] == f"A:{r.a.reason_code} B:{r.b.reason_code}"


def test_agreement_file_matches_a_recount_of_the_judgments():
    judgments = load_judgments()
    agreement = json.loads((ROOT / golden.AGREEMENT_FILE).read_text(encoding="utf-8"))
    tasks = {t["task"]: t for t in agreement["tasks"]}
    assert set(tasks) == {"error_rate_sample", *golden.QUERY_TYPES}
    by_type: dict[str, list] = {}
    for record in read_jsonl(GOLDEN):
        by_type.setdefault(record["query_type"], [])
    for key in judgments["A"]:
        if key[0].startswith("cq-"):
            by_type.setdefault("error_rate_sample", []).append(key)
        elif key[0].startswith("g1-na-"):
            by_type["no_answer"].append(key)
        elif key[0].startswith("g1-cve-"):
            by_type["cve_explicit"].append(key)
        elif key[0].startswith("g1-ps-"):
            by_type["product_symptom"].append(key)
        else:
            by_type["explanation_comparison"].append(key)
    for task, keys in by_type.items():
        summary = judge.summarize(
            [judge.resolve_pair(judgments["A"][k], judgments["B"][k]) for k in keys]
        )
        stored = {k: v for k, v in tasks[task].items() if k != "task"}
        assert stored == summary, task


def test_manifest_counts_match_the_judgment_rows_and_records():
    manifest = json.loads((ROOT / golden.JUDGE_MANIFEST_FILE).read_text(encoding="utf-8"))
    records = read_jsonl(GOLDEN)
    assert manifest["counts"]["records"] == len(records)
    assert manifest["counts"]["scored"] == sum(1 for r in records if not r["excluded"])
    assert manifest["calls"]["total"] == sum(c["n"] for c in manifest["calls"]["by_kind"])
    assert manifest["calls"]["total"] >= 2 * len(read_jsonl(ROOT / golden.JUDGMENTS_A_FILE)) // 8
    assert (
        manifest["calls"]["question_generation"] <= manifest["calls"]["caps"]["question_generation"]
    )
    assert (
        manifest["calls"]["no_answer_attempts"]
        <= manifest["calls"]["caps"]["no_answer_attempts"]
        == 20
    )
    assert manifest["judged_at"]["first"] and manifest["judged_at"]["last"]
    assert [j["model"] for j in manifest["judges"]] == ["claude-opus-5-5", "gpt-6.1-sol"]
    assert manifest["prompts"]["judge_sha256"] == judge.JUDGE_PROMPT_SHA256
    assert all("<KISA 캐시가 있는 체크아웃>" in c for c in manifest["reproduce"])
    assert [i["path"] for i in manifest["judged_inputs"]] == [i["path"] for i in manifest["inputs"]]
    assert manifest["inputs_note"]
    for item in manifest["inputs"]:
        assert item["sha256"] == golden.file_sha256(ROOT / item["path"]), item["path"]
