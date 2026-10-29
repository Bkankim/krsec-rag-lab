"""공개 평가 트랙 질의셋(#35) 테스트. fixture 전체와 합성 레코드만 쓴다(네트워크·KISA 캐시 없음)."""

import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path

import pytest

from krsec_rag_lab import public_eval
from krsec_rag_lab.public_eval import (
    MANIFEST_FILE,
    MIN_COUNTS,
    OUTPUT_FIELDS,
    PROTOCOL_VERSION,
    QUERIES_FILE,
    QUERY_TYPES,
    PublicSplitLeakError,
    assert_no_key_leak,
    assert_public_split,
    build,
    build_files,
    cpe_vendor_product,
    load_records,
)
from krsec_rag_lab.splits import CVE_ID_RE, SplitLeakError, assert_disjoint, extract_cve_ids

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixtures" / "nvd" / "cves.jsonl"
PUBLIC_DIR = ROOT / "eval" / "public"


@pytest.fixture(scope="module")
def raw_fixture():
    return FIXTURE.read_bytes()


@pytest.fixture(scope="module")
def records(raw_fixture):
    return load_records(raw_fixture)


@pytest.fixture(scope="module")
def committed_queries():
    lines = (PUBLIC_DIR / QUERIES_FILE).read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines]


@pytest.fixture(scope="module")
def committed_manifest():
    return json.loads((PUBLIC_DIR / MANIFEST_FILE).read_text(encoding="utf-8"))


def record(record_id, products, status="ok", published="2026-01-02T00:00:00.000"):
    cpe = [{"criteria": f"cpe:2.3:a:{p}:*:*:*:*:*:*:*:*"} for p in products]
    return {
        "id": record_id,
        "published": published,
        "cpe": cpe,
        "cpe_total": len(cpe),
        "vendor_products": sorted(products),
        "vendor_products_status": status,
    }


def query(query_id, split, gold=(), text="", vendor_product=None):
    return {
        "id": query_id,
        "query": text,
        "query_type": "product_symptom" if vendor_product else "cve_explicit",
        "gold": list(gold),
        "unjudged": [],
        "split": split,
        "vendor_product": vendor_product,
    }


# --- CPE 추출 --------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("criteria", "expected"),
    [
        ("cpe:2.3:a:h2database:h2:*:*:*:*:*:*:*:*", "h2database:h2"),
        ("cpe:2.3:o:debian:debian_linux:10.0:*:*:*:*:*:*:*", "debian:debian_linux"),
        ("cpe:2.3:a:microsoft:azure\\/msal-node:1.0:*:*:*:*:*:*:*", "microsoft:azure\\/msal-node"),
        # 이스케이프된 콜론은 필드 구분자가 아니다
        ("cpe:2.3:a:vend\\:or:prod:1.0:*:*:*:*:*:*:*", "vend\\:or:prod"),
        # 이스케이프된 역슬래시 뒤의 ':'는 구분자다
        ("cpe:2.3:a:foo\\\\:bar:1.0:*:*:*:*:*:*:*", "foo\\\\:bar"),
    ],
)
def test_cpe_vendor_product_extracts_raw_fields(criteria, expected):
    assert cpe_vendor_product(criteria) == expected


@pytest.mark.parametrize(
    "criteria",
    [
        "",
        "cpe:2.2:a:vendor:product:1.0",
        "cpe:2.3:a:vendor:product:1.0",
        "cpe:2.3:a:*:product:*:*:*:*:*:*:*:*",
        "cpe:2.3:a:vendor:-:*:*:*:*:*:*:*:*",
        "cpe:2.3:a:vendor:product:1:*:*:*:*:*:*:*:*",
    ],
)
def test_cpe_vendor_product_rejects_malformed_or_wildcard(criteria):
    with pytest.raises(ValueError, match="CPE"):
        cpe_vendor_product(criteria)


def test_load_records_requires_cpe_products_inside_vendor_products(raw_fixture):
    row = json.loads(raw_fixture.decode("utf-8").splitlines()[0])
    row["vendor_products"] = row["vendor_products"][1:]
    with pytest.raises(ValueError, match="not in vendor_products"):
        load_records((json.dumps(row) + "\n").encode("utf-8"))


def test_fixture_cpe_products_are_subset_of_vendor_products(records):
    # load_records가 이미 검사하지만 절단 레코드가 실제로 있어야 이 규칙이 의미가 있다
    truncated = [r for r in records if r["cpe_total"] > len(r["cpe"])]
    assert truncated
    assert any(
        set(r["vendor_products"]) - {cpe_vendor_product(c["criteria"]) for c in r["cpe"]}
        for r in truncated
    )


# --- 정답 규칙: fixture 전체로 재계산해 커밋 파일과 대조 ------------------------------------------------


def expected_product_gold_unjudged(all_records, vendor_product):
    gold, unjudged = [], []
    for r in all_records:
        if vendor_product in r["vendor_products"]:
            gold.append(r["id"])
        elif r["vendor_products_status"] in ("no_configurations", "drifted"):
            unjudged.append(r["id"])
    return sorted(gold), sorted(unjudged)


def test_committed_answers_match_recomputed_rules(committed_queries, records):
    corpus = {r["id"] for r in records}
    assert committed_queries
    for q in committed_queries:
        found = extract_cve_ids(q["query"])
        if q["query_type"] == "cve_explicit":
            assert len(found) == 1
            assert found[0] in corpus
            assert q["gold"] == found
            assert q["unjudged"] == []
            assert q["vendor_product"] is None
        elif q["query_type"] == "product_symptom":
            assert found == []
            gold, unjudged = expected_product_gold_unjudged(records, q["vendor_product"])
            assert public_eval.readable_vendor_product(q["vendor_product"]) in q["query"]
            assert "\\" not in q["query"]
            assert gold  # 뽑은 제품은 gold가 비지 않는다
            assert q["gold"] == gold
            assert q["unjudged"] == unjudged
            assert len(gold) <= public_eval.MAX_PRODUCT_GOLD
            assert not set(gold) & set(unjudged)
        else:
            assert q["query_type"] == "no_answer"
            assert len(found) == 1
            assert CVE_ID_RE.fullmatch(found[0])
            assert found[0] not in corpus
            assert q["gold"] == []
            assert q["unjudged"] == []


def test_product_gold_uses_untruncated_vendor_products_not_cpe(committed_queries, records):
    by_id = {r["id"]: r for r in records}
    cpe_products = {r["id"]: {cpe_vendor_product(c["criteria"]) for c in r["cpe"]} for r in records}
    beyond_cpe = 0
    for q in committed_queries:
        if q["query_type"] != "product_symptom":
            continue
        for record_id in q["gold"]:
            assert q["vendor_product"] in by_id[record_id]["vendor_products"]
            if q["vendor_product"] not in cpe_products[record_id]:
                beyond_cpe += 1
    # 절단된 cpe에는 없지만 vendor_products로 정답이 된 레코드가 실제로 있다
    assert beyond_cpe > 0


def test_no_configurations_records_are_unjudged_for_every_product_query(committed_queries, records):
    empty = sorted(r["id"] for r in records if r["vendor_products_status"] == "no_configurations")
    assert empty
    product_queries = [q for q in committed_queries if q["query_type"] == "product_symptom"]
    assert product_queries
    for q in product_queries:
        assert set(empty) <= set(q["unjudged"])
        assert not set(empty) & set(q["gold"])


def test_drifted_unjudged_only_when_product_missing():
    corpus = [
        record("CVE-2026-0001", ["a:one"]),
        record("CVE-2026-0002", ["a:one", "b:two"], status="drifted"),
        record("CVE-2026-0003", ["c:three"], status="drifted"),
        record("CVE-2026-0004", [], status="no_configurations"),
    ]
    assert public_eval.product_index(corpus)["a:one"] == ["CVE-2026-0001", "CVE-2026-0002"]
    # drifted인데 제품이 vendor_products에 있으면 gold, 없으면 unjudged
    assert public_eval.product_unjudged(corpus, "a:one") == ["CVE-2026-0003", "CVE-2026-0004"]
    assert public_eval.product_unjudged(corpus, "c:three") == [
        "CVE-2026-0002",
        "CVE-2026-0004",
    ]
    assert public_eval.product_unjudged(corpus, "b:two") == ["CVE-2026-0003", "CVE-2026-0004"]


# --- 분할 -------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("first", "second", "kind"),
    [
        # 같은 vendor:product를 공유하는 두 질의가 다른 split에 있다
        (
            query("p1", "dev", gold=["CVE-2026-0001"], text="x:y 제품", vendor_product="x:y"),
            query("p2", "test", gold=["CVE-2026-0002"], text="x:y 제품", vendor_product="x:y"),
            "product",
        ),
        # 같은 CVE를 정답으로 공유한다
        (
            query("p1", "dev", gold=["CVE-2026-0001"], text="a:b 제품", vendor_product="a:b"),
            query("c1", "test", gold=["CVE-2026-0001"], text="CVE-2026-0001는?"),
            "cve",
        ),
        # 질문에 적힌 CVE ID를 공유한다(no_answer)
        (
            query("n1", "dev", text="CVE-2026-9999는 무엇인가요?"),
            query("n2", "test", text="CVE-2026-9999를 찾아주세요."),
            "cve",
        ),
    ],
)
def test_shared_key_across_splits_is_rejected(first, second, kind):
    with pytest.raises(PublicSplitLeakError) as raised:
        assert_no_key_leak([first, second])
    assert [leak[0] for leak in raised.value.leaks] == [kind]


def test_same_split_sharing_keys_is_allowed():
    queries = [
        query("p1", "dev", gold=["CVE-2026-0001"], text="x:y", vendor_product="x:y"),
        query("p2", "dev", gold=["CVE-2026-0001"], text="x:y", vendor_product="x:y"),
    ]
    assert_no_key_leak(queries)


def test_committed_split_passes_all_checks(committed_queries, records):
    assert_no_key_leak(committed_queries)
    assert_public_split(committed_queries, records)
    _, notices = public_eval.split_check_inputs(committed_queries, records)
    assert len(notices) == len(records)
    assert all(row["nttId"] == row["title"] == row["cve_ids"][0] for row in notices)


def test_splits_assert_disjoint_rejects_mapped_cve_overlap(records):
    # 같은 gold 레코드를 가진 질의를 양쪽 split에 두면 splits.assert_disjoint도 거부한다
    shared = records[0]["id"]
    queries = [
        query("p1", "dev", gold=[shared], text="a:b 제품", vendor_product="a:b"),
        query("c1", "test", gold=[shared], text=f"{shared}는?"),
    ]
    items, notices = public_eval.split_check_inputs(queries, records)
    with pytest.raises(SplitLeakError):
        assert_disjoint(items, notices)


def test_connected_components_stay_within_one_split_and_under_cap(committed_queries):
    keys = {
        q["id"]: {f"cve:{r}" for r in q["gold"]}
        | {f"cve:{c}" for c in extract_cve_ids(q["query"])}
        | ({f"product:{q['vendor_product']}"} if q["vendor_product"] else set())
        for q in committed_queries
    }
    by_key = defaultdict(list)
    for query_id, query_keys in keys.items():
        for key in query_keys:
            by_key[key].append(query_id)
    seen, sizes = set(), []
    split_of = {q["id"]: q["split"] for q in committed_queries}
    for start in keys:
        if start in seen:
            continue
        stack, component = [start], set()
        while stack:
            node = stack.pop()
            if node in component:
                continue
            component.add(node)
            stack.extend(n for key in keys[node] for n in by_key[key])
        seen |= component
        sizes.append(len(component))
        assert len({split_of[n] for n in component}) == 1
    total = len(committed_queries)
    assert max(sizes) <= public_eval.COMPONENT_CAP * total


def test_component_cap_excludes_products_and_is_recorded(records, monkeypatch):
    index = public_eval.product_index(records)
    monkeypatch.setattr(public_eval, "COMPONENT_CAP", 0.04)
    queries, stats = public_eval._draw(records, index, public_eval.SEED)
    assert stats["large_component_products"] >= 1
    assert stats["cap_queries"] == 5
    assert Counter(q["query_type"] for q in queries)["product_symptom"] == (
        public_eval.N_PRODUCT_SYMPTOM
    )


def test_products_with_large_gold_are_excluded(committed_queries, committed_manifest, records):
    index = public_eval.product_index(records)
    big = {key for key, ids in index.items() if len(ids) > public_eval.MAX_PRODUCT_GOLD}
    assert big
    assert committed_manifest["excluded_products"]["gold_over_max"]["count"] == len(big)
    assert not big & {q["vendor_product"] for q in committed_queries}


def test_redraw_uses_next_seed_and_logs_attempts(records, raw_fixture, monkeypatch):
    sha = hashlib.sha256(raw_fixture).hexdigest()
    real = public_eval._split_problem
    calls = []

    def fail_first(queries):
        calls.append(1)
        return "forced" if len(calls) == 1 else real(queries)

    monkeypatch.setattr(public_eval, "_split_problem", fail_first)
    _, manifest = build(records, sha)
    assert manifest["seed"] == public_eval.SEED
    assert manifest["seed_used"] == public_eval.SEED + 1
    assert [a["accepted"] for a in manifest["attempts"]] == [False, True]
    assert manifest["attempts"][0]["reason"] == "forced"


def test_build_fails_after_max_redraws(records, raw_fixture, monkeypatch):
    sha = hashlib.sha256(raw_fixture).hexdigest()
    monkeypatch.setattr(public_eval, "_split_problem", lambda queries: "forced")
    with pytest.raises(RuntimeError, match="no valid split"):
        build(records, sha)


# --- 건수·manifest·출력 필드 ------------------------------------------------------------------


def test_counts_meet_minimums_and_match_manifest(committed_queries, committed_manifest):
    by_type = Counter(q["query_type"] for q in committed_queries)
    assert set(by_type) == set(QUERY_TYPES)
    for query_type, minimum in MIN_COUNTS.items():
        assert by_type[query_type] >= minimum
    counts = committed_manifest["counts"]
    assert counts["total"] == len(committed_queries)
    assert counts["by_type"] == dict(sorted(by_type.items()))
    by_split = Counter(q["split"] for q in committed_queries)
    assert counts["by_split"] == dict(sorted(by_split.items()))
    for query_type in QUERY_TYPES:
        expected = Counter(q["split"] for q in committed_queries if q["query_type"] == query_type)
        assert counts["by_type_split"][query_type] == dict(sorted(expected.items()))
    ratio = by_split["dev"] / len(committed_queries)
    assert 0.30 <= ratio <= 0.50
    assert counts["dev_ratio"] == round(ratio, 4)


def test_manifest_records_inputs_and_rules(committed_manifest, raw_fixture):
    manifest = committed_manifest
    assert manifest["protocol_version"] == PROTOCOL_VERSION == "eval-protocol-v2"
    assert manifest["input"]["sha256"] == hashlib.sha256(raw_fixture).hexdigest()
    assert manifest["input"]["records"] == 1560
    assert manifest["language"] == {"query": "ko", "document": "en"}
    assert manifest["track"] == "public"
    assert manifest["query_fields"] == list(OUTPUT_FIELDS)
    assert "explanation_comparison" in manifest["generation_rules"]
    assert "만들지 않는다" in manifest["generation_rules"]["explanation_comparison"]
    assert manifest["cpe_rules"]["vendor_product_extraction"]
    assert manifest["cpe_rules"]["truncation"]
    assert manifest["unjudged"]["from_cpe_truncation"] == 0
    assert manifest["unjudged"]["vendor_products_status_counts"]["no_configurations"] == 39
    assert manifest["unjudged"]["unjudged_ids_per_product_query"] == [39]
    assert manifest["excluded_products"]["gold_over_max"]["count"] == 13
    assert manifest["attempts"][-1]["accepted"] is True
    queries_bytes = (PUBLIC_DIR / QUERIES_FILE).read_bytes()
    assert manifest["query_file_sha256"] == hashlib.sha256(queries_bytes).hexdigest()


def test_output_fields_and_no_description_text(committed_queries, records):
    ids = [q["id"] for q in committed_queries]
    assert len(set(ids)) == len(ids)
    for q in committed_queries:
        assert tuple(sorted(q)) == tuple(sorted(OUTPUT_FIELDS))
        assert isinstance(q["gold"], list)
        assert isinstance(q["unjudged"], list)
        assert q["gold"] == sorted(q["gold"])
        assert q["split"] in ("dev", "test")
    # 질의셋은 NVD 설명 원문을 담지 않는다
    blob = (PUBLIC_DIR / QUERIES_FILE).read_text(encoding="utf-8") + (
        PUBLIC_DIR / MANIFEST_FILE
    ).read_text(encoding="utf-8")
    for r in records:
        description = r["description_en"].strip()
        if len(description) >= 40:
            assert description[:40] not in blob


# --- 멱등·커밋 출력 일치 -----------------------------------------------------------------------


def test_build_is_idempotent():
    assert build_files(ROOT) == build_files(ROOT)


def test_committed_output_equals_fresh_build():
    fresh = build_files(ROOT)
    for name, text in fresh.items():
        assert (PUBLIC_DIR / name).read_text(encoding="utf-8") == text


def test_seed_changes_output():
    assert build_files(ROOT, seed=public_eval.SEED + 100) != build_files(ROOT)


def test_main_writes_files_with_same_hashes(tmp_path):
    fixture_dir = tmp_path / "fixtures" / "nvd"
    fixture_dir.mkdir(parents=True)
    (fixture_dir / "cves.jsonl").write_bytes(FIXTURE.read_bytes())
    assert public_eval.main(["--root", str(tmp_path)]) == 0
    first = {
        p.name: hashlib.sha256(p.read_bytes()).hexdigest()
        for p in (tmp_path / "eval/public").iterdir()
    }
    assert public_eval.main(["--root", str(tmp_path)]) == 0
    second = {
        p.name: hashlib.sha256(p.read_bytes()).hexdigest()
        for p in (tmp_path / "eval/public").iterdir()
    }
    assert first == second
    for name in (QUERIES_FILE, MANIFEST_FILE):
        assert first[name] == hashlib.sha256((PUBLIC_DIR / name).read_bytes()).hexdigest()


# --- 리뷰 반영(C2, C4, C7) ---------------------------------------------------------------------


def test_no_answer_ids_skip_cve_ids_cited_in_descriptions(monkeypatch):
    import random

    cited = {"description_en": "Similar to CVE-2026-1000 and CVE-2026-1001."}
    assert public_eval.cited_cve_ids([cited, {"description_en": ""}]) == {
        "CVE-2026-1000",
        "CVE-2026-1001",
    }
    # 후보 번호 범위를 인용된 두 ID로 좁혀, 제외 규칙이 없으면 반드시 걸리게 한다
    monkeypatch.setattr(public_eval, "NO_ANSWER_YEARS", (2026,))
    monkeypatch.setattr(
        random.Random, "randint", lambda self, a, b: self.choice([1000, 1001, 1002])
    )
    ids = public_eval._no_answer_ids(
        random.Random(0), {"CVE-2026-1002"} | public_eval.cited_cve_ids([cited]), 0
    )
    assert ids == []
    found = public_eval._no_answer_ids(random.Random(0), public_eval.cited_cve_ids([cited]), 1)
    assert found == ["CVE-2026-1002"]


def test_committed_no_answer_ids_are_not_cited_in_any_description(committed_queries, records):
    cited = public_eval.cited_cve_ids(records)
    assert cited
    no_answer = [q for q in committed_queries if q["query_type"] == "no_answer"]
    assert no_answer
    for q in no_answer:
        assert not set(extract_cve_ids(q["query"])) & cited


@pytest.mark.parametrize(
    ("raw", "readable"),
    [
        ("microsoft:azure\\/msal-node", "microsoft:azure/msal-node"),
        ("cisco:ios_xr", "cisco:ios_xr"),
        ("foo\\\\:bar", "foo\\:bar"),
    ],
)
def test_readable_vendor_product_unescapes_cpe(raw, readable):
    assert public_eval.readable_vendor_product(raw) == readable


def test_escaped_product_question_is_readable_but_key_stays_raw(committed_queries):
    escaped = [q for q in committed_queries if q["vendor_product"] == "microsoft:azure\\/msal-node"]
    assert len(escaped) == 1
    assert "microsoft:azure/msal-node" in escaped[0]["query"]
    assert "\\" not in escaped[0]["query"]


def test_main_output_has_lf_only_bytes(tmp_path):
    fixture_dir = tmp_path / "fixtures" / "nvd"
    fixture_dir.mkdir(parents=True)
    (fixture_dir / "cves.jsonl").write_bytes(FIXTURE.read_bytes())
    assert public_eval.main(["--root", str(tmp_path)]) == 0
    for name in (QUERIES_FILE, MANIFEST_FILE):
        assert b"\r" not in (tmp_path / "eval/public" / name).read_bytes()
