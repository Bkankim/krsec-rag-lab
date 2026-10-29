"""증분 동기화 테스트: 합성 스냅샷, 가짜 인코더, 가짜 인덱스 백엔드만 쓴다(Qdrant·모델·KISA 캐시 없음)."""

import hashlib
import json
import re
import uuid
from array import array
from pathlib import Path

import pytest

from krsec_rag_lab.corpus import index_sync as sync

ROOT = Path(__file__).resolve().parents[1]
SENTINEL = "Synthetic sentinel body text"
PARSER = "kisa-html-v1"


def sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def make_docs(count=30, start=100):
    return {
        str(start + n): {
            "title": f"Invented title {start + n}",
            "body": f"{SENTINEL} {start + n} CVE-2099-{start + n:05d}.",
            "date": "2026-01-02",
            "cve_ids": [f"CVE-2099-{start + n:05d}"],
        }
        for n in range(count)
    }


def write_snapshot(root, docs, complete=True, unresolved=(), parser=PARSER):
    """합성 스냅샷을 root에 쓴다. 반환값은 (fixtures_dir, cache_root)."""
    root = Path(root)
    fixtures = root / "fixtures"
    fixtures.mkdir(parents=True, exist_ok=True)
    documents, rows = [], []
    for ntt_id, doc in docs.items():
        directory = root / "data/kisa_full" / ntt_id
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "body.txt").write_text(doc["body"], encoding="utf-8")
        documents.append(
            {"nttId": ntt_id, "collected_at": "t", "sha256": sha(doc["body"]), "result": "ok"}
        )
        rows.append(
            {
                "url": "u",
                "title": doc["title"],
                "date": doc["date"],
                "nttId": ntt_id,
                "cve_ids": doc["cve_ids"],
            }
        )
    for ntt_id in unresolved:
        documents.append(
            {"nttId": ntt_id, "collected_at": "t", "sha256": "", "result": "parse_failed:x"}
        )
    manifest = {
        "schema_version": 1,
        "parser_version": parser,
        "started_at": "s",
        "finished_at": "f",
        "discovery_complete": True,
        "complete": complete,
        "target_ids": sorted([*docs, *unresolved], key=int),
        "documents": documents,
    }
    (fixtures / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (fixtures / "metadata.jsonl").write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows), encoding="utf-8"
    )
    return fixtures, root


def load(tmp_path, name, docs, **kwargs):
    fixtures, cache = write_snapshot(tmp_path / name, docs, **kwargs)
    return sync.load_snapshot(fixtures, cache)


class FakeEncoder:
    dimension = 8
    max_seq_length = 8192

    def __init__(self):
        self.texts = []

    def encode(self, texts):
        self.texts.extend(texts)
        return [self.vector(t) for t in texts]

    @staticmethod
    def vector(text):
        digest = hashlib.sha256(text.encode("utf-8")).digest()
        values = [(b - 127.5) / 127.5 for b in digest[:8]]
        norm = sum(v * v for v in values) ** 0.5
        return [v / norm for v in values]

    def token_lengths(self, texts):
        return [len(t.split()) for t in texts]

    def describe(self):
        return {"name": "fake", "revision": "fake-rev", "max_seq_length": self.max_seq_length}


class FakeBackend:
    def __init__(self):
        self.points = {}
        self.created = False
        self.calls = []

    def exists(self):
        return self.created

    def create(self, dimension):
        self.created = True
        self.calls.append(("create", dimension))

    def drop(self):
        self.created = False
        self.points = {}

    def scan(self):
        return {pid: dict(payload) for pid, (payload, _) in self.points.items()}

    def dump(self):
        return {pid: (dict(p), array("f", v)) for pid, (p, v) in self.points.items()}

    def count(self):
        return len(self.points)

    def upsert(self, points):
        self.calls.append(("upsert", [pid for pid, _, _ in points]))
        for pid, vector, payload in points:
            self.points[pid] = (dict(payload), list(array("f", vector)))

    def set_payload(self, updates):
        self.calls.append(("set_payload", [pid for pid, _ in updates]))
        for pid, payload in updates:
            self.points[pid] = (dict(payload), self.points[pid][1])

    def delete(self, ids):
        self.calls.append(("delete", list(ids)))
        for pid in ids:
            del self.points[pid]

    def writes(self):
        return [call for call in self.calls if call[0] != "create"] or []


def run(snapshot, backend, encoder=None, **kwargs):
    encoder = encoder or FakeEncoder()
    plan = sync.run_sync(snapshot, backend, encoder, log=lambda message: None, **kwargs)
    return plan, encoder


def pids(*ids):
    return {sync.point_id(i) for i in ids}


# ------------------------------------------------------------------ point ID와 payload


def test_point_id_is_deterministic_uuid5_of_ntt_id():
    expected = str(uuid.uuid5(sync.POINT_NAMESPACE, "kisa:12345"))
    assert sync.point_id("12345") == sync.point_id("12345") == expected
    assert uuid.UUID(expected).version == 5
    ids = {sync.point_id(str(n)) for n in range(1000)}
    assert len(ids) == 1000


@pytest.mark.parametrize("bad", ["", "abc", "12 3", "../1", "1.5"])
def test_point_id_rejects_non_numeric_ids(bad):
    with pytest.raises(sync.SyncError, match="invalid_id"):
        sync.point_id(bad)


def test_payload_has_only_allowed_fields_and_no_text(tmp_path):
    snapshot = load(tmp_path, "s", make_docs(5))
    backend = FakeBackend()
    run(snapshot, backend)
    assert len(backend.points) == 5
    for payload, _ in backend.points.values():
        assert set(payload) == set(sync.PAYLOAD_KEYS)
        assert SENTINEL not in json.dumps(payload, ensure_ascii=False)
        assert "Invented title" not in json.dumps(payload, ensure_ascii=False)


# ------------------------------------------------------------------ 계획 계산


def test_plan_splits_add_update_payload_update_delete_keep(tmp_path):
    docs = make_docs(10)
    backend = FakeBackend()
    run(load(tmp_path, "a", docs), backend)

    changed = {k: dict(v) for k, v in docs.items()}
    changed["101"]["title"] = "Another title"  # 입력 지문이 달라진다 -> 갱신
    changed["102"]["date"] = "2026-02-02"  # 메타데이터만 -> payload 갱신
    del changed["103"]  # 삭제
    changed.update(make_docs(2, start=500))  # 추가 2건
    plan, _ = run(load(tmp_path, "b", changed), backend, dry_run=True)

    assert plan.ids() == {
        "add": ["500", "501"],
        "update": ["101"],
        "payload_update": ["102"],
        "delete": ["103"],
    }
    assert plan.counts()["keep"] == 7


def test_plan_lines_print_counts_and_ids(tmp_path):
    snapshot = load(tmp_path, "s", make_docs(3))
    plan, _ = run(snapshot, FakeBackend(), dry_run=True)
    lines = sync.plan_lines(plan)
    assert lines[0].startswith("plan: add=3 update=0 payload_update=0 delete=0 keep=0")
    assert lines[1] == "  add_ids=100,101,102"


# ------------------------------------------------------------------ 재실행과 변경 실행


def test_rerun_encodes_upserts_and_deletes_nothing(tmp_path):
    snapshot = load(tmp_path, "s", make_docs(12))
    backend = FakeBackend()
    run(snapshot, backend)
    before = backend.dump()
    backend.calls.clear()

    plan, encoder = run(snapshot, backend)

    assert plan.counts() == {
        "add": 0,
        "update": 0,
        "payload_update": 0,
        "delete": 0,
        "keep": 12,
        "kept_unresolved": 0,
    }
    assert encoder.texts == []
    assert backend.calls == []
    assert backend.dump() == before


def test_changed_run_touches_only_added_updated_and_deleted_ids(tmp_path):
    docs = make_docs(12)
    backend = FakeBackend()
    run(load(tmp_path, "a", docs), backend)
    before = backend.dump()
    backend.calls.clear()

    changed = {k: dict(v) for k, v in docs.items()}
    changed["104"]["body"] += " edited"
    del changed["105"]
    changed.update(make_docs(1, start=900))
    snapshot = load(tmp_path, "b", changed)
    _, encoder = run(snapshot, backend)

    expected_texts = [snapshot.docs[i].text() for i in ("104", "900")]
    assert sorted(encoder.texts) == sorted(expected_texts)
    upserted = [pid for op, ids in backend.calls if op == "upsert" for pid in ids]
    deleted = [pid for op, ids in backend.calls if op == "delete" for pid in ids]
    assert set(upserted) == pids("104", "900")
    assert deleted == [sync.point_id("105")]
    assert not [op for op, _ in backend.calls if op == "set_payload"]
    after = backend.dump()
    untouched = set(before) - pids("104", "105", "900")
    assert all(after[i] == before[i] for i in untouched)


@pytest.mark.parametrize("state", ["empty_collection", "missing_collection", "changed"])
def test_dry_run_makes_no_write_calls(tmp_path, state):
    docs = make_docs(8)
    backend = FakeBackend()
    if state == "changed":
        run(load(tmp_path, "a", docs), backend)
        docs = {k: dict(v) for k, v in docs.items() if k != "100"}
        docs["101"]["body"] += " edited"
        docs.update(make_docs(1, start=700))
        backend.calls.clear()
    elif state == "empty_collection":
        backend.created = True
    snapshot = load(tmp_path, "b", docs)
    encoder = FakeEncoder()
    messages = []
    sync.run_sync(snapshot, backend, encoder, dry_run=True, log=messages.append)
    assert backend.calls == []
    assert encoder.texts == []
    assert messages[0].startswith("plan: ")
    assert messages[-1] == "dry-run: no writes"


def test_incremental_result_equals_from_scratch(tmp_path):
    docs = make_docs(15)
    incremental = FakeBackend()
    run(load(tmp_path, "a", docs), incremental)
    changed = {k: dict(v) for k, v in docs.items()}
    changed["110"]["title"] = "Renamed"
    changed["111"]["cve_ids"] = ["CVE-2099-99999"]
    changed["112"]["body"] += " edited"
    del changed["113"], changed["114"]
    changed.update(make_docs(3, start=800))
    snapshot = load(tmp_path, "b", changed)
    run(snapshot, incremental)

    scratch = FakeBackend()
    run(snapshot, scratch)

    comparison = sync.compare_states(incremental.dump(), scratch.dump())
    assert comparison["ids_equal"] and comparison["payload_equal"]
    assert comparison["vectors_max_abs_diff"] == 0.0


# ------------------------------------------------------------------ 갱신 판정


@pytest.mark.parametrize(
    ("field", "value", "expected"),
    [
        ("title", "Changed title", "update"),
        ("body", f"{SENTINEL} rewritten body", "update"),
        ("date", "2026-03-03", "payload_update"),
        ("cve_ids", ["CVE-2099-00001", "CVE-2099-00002"], "payload_update"),
        (None, None, "keep"),
    ],
)
def test_update_decision_follows_input_fingerprint(tmp_path, field, value, expected):
    docs = make_docs(4)
    backend = FakeBackend()
    run(load(tmp_path, "a", docs), backend)
    backend.calls.clear()
    changed = {k: dict(v) for k, v in docs.items()}
    if field:
        changed["100"][field] = value
    plan, encoder = run(load(tmp_path, "b", changed), backend)

    names = ("add", "update", "payload_update")
    got = {name: plan.ids()[name] for name in names if plan.ids()[name]}
    assert got == ({expected: ["100"]} if expected != "keep" else {})
    assert len(encoder.texts) == (1 if expected == "update" else 0)
    ops = [op for op, _ in backend.calls]
    assert ops == {"update": ["upsert"], "payload_update": ["set_payload"], "keep": []}[expected]


def test_parser_version_change_updates_payload_only(tmp_path):
    docs = make_docs(3)
    backend = FakeBackend()
    run(load(tmp_path, "a", docs), backend)
    backend.calls.clear()
    plan, encoder = run(load(tmp_path, "b", docs, parser="kisa-html-v2"), backend)
    assert plan.ids()["payload_update"] == ["100", "101", "102"]
    assert encoder.texts == []
    assert {payload["parser_version"] for payload, _ in backend.points.values()} == {"kisa-html-v2"}


# ------------------------------------------------------------------ manifest 완료 여부와 비 ok 문서


@pytest.mark.parametrize("with_deletes", [True, False])
def test_incomplete_manifest_refuses_deletes_only(tmp_path, with_deletes):
    docs = make_docs(6)
    backend = FakeBackend()
    run(load(tmp_path, "a", docs), backend)
    backend.calls.clear()
    partial = {k: v for k, v in docs.items() if k != "100"} if with_deletes else dict(docs)
    partial.update(make_docs(1, start=600))
    snapshot = load(tmp_path, "b", partial, complete=False)
    if with_deletes:
        with pytest.raises(sync.SyncError, match="incomplete_manifest_delete_refused"):
            run(snapshot, backend)
        assert backend.calls == []
        assert sync.point_id("100") in backend.points
    else:
        plan, _ = run(snapshot, backend)
        assert plan.ids()["add"] == ["600"]
        assert plan.counts()["delete"] == 0


def test_unresolved_ids_are_not_indexed_but_existing_points_stay(tmp_path):
    docs = make_docs(5)
    backend = FakeBackend()
    run(load(tmp_path, "a", docs), backend)
    backend.calls.clear()
    # 101은 이제 파싱 실패(ok 아님), 777은 처음부터 ok가 아니다. 둘 다 target_ids에는 있다.
    remaining = {k: v for k, v in docs.items() if k != "101"}
    snapshot = load(tmp_path, "b", remaining, unresolved=("101", "777"))
    plan, encoder = run(snapshot, backend)

    assert plan.counts()["delete"] == 0
    assert plan.counts()["kept_unresolved"] == 1
    assert plan.ids()["add"] == []
    assert encoder.texts == []
    assert backend.calls == []
    assert sync.point_id("101") in backend.points
    assert sync.point_id("777") not in backend.points


def test_id_missing_from_target_ids_is_deleted_even_if_unresolved_elsewhere(tmp_path):
    docs = make_docs(4)
    backend = FakeBackend()
    run(load(tmp_path, "a", docs), backend)
    snapshot = load(tmp_path, "b", {k: v for k, v in docs.items() if k != "102"})
    plan, _ = run(snapshot, backend)
    assert plan.ids()["delete"] == ["102"]
    assert sync.point_id("102") not in backend.points


# ------------------------------------------------------------------ 모델 경계


class FakeModel:
    def __init__(self):
        self.encode_calls = []
        self.max_seq_length = None

    def encode(self, texts, **kwargs):
        self.encode_calls.append((list(texts), kwargs))
        return [FakeEncoder.vector(t) for t in texts]

    def __iter__(self):
        return iter(())


def test_model_boundary_gets_title_newline_body_revision_and_max_seq_length(tmp_path):
    loads = []
    model = FakeModel()

    def loader(name, revision, device):
        loads.append((name, revision, device))
        return model

    encoder = sync.SentenceTransformerEncoder(
        max_seq_length=1234, batch_size=1, loader=loader, dimension=8
    )
    snapshot = load(tmp_path, "s", make_docs(3))
    backend = FakeBackend()
    sync.run_sync(snapshot, backend, encoder, log=lambda message: None)

    assert loads == [("BAAI/bge-m3", "5617a9f61b028005a4858fdac845db406aefb181", "cpu")]
    assert model.max_seq_length == 1234
    (texts, kwargs), *rest = model.encode_calls
    assert not rest
    assert texts == [f"{d['title']}\n{d['body']}" for d in make_docs(3).values()]
    assert kwargs["batch_size"] == 1 and kwargs["normalize_embeddings"] is True


def test_default_encoder_settings_match_the_dense_baseline():
    assert sync.MODEL_REVISION == "5617a9f61b028005a4858fdac845db406aefb181"
    assert sync.MAX_SEQ_LENGTH == 8192 and sync.BATCH_SIZE == 1 and sync.DIMENSION == 1024


def test_wrong_vector_dimension_fails_with_fixed_code(tmp_path):
    class BadEncoder(FakeEncoder):
        def encode(self, texts):
            return [[0.0] * 3 for _ in texts]

    with pytest.raises(sync.SyncError, match="dimension_mismatch"):
        run(load(tmp_path, "s", make_docs(2)), FakeBackend(), BadEncoder())


# ------------------------------------------------------------------ 캐시와 snapshot 검증


def test_cache_hash_mismatch_fails_with_fixed_code(tmp_path):
    fixtures, cache = write_snapshot(tmp_path / "s", make_docs(3))
    (cache / "data/kisa_full/101/body.txt").write_text("tampered body", encoding="utf-8")
    with pytest.raises(sync.SyncError) as caught:
        sync.load_snapshot(fixtures, cache)
    assert str(caught.value) == "cache_hash_mismatch"


def test_missing_cache_file_fails_with_fixed_code(tmp_path):
    fixtures, cache = write_snapshot(tmp_path / "s", make_docs(3))
    (cache / "data/kisa_full/101/body.txt").unlink()
    with pytest.raises(sync.SyncError, match="cache_missing"):
        sync.load_snapshot(fixtures, cache)


@pytest.mark.parametrize(
    "breakage", ["no_manifest", "bad_json", "no_metadata_row", "not_complete_bool"]
)
def test_broken_snapshot_fails_with_fixed_code(tmp_path, breakage):
    fixtures, cache = write_snapshot(tmp_path / "s", make_docs(3))
    manifest = json.loads((fixtures / "manifest.json").read_text(encoding="utf-8"))
    if breakage == "no_manifest":
        (fixtures / "manifest.json").unlink()
    elif breakage == "bad_json":
        (fixtures / "manifest.json").write_text("{", encoding="utf-8")
    elif breakage == "no_metadata_row":
        lines = (fixtures / "metadata.jsonl").read_text(encoding="utf-8").splitlines()
        (fixtures / "metadata.jsonl").write_text("\n".join(lines[1:]) + "\n", encoding="utf-8")
    else:
        manifest["complete"] = "yes"
        (fixtures / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(sync.SyncError, match="snapshot_invalid"):
        sync.load_snapshot(fixtures, cache)


# ------------------------------------------------------------------ CLI와 유출


def patch_cli(monkeypatch, backend):
    monkeypatch.setattr(sync, "QdrantBackend", lambda url, name: backend)
    monkeypatch.setattr(sync, "SentenceTransformerEncoder", lambda *a, **k: FakeEncoder())
    monkeypatch.setattr(sync, "qdrant_version", lambda url: "test")


def test_cli_failure_prints_fixed_code_without_body_or_paths(tmp_path, monkeypatch, capsys):
    fixtures, cache = write_snapshot(tmp_path / "private-scratch-dir", make_docs(3))
    (cache / "data/kisa_full/101/body.txt").write_text(f"{SENTINEL} tampered", encoding="utf-8")
    patch_cli(monkeypatch, FakeBackend())
    code = sync.main(["--fixtures-dir", str(fixtures), "--cache-root", str(cache)])
    out, err = capsys.readouterr()
    assert code == 1
    assert err.strip() == "error=cache_hash_mismatch"
    for text in (out, err):
        assert (
            SENTINEL not in text and "private-scratch-dir" not in text and str(tmp_path) not in text
        )


def test_cli_unexpected_failure_prints_class_name_only(tmp_path, monkeypatch, capsys):
    fixtures, cache = write_snapshot(tmp_path / "private-scratch-dir", make_docs(2))

    class Boom:
        def __init__(self, url, name):
            raise RuntimeError(f"{SENTINEL} {tmp_path}")

    monkeypatch.setattr(sync, "QdrantBackend", Boom)
    code = sync.main(["--fixtures-dir", str(fixtures), "--cache-root", str(cache)])
    out, err = capsys.readouterr()
    assert code == 1
    assert err.strip() == "error=unexpected_failure:RuntimeError"
    assert SENTINEL not in out + err and str(tmp_path) not in out + err


def test_cli_dry_run_writes_nothing_and_skips_the_model(tmp_path, monkeypatch, capsys):
    fixtures, cache = write_snapshot(tmp_path / "s", make_docs(4))
    backend = FakeBackend()
    patch_cli(monkeypatch, backend)

    def no_model(*args, **kwargs):
        raise AssertionError("model must not load on dry-run")

    monkeypatch.setattr(sync, "SentenceTransformerEncoder", no_model)
    code = sync.main(["--fixtures-dir", str(fixtures), "--cache-root", str(cache), "--dry-run"])
    out, _ = capsys.readouterr()
    assert code == 0 and backend.calls == []
    assert out.splitlines()[0].startswith("plan: add=4")


def test_cli_sync_then_rerun_is_a_noop(tmp_path, monkeypatch, capsys):
    fixtures, cache = write_snapshot(tmp_path / "s", make_docs(4))
    backend = FakeBackend()
    patch_cli(monkeypatch, backend)
    args = ["--fixtures-dir", str(fixtures), "--cache-root", str(cache)]
    assert sync.main(args) == 0
    backend.calls.clear()
    capsys.readouterr()
    assert sync.main(args) == 0
    out, _ = capsys.readouterr()
    assert out.splitlines()[0].startswith("plan: add=0 update=0 payload_update=0 delete=0 keep=4")
    assert backend.calls == []


# ------------------------------------------------------------------ 멱등성 검증


def verification(tmp_path, docs=None, unresolved=("9001", "9002"), **kwargs):
    docs = docs or make_docs(40)
    fixtures, cache = write_snapshot(tmp_path / "src", docs, unresolved=unresolved)
    backends = {}

    def factory(name):
        return backends.setdefault(name, FakeBackend())

    report = sync.verify_idempotency(
        fixtures, cache, factory, FakeEncoder(), log=lambda message: None, **kwargs
    )
    return report, fixtures, cache, backends


def tree_digest(root):
    return {
        str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(Path(root).rglob("*"))
        if p.is_file()
    }


def test_pick_sets_are_disjoint_fixed_and_from_ok_ids(tmp_path):
    snapshot = load(tmp_path, "s", make_docs(40), unresolved=("9001",))
    update, delete, spare = sync.pick_sets(snapshot)
    again = sync.pick_sets(snapshot)
    assert (update, delete, spare) == again
    assert len({*update, *delete, *spare}) == 15
    assert {*update, *delete, *spare} <= set(snapshot.docs)
    assert "9001" not in {*update, *delete, *spare}


def test_verification_passes_all_five_steps_and_leaves_sources_untouched(tmp_path):
    docs = make_docs(40)
    fixtures, cache = write_snapshot(tmp_path / "src", docs, unresolved=("9001", "9002"))
    before = (tree_digest(fixtures), tree_digest(cache))
    backends = {}
    report = sync.verify_idempotency(
        fixtures,
        cache,
        lambda name: backends.setdefault(name, FakeBackend()),
        FakeEncoder(),
        log=lambda message: None,
    )
    assert (tree_digest(fixtures), tree_digest(cache)) == before

    assert report["passed"] is True and report["error"] is None and report["failed_step"] is None
    steps = {s["step"]: s for s in report["steps"]}
    assert sorted(steps) == [1, 2, 3, 4, 5] and all(s["passed"] for s in steps.values())
    k = report["k"]
    assert steps[1]["plan"]["add"] == steps[1]["points"] == 40 - k
    assert steps[2]["plan"] == {
        "add": 0,
        "update": 0,
        "payload_update": 0,
        "delete": 0,
        "keep": 40 - k,
        "kept_unresolved": 0,
    }
    assert steps[2]["encoded_texts"] == 0 and not any(steps[2]["writes"].values())
    assert [steps[3]["plan"][name] for name in ("add", "update", "delete")] == [k, k, k]
    assert steps[3]["plan"]["payload_update"] == 0
    assert steps[3]["comparison"]["unchanged_points_identical"] == 40 - 3 * k
    assert steps[4]["comparison"]["ids_equal"] and steps[4]["comparison"]["payload_equal"]
    assert steps[4]["comparison"]["vectors_max_abs_diff"] <= sync.VECTOR_TOLERANCE
    assert [steps[5]["plan"][name] for name in ("add", "update", "delete")] == [k, k, k]
    assert steps[5]["comparison"]["payload_equal"]
    # 비 ok 대상 ID는 어느 단계에서도 색인되지 않는다.
    assert not any(
        sync.point_id(i) in b.points for b in backends.values() for i in ("9001", "9002")
    )
    assert set(report["corpus"]["update_ids"]).isdisjoint(report["corpus"]["delete_ids"])


def test_verification_variant_marks_updates_with_a_fixed_line_and_new_hash(tmp_path):
    snapshot = load(tmp_path, "s", make_docs(40))
    update, delete, _ = sync.pick_sets(snapshot)
    fixtures, cache = sync.write_derived(
        tmp_path / "derived", snapshot, set(snapshot.docs) - set(delete), marked=set(update)
    )
    derived = sync.load_snapshot(fixtures, cache)
    manifest = json.loads((fixtures / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["complete"] is True and manifest["discovery_complete"] is True
    assert set(manifest["target_ids"]) == set(derived.docs) == set(snapshot.docs) - set(delete)
    for ntt_id in update:
        assert derived.docs[ntt_id].body == snapshot.docs[ntt_id].body + f"\n{sync.MARKER_LINE}\n"
        assert derived.docs[ntt_id].sha256 != snapshot.docs[ntt_id].sha256
    for ntt_id in set(derived.docs) - set(update):
        assert derived.docs[ntt_id].sha256 == snapshot.docs[ntt_id].sha256


def test_verification_reports_failed_step_when_resync_writes(tmp_path):
    class DriftingBackend(FakeBackend):
        """재실행 때 payload를 몰래 바꿔 2단계가 실패하도록 한다."""

        def scan(self):
            scanned = super().scan()
            if len(self.calls) > 1:
                for payload in scanned.values():
                    payload["date"] = "1999-01-01"
            return scanned

    docs = make_docs(40)
    fixtures, cache = write_snapshot(tmp_path / "src", docs)
    backends = {}
    report = sync.verify_idempotency(
        fixtures,
        cache,
        lambda name: backends.setdefault(name, DriftingBackend()),
        FakeEncoder(),
        log=lambda message: None,
    )
    assert report["passed"] is False and report["failed_step"] == 2
    assert [s["step"] for s in report["steps"]] == [1, 2]


def test_verification_failure_report_has_fixed_code_and_no_leaks(tmp_path):
    docs = make_docs(40)
    fixtures, cache = write_snapshot(tmp_path / "private-scratch-dir", docs)
    (cache / "data/kisa_full/101/body.txt").write_text(f"{SENTINEL} tampered", encoding="utf-8")
    report = sync.verify_idempotency(
        fixtures, cache, lambda name: FakeBackend(), FakeEncoder(), log=lambda message: None
    )
    assert report["passed"] is False and report["error"] == "cache_hash_mismatch"
    text = json.dumps(report, ensure_ascii=False)
    assert SENTINEL not in text and "private-scratch-dir" not in text and str(tmp_path) not in text


def test_verification_with_too_small_corpus_fails_with_fixed_code(tmp_path):
    report, *_ = verification(tmp_path, docs=make_docs(10), unresolved=())
    assert report["error"] == "corpus_too_small" and report["passed"] is False


def test_cli_verify_idempotency_writes_a_report_and_exits_zero(tmp_path, monkeypatch, capsys):
    fixtures, cache = write_snapshot(tmp_path / "src", make_docs(40))
    backends = {}
    monkeypatch.setattr(
        sync, "QdrantBackend", lambda url, name: backends.setdefault(name, FakeBackend())
    )
    monkeypatch.setattr(sync, "SentenceTransformerEncoder", lambda *a, **k: FakeEncoder())
    monkeypatch.setattr(sync, "qdrant_version", lambda url: "1.19.2")
    results = tmp_path / "results"
    code = sync.main(
        [
            "--verify-idempotency",
            "--fixtures-dir",
            str(fixtures),
            "--cache-root",
            str(cache),
            "--results-dir",
            str(results),
        ]
    )
    out, _ = capsys.readouterr()
    assert code == 0 and out.strip().endswith("idempotency: pass")
    report = json.loads((results / "report.json").read_text(encoding="utf-8"))
    assert list(report) == list(sync.REPORT_KEYS)
    assert report["qdrant"] == {"image": "qdrant/qdrant:v1.19.2", "version": "1.19.2"}
    assert str(tmp_path) not in json.dumps(report)
    sync.check_report_strings(report)


def test_cli_verify_rejects_other_batch_sizes(tmp_path, monkeypatch, capsys):
    fixtures, cache = write_snapshot(tmp_path / "src", make_docs(40))
    patch_cli(monkeypatch, FakeBackend())
    code = sync.main(
        [
            "--verify-idempotency",
            "--batch-size",
            "8",
            "--fixtures-dir",
            str(fixtures),
            "--cache-root",
            str(cache),
        ]
    )
    assert code == 1
    assert capsys.readouterr().err.strip() == "error=verify_requires_batch_size_1"


# ------------------------------------------------------------------ 보고서 형식


@pytest.mark.parametrize(
    "value", ["/leading/slash", "x" * 501, {"nested": ["ok", "/bad"]}, {"/key": "ok"}]
)
def test_report_strings_reject_leading_slash_and_long_values(value):
    with pytest.raises(sync.SyncError, match="report_string_rejected"):
        sync.check_report_strings(value)


def test_report_strings_accept_normal_values():
    sync.check_report_strings({"a": "ok", "b": ["x" * 500, {"c": "https://example.invalid"}]})


def test_report_keys_are_documented_in_the_table():
    doc = (ROOT / "docs/m4-idempotency.md").read_text(encoding="utf-8")
    section = doc.split("## report.json 키")[1].split("\n## ")[0]
    first_cells = re.findall(r"^\| ([^|]+) \|", section, flags=re.MULTILINE)
    documented = {key for cell in first_cells for key in re.findall(r"`([a-z_]+)`", cell)}
    assert set(sync.REPORT_KEYS) <= documented


def test_committed_report_is_clean_and_passing():
    path = ROOT / "results/m4/idempotency/report.json"
    if not path.exists():
        pytest.skip("report not generated yet")
    text = path.read_text(encoding="utf-8")
    report = json.loads(text)
    assert list(report) == list(sync.REPORT_KEYS)
    assert report["passed"] is True and report["error"] is None
    assert [s["step"] for s in report["steps"]] == [1, 2, 3, 4, 5]
    assert all(s["passed"] for s in report["steps"])
    assert "/Users" not in text
    sync.check_report_strings(report)
