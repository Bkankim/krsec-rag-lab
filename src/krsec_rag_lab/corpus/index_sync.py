"""전체 코퍼스 스냅샷(manifest + 메타데이터 + 캐시)과 Qdrant 컬렉션의 증분 동기화와 멱등성 검증.

문서 하나 = point 하나(청킹 없음). point ID는 nttId에서 결정적으로 만들고 payload에는 본문을 넣지 않는다.
numpy·torch·sentence_transformers·qdrant_client는 함수 안에서만 import한다(CI dev 그룹에 없다).
화면·오류·보고서에는 진행 수치와 고정 reason code만 남기고, 본문·캐시 경로는 어디에도 쓰지 않는다.
규칙의 정본은 이슈 #59와 docs/m4-idempotency.md다.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import platform
import re
import sys
import tempfile
import time
import urllib.parse
import urllib.request
import uuid
from array import array
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from krsec_rag_lab.baselines import dense

ROOT = Path(__file__).resolve().parents[3]
SCHEMA_VERSION = 1
CACHE_SUBDIR = Path("data/kisa_full")
POINT_NAMESPACE = uuid.uuid5(
    uuid.NAMESPACE_URL, "https://github.com/Bkankim/krsec-rag-lab/corpus/kisa"
)
# payload에 둘 수 있는 키 전부. 본문·제목 텍스트는 없다.
PAYLOAD_KEYS = ("nttId", "sha256", "input_sha256", "parser_version", "date", "cve_ids")
MODEL_NAME = dense.MODEL_NAME
MODEL_REVISION = dense.MODEL_REVISION
DEVICE = dense.DEVICE
MAX_SEQ_LENGTH = dense.MAX_SEQ_LENGTH
DIMENSION = 1024
BATCH_SIZE = 1
UPSERT_CHUNK = 32
DEFAULT_URL = "http://127.0.0.1:16333"
URL_ENV = "KRSEC_QDRANT_URL"
QDRANT_IMAGE = "qdrant/qdrant:v1.19.2"
COLLECTION = "krsec_kisa_full"
VERIFY_COLLECTIONS = ("krsec_m4_idem_main", "krsec_m4_idem_scratch")
VERIFY_K = 5
VERIFY_SEED = 59
VECTOR_TOLERANCE = 1e-5
MARKER_LINE = "[idempotency-check marker line]"
MAX_REPORT_STRING = 500
PRINT_IDS = 50


class SyncError(Exception):
    """동기화를 멈춘다. 메시지는 고정 reason code만 담는다."""


def point_id(ntt_id):
    """nttId에서 결정적으로 만든 point ID(UUID 문자열)."""
    if not re.fullmatch(r"[0-9]+", str(ntt_id)):
        raise SyncError("invalid_id")
    return str(uuid.uuid5(POINT_NAMESPACE, f"kisa:{ntt_id}"))


def sha256_text(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def encoder_input(title, body):
    """인코딩 입력 문자열: 제목 + 줄바꿈 + 본문."""
    return f"{title}\n{body}"


def by_id(ids):
    return sorted(ids, key=int)


# ---------------------------------------------------------------- 스냅샷


@dataclass
class SnapshotDoc:
    ntt_id: str
    title: str = field(repr=False)
    date: str
    cve_ids: list
    sha256: str
    parser_version: str
    body: str = field(repr=False)
    input_sha256: str

    def payload(self):
        return {
            "nttId": self.ntt_id,
            "sha256": self.sha256,
            "input_sha256": self.input_sha256,
            "parser_version": self.parser_version,
            "date": self.date,
            "cve_ids": list(self.cve_ids),
        }

    def text(self):
        return encoder_input(self.title, self.body)


@dataclass
class Snapshot:
    parser_version: str
    complete: bool
    target_ids: list
    docs: dict  # ok인 문서만: nttId -> SnapshotDoc
    manifest: dict = field(repr=False)

    @property
    def unresolved_ids(self):
        return [i for i in self.target_ids if i not in self.docs]


def read_cached_body(cache_root, ntt_id, sha256):
    """`body.txt`를 읽고 manifest의 sha256과 대조한다. 재파싱은 하지 않는다."""
    path = Path(cache_root) / CACHE_SUBDIR / ntt_id / "body.txt"
    try:
        body = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise SyncError("cache_missing") from None
    except (OSError, UnicodeError):
        raise SyncError("cache_invalid") from None
    if sha256_text(body) != sha256:
        raise SyncError("cache_hash_mismatch")
    return body


def load_snapshot(fixtures_dir, cache_root):
    fixtures_dir = Path(fixtures_dir)
    try:
        manifest = json.loads((fixtures_dir / "manifest.json").read_text(encoding="utf-8"))
        rows = [
            json.loads(line)
            for line in (fixtures_dir / "metadata.jsonl").read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        metadata = {row["nttId"]: row for row in rows}
        parser_version = manifest["parser_version"]
        complete = manifest["complete"]
        target_ids = manifest["target_ids"]
        results = {entry["nttId"]: entry for entry in manifest["documents"]}
    except (OSError, UnicodeError, ValueError, KeyError, TypeError):
        raise SyncError("snapshot_invalid") from None
    if (
        manifest.get("schema_version") != 1
        or not isinstance(parser_version, str)
        or not isinstance(complete, bool)
        or not isinstance(target_ids, list)
        or not all(isinstance(i, str) and re.fullmatch(r"[0-9]+", i) for i in target_ids)
        or len(set(target_ids)) != len(target_ids)
    ):
        raise SyncError("snapshot_invalid")
    docs = {}
    for ntt_id in by_id(target_ids):
        entry = results.get(ntt_id)
        if entry is None or entry.get("result") != "ok":
            continue
        row = metadata.get(ntt_id)
        sha256 = entry.get("sha256")
        if row is None or not isinstance(sha256, str):
            raise SyncError("snapshot_invalid")
        try:
            title, date, cve_ids = row["title"], row["date"], sorted(row["cve_ids"])
        except (KeyError, TypeError):
            raise SyncError("snapshot_invalid") from None
        body = read_cached_body(cache_root, ntt_id, sha256)
        docs[ntt_id] = SnapshotDoc(
            ntt_id,
            title,
            date,
            cve_ids,
            sha256,
            parser_version,
            body,
            sha256_text(encoder_input(title, body)),
        )
    return Snapshot(parser_version, complete, by_id(target_ids), docs, manifest)


# ---------------------------------------------------------------- 계획


@dataclass
class Plan:
    add: list  # SnapshotDoc
    update: list  # 입력 지문이 달라 재인코딩할 SnapshotDoc
    payload_update: list  # 메타데이터만 달라 payload만 고칠 SnapshotDoc
    delete: list  # (point ID, 표시용 ID)
    keep: int
    kept_unresolved: int  # target_ids에 있지만 ok가 아닌데 이미 색인돼 유지하는 point 수

    def counts(self):
        return {
            "add": len(self.add),
            "update": len(self.update),
            "payload_update": len(self.payload_update),
            "delete": len(self.delete),
            "keep": self.keep,
            "kept_unresolved": self.kept_unresolved,
        }

    def ids(self):
        return {
            "add": [d.ntt_id for d in self.add],
            "update": [d.ntt_id for d in self.update],
            "payload_update": [d.ntt_id for d in self.payload_update],
            "delete": [label for _, label in self.delete],
        }


def compute_plan(snapshot, existing):
    """스냅샷과 컬렉션(point ID -> payload)을 비교해 추가·갱신·payload 갱신·삭제·유지로 나눈다."""
    add, update, payload_update, keep = [], [], [], 0
    for ntt_id, doc in snapshot.docs.items():
        payload = existing.get(point_id(ntt_id))
        if payload is None:
            add.append(doc)
        elif payload.get("input_sha256") != doc.input_sha256:
            update.append(doc)
        elif payload != doc.payload():
            payload_update.append(doc)
        else:
            keep += 1
    kept_unresolved = sum(1 for ntt_id in snapshot.unresolved_ids if point_id(ntt_id) in existing)
    target_points = {point_id(i) for i in snapshot.target_ids}
    delete = [
        (pid, str(payload.get("nttId", pid)))
        for pid, payload in existing.items()
        if pid not in target_points
    ]
    delete.sort(
        key=lambda item: (0, int(item[1]), item[0]) if item[1].isdigit() else (1, 0, item[0])
    )
    return Plan(add, update, payload_update, delete, keep, kept_unresolved)


def plan_lines(plan, all_ids=False):
    counts = plan.counts()
    lines = [
        "plan: "
        + " ".join(
            f"{name}={counts[name]}" for name in ("add", "update", "payload_update", "delete")
        )
        + f" keep={counts['keep']} kept_unresolved={counts['kept_unresolved']}"
    ]
    for name, ids in plan.ids().items():
        if not ids:
            continue
        shown = ids if all_ids or len(ids) <= PRINT_IDS else ids[:PRINT_IDS]
        rest = len(ids) - len(shown)
        lines.append(f"  {name}_ids={','.join(shown)}" + (f" (+{rest} more)" if rest else ""))
    return lines


# ---------------------------------------------------------------- 인코더


class SentenceTransformerEncoder:
    """bge-m3 dense 인코더. 모델은 `loader(name, revision, device)`가 만든다(테스트에서 가짜로 바꾼다)."""

    def __init__(
        self,
        max_seq_length=MAX_SEQ_LENGTH,
        batch_size=BATCH_SIZE,
        revision=MODEL_REVISION,
        loader=None,
        dimension=DIMENSION,
    ):
        self.max_seq_length = max_seq_length
        self.batch_size = batch_size
        self.revision = revision
        self.dimension = dimension
        self.model = (loader or load_sentence_transformer)(MODEL_NAME, revision, DEVICE)
        self.model.max_seq_length = max_seq_length
        self.output_dtype = None
        self.min_norm = None
        self.max_norm = None

    def encode(self, texts):
        raw = self.model.encode(
            list(texts),
            batch_size=self.batch_size,
            normalize_embeddings=True,
            convert_to_numpy=True,
            show_progress_bar=False,
        )
        self.output_dtype = str(getattr(raw, "dtype", "unknown"))
        vectors = []
        for row in raw:
            values = row.tolist() if hasattr(row, "tolist") else [float(x) for x in row]
            norm = sum(x * x for x in values) ** 0.5
            self.min_norm = norm if self.min_norm is None else min(self.min_norm, norm)
            self.max_norm = norm if self.max_norm is None else max(self.max_norm, norm)
            vectors.append(values)
        return vectors

    def token_lengths(self, texts):
        tokenizer = getattr(self.model, "tokenizer", None)
        if tokenizer is None:
            return None
        return [
            len(ids)
            for ids in tokenizer(
                list(texts), add_special_tokens=True, truncation=False, return_attention_mask=False
            )["input_ids"]
        ]

    def describe(self):
        pooling = None
        try:
            modules = list(self.model)
        except TypeError:
            modules = []
        for module in modules:
            config = getattr(module, "get_config_dict", None)
            if config is not None and "pooling_mode" in config():
                pooling = str(config()["pooling_mode"])
        size = getattr(self.model, "get_embedding_dimension", None) or getattr(
            self.model, "get_sentence_embedding_dimension", None
        )
        return {
            "name": MODEL_NAME,
            "revision": self.revision,
            "modules": [type(module).__name__ for module in modules],
            "pooling": pooling,
            "normalized": True,
            "dtype": self.output_dtype,
            "stored_dtype": "float32",
            "dimension": size() if size else None,
            "max_seq_length": self.max_seq_length,
            "batch_size": self.batch_size,
            "device": DEVICE,
            "min_vector_norm": self.min_norm,
            "max_vector_norm": self.max_norm,
        }


def load_sentence_transformer(name, revision, device):
    import torch
    from sentence_transformers import SentenceTransformer

    torch.manual_seed(0)
    model = SentenceTransformer(name, revision=revision, device=device)
    model.eval()
    return model


# ---------------------------------------------------------------- 백엔드


def normalize_url(url):
    """스킴이 없는 `host:port`는 urlsplit이 호스트를 스킴으로 읽으므로 `http://`를 붙여 해석한다."""
    url = url.strip()
    return url if "://" in url else f"http://{url}"


def client_kwargs(url):
    """`url`의 호스트·포트·스킴·접두사. QdrantClient(url=...)는 포트가 없으면 6333을 쓰지만 urllib은
    스킴 기본 포트(80/443)를 쓰므로, 둘이 같은 서버를 보도록 포트를 명시해 넘긴다."""
    parts = urllib.parse.urlsplit(normalize_url(url))
    https = parts.scheme == "https"
    host = parts.hostname or ""
    if ":" in host:  # QdrantClient는 host:port를 이어 붙일 뿐 IPv6 대괄호를 더하지 않는다
        host = f"[{host}]"
    return {
        "host": host,
        "port": parts.port or (443 if https else 80),
        "https": https,
        "prefix": parts.path.strip("/") or None,
    }


class QdrantBackend:
    """컬렉션 하나에 대한 Qdrant REST 접근. 이 컬렉션 밖은 건드리지 않는다."""

    def __init__(self, url, collection):
        from qdrant_client import QdrantClient

        self.collection = collection
        self.client = QdrantClient(**client_kwargs(url), prefer_grpc=False, timeout=120)

    def exists(self):
        return self.client.collection_exists(self.collection)

    def create(self, dimension):
        from qdrant_client import models

        self.client.create_collection(
            collection_name=self.collection,
            vectors_config=models.VectorParams(size=dimension, distance=models.Distance.COSINE),
        )

    def drop(self):
        if self.exists():
            self.client.delete_collection(self.collection)

    def _scroll(self, with_vectors):
        offset = None
        while True:
            points, offset = self.client.scroll(
                self.collection,
                limit=256,
                offset=offset,
                with_payload=True,
                with_vectors=with_vectors,
            )
            yield from points
            if offset is None:
                return

    def scan(self):
        return {str(p.id): dict(p.payload or {}) for p in self._scroll(False)}

    def dump(self):
        return {
            str(p.id): (dict(p.payload or {}), array("f", p.vector)) for p in self._scroll(True)
        }

    def count(self):
        return self.client.count(self.collection, exact=True).count

    def upsert(self, points):
        from qdrant_client import models

        self.client.upsert(
            self.collection,
            points=[models.PointStruct(id=i, vector=v, payload=p) for i, v, p in points],
            wait=True,
        )

    def set_payload(self, updates):
        for pid, payload in updates:
            self.client.overwrite_payload(self.collection, payload=payload, points=[pid], wait=True)

    def delete(self, ids):
        from qdrant_client import models

        self.client.delete(
            self.collection, points_selector=models.PointIdsList(points=list(ids)), wait=True
        )


class LazyEncoder:
    """처음 인코딩할 때에야 모델을 읽는다(변경이 없는 재실행·dry-run은 모델을 읽지 않는다)."""

    def __init__(self, factory):
        self.factory = factory
        self.inner = None

    @property
    def dimension(self):
        return self.inner.dimension if self.inner else None

    def encode(self, texts):
        if self.inner is None:
            self.inner = self.factory()
        return self.inner.encode(texts)


class MeteredBackend:
    """쓰기 호출을 센다(point 수 기준). 읽기는 그대로 넘긴다."""

    def __init__(self, inner):
        self.inner = inner
        self.writes = {"upsert": 0, "payload_update": 0, "delete": 0, "create": 0}

    def __getattr__(self, name):
        return getattr(self.inner, name)

    def create(self, dimension):
        self.writes["create"] += 1
        return self.inner.create(dimension)

    def upsert(self, points):
        self.writes["upsert"] += len(points)
        return self.inner.upsert(points)

    def set_payload(self, updates):
        self.writes["payload_update"] += len(updates)
        return self.inner.set_payload(updates)

    def delete(self, ids):
        self.writes["delete"] += len(ids)
        return self.inner.delete(ids)


class MeteredEncoder:
    def __init__(self, inner):
        self.inner = inner
        self.encoded = 0

    def __getattr__(self, name):
        return getattr(self.inner, name)

    def encode(self, texts):
        self.encoded += len(texts)
        return self.inner.encode(texts)


# ---------------------------------------------------------------- 동기화


def run_sync(
    snapshot, backend, encoder, dry_run=False, log=print, all_ids=False, chunk=UPSERT_CHUNK
):
    """계획을 계산해 출력하고(삭제가 있는데 manifest가 미완료면 거부) 추가·갱신·삭제를 반영한다."""
    exists = backend.exists()
    plan = compute_plan(snapshot, backend.scan() if exists else {})
    for line in plan_lines(plan, all_ids):
        log(line)
    if plan.delete and not snapshot.complete:
        raise SyncError("incomplete_manifest_delete_refused")
    if dry_run:
        log("dry-run: no writes")
        return plan
    if plan.payload_update:
        backend.set_payload([(point_id(d.ntt_id), d.payload()) for d in plan.payload_update])
    pending = plan.add + plan.update
    for start in range(0, len(pending), chunk):
        batch = pending[start : start + chunk]
        vectors = encoder.encode([d.text() for d in batch])
        if len(vectors) != len(batch) or any(len(v) != encoder.dimension for v in vectors):
            raise SyncError("dimension_mismatch")
        if not exists:  # 컬렉션 차원은 실제 벡터 길이로 정한다
            backend.create(len(vectors[0]))
            exists = True
        backend.upsert(
            [(point_id(d.ntt_id), v, d.payload()) for d, v in zip(batch, vectors, strict=True)]
        )
        log(f"encoded {min(start + chunk, len(pending))}/{len(pending)}")
    if plan.delete:
        backend.delete([pid for pid, _ in plan.delete])
    return plan


# ---------------------------------------------------------------- 상태 비교


def compare_states(a, b):
    """두 컬렉션 덤프(point ID -> (payload, 벡터))를 ID 집합·payload·벡터 최대 절대 차로 비교한다."""
    common = a.keys() & b.keys()
    payload_mismatch = sum(1 for i in common if a[i][0] != b[i][0])
    max_diff = 0.0
    for i in common:
        va, vb = a[i][1], b[i][1]
        if len(va) != len(vb):
            max_diff = float("inf")
            continue
        max_diff = max([max_diff, *(abs(x - y) for x, y in zip(va, vb, strict=True))])
    return {
        "points_a": len(a),
        "points_b": len(b),
        "ids_equal": a.keys() == b.keys(),
        "payload_equal": a.keys() == b.keys() and payload_mismatch == 0,
        "vectors_max_abs_diff": max_diff,
    }


def payload_keys_ok(state):
    return all(set(payload) <= set(PAYLOAD_KEYS) for payload, _ in state.values())


# ---------------------------------------------------------------- 파생 스냅샷과 멱등성 검증


def pick_sets(snapshot, k=VERIFY_K, seed=VERIFY_SEED):
    """`ok` ID에서 고정 시드로 서로 겹치지 않는 세 집합(갱신 k, 삭제 k, 예비 k)을 고른다."""
    ranked = sorted(snapshot.docs, key=lambda i: hashlib.sha256(f"{seed}:{i}".encode()).hexdigest())
    if len(ranked) < 3 * k:
        raise SyncError("corpus_too_small")
    return by_id(ranked[:k]), by_id(ranked[k : 2 * k]), by_id(ranked[2 * k : 3 * k])


def write_derived(root, base, include, marked=()):
    """`base` 스냅샷에서 `include` ID만 남긴 파생 스냅샷을 `root`에 쓴다.

    `marked` ID는 body.txt 끝에 고정 표식 줄을 더하고 manifest sha256을 다시 계산한다.
    target_ids·documents·metadata를 파생 집합으로 다시 쓰고 complete: true를 유지한다.
    비 ok 대상 ID는 그대로 둔다. 반환값은 (fixtures_dir, cache_root).
    """
    root = Path(root)
    fixtures_dir = root / "fixtures"
    fixtures_dir.mkdir(parents=True)
    keep = set(include)
    targets = by_id(keep | set(base.unresolved_ids))
    results = {e["nttId"]: e for e in base.manifest["documents"]}
    documents, rows = [], []
    for ntt_id in targets:
        entry = dict(results.get(ntt_id, {"nttId": ntt_id, "result": "missing"}))
        if ntt_id in base.docs:
            doc = base.docs[ntt_id]
            body = doc.body + (f"\n{MARKER_LINE}\n" if ntt_id in marked else "")
            entry["sha256"] = sha256_text(body)
            directory = root / CACHE_SUBDIR / ntt_id
            directory.mkdir(parents=True)
            (directory / "body.txt").write_text(body, encoding="utf-8")
            rows.append(
                {
                    "url": "",
                    "title": doc.title,
                    "date": doc.date,
                    "nttId": ntt_id,
                    "cve_ids": doc.cve_ids,
                }
            )
        documents.append(entry)
    manifest = {
        key: base.manifest[key]
        for key in ("schema_version", "parser_version", "started_at", "finished_at")
    } | {
        "discovery_complete": True,
        "complete": True,
        "target_ids": targets,
        "documents": documents,
    }
    (fixtures_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (fixtures_dir / "metadata.jsonl").write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows), encoding="utf-8"
    )
    return fixtures_dir, root


def now():
    return datetime.now(UTC).isoformat(timespec="seconds")


def verify_idempotency(
    fixtures_dir,
    cache_root,
    backend_factory,
    encoder,
    k=VERIFY_K,
    seed=VERIFY_SEED,
    log=print,
):
    """이슈 #59의 1~5단계를 차례로 돌려 보고서(dict)를 돌려준다. 첫 실패 단계에서 멈춘다.

    `backend_factory(컬렉션 이름)`이 백엔드를 만든다. 임시 스냅샷은 시스템 임시 디렉터리에만 둔다.
    오류는 던지지 않고 보고서 `error`에 고정 reason code로 남긴다.
    """
    started = time.perf_counter()
    report = {
        "schema_version": SCHEMA_VERSION,
        "passed": False,
        "failed_step": None,
        "error": None,
        "started_at": now(),
        "k": k,
        "seed": seed,
        "tolerances": {"unchanged_points": 0.0, "vector_abs": VECTOR_TOLERANCE},
        "steps": [],
    }
    try:
        run_verification(report, fixtures_dir, cache_root, backend_factory, encoder, k, seed, log)
    except SyncError as error:
        report["error"] = str(error)
    except Exception as error:  # noqa: BLE001 - 임의 예외 문자열에는 본문·경로가 섞일 수 있어 클래스 이름만 남긴다
        report["error"] = f"unexpected_failure:{type(error).__name__}"
    report["model"] = encoder.describe()
    report["finished_at"] = now()
    report["elapsed_seconds"] = round(time.perf_counter() - started, 1)
    return report


def run_verification(report, fixtures_dir, cache_root, backend_factory, encoder, k, seed, log):
    main_name, scratch_name = VERIFY_COLLECTIONS
    full = load_snapshot(fixtures_dir, cache_root)
    if not full.complete:  # 파생 스냅샷은 complete: true라 미완료 거부를 입력에서 먼저 적용한다
        raise SyncError("incomplete_manifest_verify_refused")
    update_ids, delete_ids, spare_ids = pick_sets(full, k, seed)
    report["corpus"] = {
        "parser_version": full.parser_version,
        "target_ids": len(full.target_ids),
        "ok_docs": len(full.docs),
        "unresolved_ids": len(full.unresolved_ids),
        "baseline_docs": len(full.docs) - k,
        "update_ids": update_ids,
        "delete_ids": delete_ids,
        "added_ids": spare_ids,
    }
    lengths = encoder.token_lengths([d.text() for d in full.docs.values()])
    if lengths is not None:
        report["corpus"] |= {
            "max_tokens": max(lengths),
            "truncated_docs": sum(1 for n in lengths if n > encoder.max_seq_length),
            "total_tokens": sum(lengths),
        }
    backends = {name: backend_factory(name) for name in VERIFY_COLLECTIONS}
    for backend in backends.values():
        backend.drop()
    with tempfile.TemporaryDirectory(prefix="krsec-m4-") as tmp:
        base_fx, base_root = write_derived(
            Path(tmp) / "baseline", full, set(full.docs) - set(spare_ids)
        )
        baseline = load_snapshot(base_fx, base_root)
        var_fx, var_root = write_derived(
            Path(tmp) / "variant",
            full,
            (set(baseline.docs) - set(delete_ids)) | set(spare_ids),
            marked=set(update_ids),
        )
        variant = load_snapshot(var_fx, var_root)

        def step(number, name, snapshot, collection, check):
            t0 = time.perf_counter()
            log(f"step {number}: {name}")
            backend = MeteredBackend(backends[collection])
            enc = MeteredEncoder(encoder)
            plan = run_sync(snapshot, backend, enc, log=log)
            dump = backend.dump()
            entry = {
                "step": number,
                "name": name,
                "collection": collection,
                "plan": plan.counts(),
                "points": len(dump),
                "encoded_texts": enc.encoded,
                "writes": dict(backend.writes),
                "payload_keys_allowed": payload_keys_ok(dump),
            }
            for key, ids in plan.ids().items():
                if len(ids) <= 20:
                    entry.setdefault("plan_ids", {})[key] = ids
            comparison, ok = check(plan, dump, entry)
            entry["comparison"] = comparison
            entry["passed"] = bool(ok and entry["payload_keys_allowed"])
            entry["elapsed_seconds"] = round(time.perf_counter() - t0, 1)
            report["steps"].append(entry)
            log(f"step {number}: {'pass' if entry['passed'] else 'FAIL'}")
            return dump, entry["passed"]

        states = {}

        def check1(plan, dump, entry):
            counts = plan.counts()
            ok = (
                counts["add"] == len(baseline.docs)
                and counts["update"] == counts["delete"] == counts["payload_update"] == 0
                and len(dump) == len(baseline.docs)
            )
            return {"points_equal_snapshot_docs": len(dump) == len(baseline.docs)}, ok

        def check2(plan, dump, entry):
            counts = plan.counts()
            comparison = compare_states(states[1], dump)
            ok = (
                counts["add"]
                == counts["update"]
                == counts["payload_update"]
                == counts["delete"]
                == 0
                and entry["encoded_texts"] == 0
                and not any(entry["writes"].values())
                and comparison["payload_equal"]
                and comparison["vectors_max_abs_diff"] == 0.0
            )
            return comparison, ok

        def check3(plan, dump, entry):
            counts = plan.counts()
            affected = {point_id(i) for i in (*update_ids, *delete_ids, *spare_ids)}
            unchanged = [i for i in states[1] if i not in affected]
            same = sum(1 for i in unchanged if i in dump and dump[i] == states[1][i])
            changed_vectors = sum(
                1 for i in update_ids if dump[point_id(i)][1] != states[1][point_id(i)][1]
            )
            comparison = {
                "unchanged_points": len(unchanged),
                "unchanged_points_identical": same,
                "updated_vectors_changed": changed_vectors,
                "deleted_absent": all(point_id(i) not in dump for i in delete_ids),
                "added_present": all(point_id(i) in dump for i in spare_ids),
                "points_equal_snapshot_docs": len(dump) == len(variant.docs),
            }
            ok = (
                counts["add"] == counts["update"] == counts["delete"] == k
                and counts["payload_update"] == 0
                and entry["encoded_texts"] == 2 * k
                and entry["writes"]["upsert"] == 2 * k
                and entry["writes"]["delete"] == k
                and same == len(unchanged)
                and comparison["deleted_absent"]
                and comparison["added_present"]
                and comparison["points_equal_snapshot_docs"]
                and all(
                    dump[point_id(i)][0]["input_sha256"] == variant.docs[i].input_sha256
                    for i in update_ids
                )
            )
            return comparison, ok

        def check4(plan, dump, entry):
            comparison = compare_states(states[3], dump)
            comparison["from_scratch_add"] = plan.counts()["add"]
            ok = (
                comparison["ids_equal"]
                and comparison["payload_equal"]
                and comparison["vectors_max_abs_diff"] <= VECTOR_TOLERANCE
                and plan.counts()["add"] == len(variant.docs)
            )
            return comparison, ok

        def check5(plan, dump, entry):
            counts = plan.counts()
            comparison = compare_states(states[1], dump)
            ok = (
                counts["add"] == counts["update"] == counts["delete"] == k
                and counts["payload_update"] == 0
                and comparison["ids_equal"]
                and comparison["payload_equal"]
                and comparison["vectors_max_abs_diff"] <= VECTOR_TOLERANCE
            )
            return comparison, ok

        plan_steps = (
            (1, "full_sync_baseline", baseline, main_name, check1),
            (2, "resync_same_snapshot", baseline, main_name, check2),
            (3, "incremental_variant", variant, main_name, check3),
            (4, "from_scratch_variant", variant, scratch_name, check4),
            (5, "revert_to_baseline", baseline, main_name, check5),
        )
        for number, name, snapshot, collection, check in plan_steps:
            report["failed_step"] = number  # 단계 안에서 예외가 나도 어느 단계인지 남는다
            states[number], ok = step(number, name, snapshot, collection, check)
            if not ok:
                break
            report["failed_step"] = None
        else:
            report["passed"] = True


# ---------------------------------------------------------------- 보고서와 환경


REPORT_KEYS = (
    "schema_version",
    "passed",
    "failed_step",
    "error",
    "started_at",
    "finished_at",
    "elapsed_seconds",
    "k",
    "seed",
    "tolerances",
    "corpus",
    "model",
    "qdrant",
    "runtime",
    "environment",
    "steps",
)


def check_report_strings(value):
    """보고서의 문자열은 `/`로 시작하지 않고 500자 이하여야 한다(#60 v0.3 asset 검사)."""
    if isinstance(value, str):
        if value.startswith("/") or len(value) > MAX_REPORT_STRING:
            raise SyncError("report_string_rejected")
    elif isinstance(value, dict):
        for key, item in value.items():
            check_report_strings(key)
            check_report_strings(item)
    elif isinstance(value, list):
        for item in value:
            check_report_strings(item)


def write_report(results_dir, report):
    check_report_strings(report)
    results_dir = Path(results_dir)
    results_dir.mkdir(parents=True, exist_ok=True)
    (results_dir / "report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )


def qdrant_version(url):
    with urllib.request.urlopen(f"{url.rstrip('/')}/", timeout=30) as response:
        return json.load(response).get("version")


def package_version(name):
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return None


def runtime_info():
    info = {
        "python": platform.python_version(),
        "sentence_transformers": package_version("sentence-transformers"),
        "torch": package_version("torch"),
        "numpy": package_version("numpy"),
        "qdrant_client": package_version("qdrant-client"),
    }
    try:
        import torch

        info["torch_threads"] = torch.get_num_threads()
    except ImportError:
        info["torch_threads"] = None
    return info


def environment_info():
    return {
        "system": platform.system(),
        "machine": platform.machine(),
        "cpu_count": os.cpu_count(),
        "omp_num_threads": os.environ.get("OMP_NUM_THREADS"),
    }


# ---------------------------------------------------------------- CLI


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--cache-root", type=Path, required=True, help="data/kisa_full/의 상위 경로"
    )
    parser.add_argument("--fixtures-dir", type=Path, default=ROOT / "fixtures/kisa_full")
    parser.add_argument("--results-dir", type=Path, default=ROOT / "results/m4/idempotency")
    parser.add_argument("--qdrant-url", default=None, help=f"기본: ${URL_ENV} 또는 {DEFAULT_URL}")
    parser.add_argument("--collection", default=COLLECTION)
    parser.add_argument(
        "--dry-run", action="store_true", help="계획만 출력하고 쓰기 호출은 하지 않는다"
    )
    parser.add_argument(
        "--all-ids", action="store_true", help=f"계획의 ID를 {PRINT_IDS}개 넘어도 전부 출력"
    )
    parser.add_argument("--verify-idempotency", action="store_true", help="이슈 #59의 1~5단계 검증")
    parser.add_argument("--batch-size", type=int, default=BATCH_SIZE)
    parser.add_argument("--max-seq-length", type=int, default=MAX_SEQ_LENGTH)
    args = parser.parse_args(argv)
    url = normalize_url(args.qdrant_url or os.environ.get(URL_ENV) or DEFAULT_URL).rstrip("/")

    def log(message):
        print(message, flush=True)

    try:
        if args.verify_idempotency:
            if args.dry_run:  # 검증은 컬렉션을 지우고 다시 만들므로 쓰기 없는 미리보기가 없다
                raise SyncError("verify_dry_run_unsupported")
            if args.batch_size != BATCH_SIZE:
                raise SyncError("verify_requires_batch_size_1")
            encoder = SentenceTransformerEncoder(args.max_seq_length, BATCH_SIZE)
            report = verify_idempotency(
                args.fixtures_dir,
                args.cache_root,
                lambda name: QdrantBackend(url, name),
                encoder,
                log=log,
            )
            report["qdrant"] = {"image": QDRANT_IMAGE, "version": qdrant_version(url)}
            report["runtime"] = runtime_info()
            report["environment"] = environment_info()
            write_report(args.results_dir, {key: report.get(key) for key in REPORT_KEYS})
            log("idempotency: " + ("pass" if report["passed"] else "FAIL"))
            return 0 if report["passed"] else 1
        snapshot = load_snapshot(args.fixtures_dir, args.cache_root)
        backend = QdrantBackend(url, args.collection)
        encoder = LazyEncoder(
            lambda: SentenceTransformerEncoder(args.max_seq_length, args.batch_size)
        )
        run_sync(snapshot, backend, encoder, args.dry_run, log, args.all_ids)
        return 0
    except SyncError as error:
        print(f"error={error}", file=sys.stderr)
    except Exception as error:  # noqa: BLE001 - 임의 예외 문자열에는 본문·경로가 섞일 수 있어 클래스 이름만 남긴다
        print(f"error=unexpected_failure:{type(error).__name__}", file=sys.stderr)
    return 1
