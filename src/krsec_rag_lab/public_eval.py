"""공개 평가 트랙 질의셋(#35) - NVD fixture 메타데이터에서 정답을 기계적으로 정한다.

입력은 `fixtures/nvd/cves.jsonl` 하나다(문서 단위 = 레코드 `id`). 네트워크·KISA 캐시·LLM 판정을 쓰지 않고,
질의셋에는 질문과 ID만 넣는다(NVD 설명 원문은 출력에 없다). 같은 입력과 seed면 출력이 바이트까지 같다.
채점 규칙(`gold` / `unjudged` / 비관련)과 질의 유형 이름은 docs/eval-protocol.md 1·5·11절을 따른다.

표준 라이브러리만 쓴다.
"""

import argparse
import hashlib
import json
import random
import re
import sys
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path

from krsec_rag_lab.splits import CVE_ID_RE, assert_disjoint, extract_cve_ids

PROTOCOL_VERSION = "eval-protocol-v2"
SEED = 35
MAX_REDRAWS = 10

FIXTURE_PATH = "fixtures/nvd/cves.jsonl"
OUT_DIR = "eval/public"
QUERIES_FILE = "queries.jsonl"
MANIFEST_FILE = "manifest.json"

QUERY_TYPES = ("cve_explicit", "product_symptom", "no_answer")
OUTPUT_FIELDS = ("id", "query", "query_type", "gold", "unjudged", "split", "vendor_product")
ID_PREFIX = {"cve_explicit": "pub-cve", "product_symptom": "pub-prod", "no_answer": "pub-noans"}

# 표본 크기(최소 50 / 50 / 20은 이슈 #35 완료 기준)
N_CVE_EXPLICIT = 60
N_PRODUCT_SYMPTOM = 60
N_NO_ANSWER = 24
MIN_COUNTS = {"cve_explicit": 50, "product_symptom": 50, "no_answer": 20}
MAX_PRODUCT_GOLD = 200
COMPONENT_CAP = 0.25
DEV_TARGET = 0.40
DEV_RANGE = (0.30, 0.50)
NO_ANSWER_YEARS = (2024, 2025, 2026)

STATUS_OK = "ok"
STATUS_NO_CONFIGURATIONS = "no_configurations"
STATUS_DRIFTED = "drifted"
VENDOR_PRODUCT_STATUSES = (STATUS_OK, STATUS_NO_CONFIGURATIONS, STATUS_DRIFTED)

# CVE ID를 담는 템플릿(cve_explicit, no_answer 공용). 조사가 붙어도 splits.extract_cve_ids가 읽어낸다.
CVE_TEMPLATES = (
    "{cve}는 어떤 취약점인가요?",
    "{cve}를 설명하는 NVD 레코드를 찾아주세요.",
    "{cve} 취약점의 영향 범위와 심각도가 궁금합니다.",
)
# CVE ID가 없는 템플릿(product_symptom)
PRODUCT_TEMPLATES = (
    "{vendor_product} 제품에 영향을 주는 취약점은 무엇인가요?",
    "{vendor_product}에서 발견된 취약점 레코드를 찾아주세요.",
    "{vendor_product} 제품이 영향받는 보안 취약점 목록이 궁금합니다.",
)

CPE_FIELD_COUNT = 13


class ProductShortageError(ValueError):
    """컴포넌트 상한 안에서 필요한 수만큼 제품을 뽑지 못했다. 다음 seed로 다시 뽑는다."""


class PublicSplitLeakError(AssertionError):
    """dev/test 사이에 같은 CVE ID 또는 vendor:product 키를 공유하는 질의가 있다."""

    def __init__(self, leaks: "list[tuple[str, str, list[str], list[str]]]"):
        self.leaks = leaks
        super().__init__(
            "public eval dev/test key overlap: "
            + "; ".join(f"{kind}={key} dev={dev} test={test}" for kind, key, dev, test in leaks)
        )


def _split_cpe_fields(criteria: str) -> list[str]:
    """이스케이프되지 않은 ':'로 나눈다. 역슬래시는 바로 뒤 한 글자를 이스케이프한다."""
    fields: list[str] = []
    current: list[str] = []
    chars = iter(criteria)
    for char in chars:
        if char == "\\":
            current.append(char)
            current.extend(next(chars, ""))
        elif char == ":":
            fields.append("".join(current))
            current = []
        else:
            current.append(char)
    fields.append("".join(current))
    return fields


def cpe_vendor_product(criteria: str) -> str:
    """CPE 2.3 형식 문자열에서 `vendor:product`를 뽑는다.

    필드는 이스케이프되지 않은 `:`로 나누고(`cpe:2.3:part:vendor:product:version:...`, 13개) 4·5번째 필드를
    원문 그대로 이어 붙인다(소문자·역슬래시 이스케이프 포함, 정규화하지 않는다). vendor나 product가 `*`·`-`이면
    제품을 특정할 수 없으므로 거부한다.
    """
    fields = _split_cpe_fields(criteria)
    if len(fields) != CPE_FIELD_COUNT or fields[0] != "cpe" or fields[1] != "2.3":
        raise ValueError(f"not a CPE 2.3 formatted string: {criteria!r}")
    vendor, product = fields[3], fields[4]
    if vendor in ("", "*", "-") or product in ("", "*", "-"):
        raise ValueError(f"CPE has no concrete vendor:product: {criteria!r}")
    return f"{vendor}:{product}"


def load_records(raw: bytes) -> list[dict]:
    records = [json.loads(line) for line in raw.decode("utf-8").splitlines() if line.strip()]
    seen: set[str] = set()
    for record in records:
        record_id = record["id"]
        if not CVE_ID_RE.fullmatch(record_id):
            raise ValueError(f"malformed CVE ID in fixture: {record_id!r}")
        if record_id in seen:
            raise ValueError(f"duplicate record id: {record_id}")
        seen.add(record_id)
        if record["vendor_products_status"] not in VENDOR_PRODUCT_STATUSES:
            raise ValueError(f"{record_id}: unknown vendor_products_status")
        # 절단된 cpe 목록의 제품도 절단 없는 vendor_products에 들어 있어야 한다(fixture README)
        in_cpe = {cpe_vendor_product(entry["criteria"]) for entry in record["cpe"]}
        missing = in_cpe - set(record["vendor_products"])
        if missing:
            raise ValueError(f"{record_id}: cpe products not in vendor_products: {sorted(missing)}")
        if record["cpe_total"] < len(record["cpe"]):
            raise ValueError(f"{record_id}: cpe_total is smaller than len(cpe)")
    return records


def product_index(records: Iterable[Mapping]) -> dict[str, list[str]]:
    """vendor:product -> 그 제품을 `vendor_products`에 가진 레코드 id(정렬). 정답 규칙의 gold 쪽이다."""
    index: dict[str, set[str]] = defaultdict(set)
    for record in records:
        for vendor_product in record["vendor_products"]:
            index[vendor_product].add(record["id"])
    return {key: sorted(ids) for key, ids in sorted(index.items())}


def product_unjudged(records: Iterable[Mapping], vendor_product: str) -> list[str]:
    """제품 부재를 확정할 수 없는 레코드 id(정렬).

    `no_configurations`이거나, `drifted`인데 그 제품이 `vendor_products`에 없는 레코드. 그 밖은 비관련이다.
    """
    unjudged = []
    for record in records:
        status = record["vendor_products_status"]
        missing = status == STATUS_DRIFTED and vendor_product not in record["vendor_products"]
        if status == STATUS_NO_CONFIGURATIONS or missing:
            unjudged.append(record["id"])
    return sorted(unjudged)


class _Components:
    """질의를 그룹 키(CVE ID, vendor:product)로 잇는 연결 성분. 키 -> 성분 번호와 성분 크기를 들고 있다."""

    def __init__(self) -> None:
        self.key_to_comp: dict[str, int] = {}
        self.size: dict[int, int] = {}
        self._next = 0

    def merged_size(self, keys: Iterable[str]) -> int:
        """질의 하나(keys)를 더했을 때 그 질의가 속하게 될 성분의 크기."""
        comps = {self.key_to_comp[key] for key in keys if key in self.key_to_comp}
        return 1 + sum(self.size[comp] for comp in comps)

    def add(self, keys: Iterable[str]) -> None:
        keys = list(keys)
        comps = {self.key_to_comp[key] for key in keys if key in self.key_to_comp}
        target = self._next
        self._next += 1
        self.size[target] = 1 + sum(self.size.pop(comp) for comp in comps)
        for key, comp in list(self.key_to_comp.items()):
            if comp in comps:
                self.key_to_comp[key] = target
        for key in keys:
            self.key_to_comp[key] = target


def query_keys(query: Mapping) -> set[str]:
    """질의의 그룹 키. CVE ID(정답 레코드 + 질문에 적힌 ID)와 vendor:product."""
    keys = {f"cve:{record_id}" for record_id in query["gold"]}
    keys.update(f"cve:{cve_id}" for cve_id in extract_cve_ids(query["query"]))
    if query.get("vendor_product"):
        keys.add(f"product:{query['vendor_product']}")
    return keys


def _components_of(queries: Sequence[Mapping]) -> list[list[int]]:
    """질의 위치의 연결 성분 목록(위치 오름차순)."""
    parent = list(range(len(queries)))

    def find(node: int) -> int:
        while parent[node] != node:
            parent[node] = parent[parent[node]]
            node = parent[node]
        return node

    owner: dict[str, int] = {}
    for position, query in enumerate(queries):
        for key in sorted(query_keys(query)):
            if key in owner:
                parent[find(position)] = find(owner[key])
            else:
                owner[key] = position
    grouped: dict[int, list[int]] = defaultdict(list)
    for position in range(len(queries)):
        grouped[find(position)].append(position)
    return sorted(grouped.values(), key=lambda members: members[0])


def assign_splits(queries: Sequence[Mapping]) -> list[str]:
    """연결 성분을 큰 것부터 dev/test로 나눈다. 목표 dev 비율과의 부족분이 큰 쪽에 둔다(동점은 dev)."""
    total = len(queries)
    splits = ["test"] * total
    dev_count = test_count = 0
    components = _components_of(queries)
    components.sort(key=lambda members: (-len(members), members[0]))
    for members in components:
        dev_deficit = DEV_TARGET * total - dev_count
        test_deficit = (1 - DEV_TARGET) * total - test_count
        if dev_deficit >= test_deficit:
            dev_count += len(members)
            for position in members:
                splits[position] = "dev"
        else:
            test_count += len(members)
    return splits


def assert_no_key_leak(queries: Iterable[Mapping]) -> None:
    """같은 CVE ID나 vendor:product 키를 가진 질의가 dev와 test에 갈라져 있으면 PublicSplitLeakError."""
    by_key: dict[str, dict[str, list[str]]] = defaultdict(lambda: {"dev": [], "test": []})
    for query in queries:
        for key in query_keys(query):
            by_key[key][query["split"]].append(query["id"])
    leaks = []
    for key, by_split in sorted(by_key.items()):
        if by_split["dev"] and by_split["test"]:
            kind = key.split(":", 1)[0]
            leaks.append((kind, key.split(":", 1)[1], by_split["dev"], by_split["test"]))
    if leaks:
        raise PublicSplitLeakError(leaks)


def split_check_inputs(
    queries: Iterable[Mapping], records: Iterable[Mapping]
) -> tuple[list[dict], list[dict]]:
    """`splits.assert_disjoint`에 넘길 (질의 항목, 문서 목록). 이슈 #35의 매핑이다."""
    items = [
        {
            "id": query["id"],
            "split": query["split"],
            "ntt_ids": list(query["gold"]),
            "cve_ids": list(query["gold"]),
            "query": query["query"],
        }
        for query in queries
    ]
    notices = [
        {
            "nttId": record["id"],
            "title": record["id"],
            "date": record["published"][:10],
            "cve_ids": [record["id"]],
        }
        for record in records
    ]
    return items, notices


def assert_public_split(queries: Sequence[Mapping], records: Sequence[Mapping]) -> None:
    """vendor:product·CVE 키 검사와 `splits.assert_disjoint`를 모두 통과해야 한다."""
    assert_no_key_leak(queries)
    items, notices = split_check_inputs(queries, records)
    assert_disjoint(items, notices)


def cited_cve_ids(records: Iterable[Mapping]) -> set[str]:
    """레코드 설명(description_en)이 본문에서 인용한 CVE ID 집합. no_answer 후보에서 뺀다."""
    cited: set[str] = set()
    for record in records:
        cited.update(extract_cve_ids(record.get("description_en", "")))
    return cited


def readable_vendor_product(vendor_product: str) -> str:
    """CPE 이스케이프(역슬래시 + 문자)를 풀어 질문 문장에 넣을 사람이 읽는 형태로 만든다."""
    return re.sub(r"\\(.)", r"\1", vendor_product)


def _no_answer_ids(rng: random.Random, corpus_ids: set[str], count: int) -> list[str]:
    found: list[str] = []
    while len(found) < count:
        candidate = f"CVE-{rng.choice(NO_ANSWER_YEARS)}-{rng.randint(1000, 99999)}"
        if candidate not in corpus_ids and candidate not in found:
            found.append(candidate)
    return found


def _draw(
    records: Sequence[Mapping],
    index: Mapping[str, Sequence[str]],
    seed: int,
) -> tuple[list[dict], dict]:
    """seed 하나로 표본을 뽑는다. 제품이 모자라면 ValueError. 반환: (분할 전 질의, 제외 통계)."""
    rng = random.Random(seed)
    corpus_ids = {record["id"] for record in records}
    total = N_CVE_EXPLICIT + N_PRODUCT_SYMPTOM + N_NO_ANSWER
    cap = int(COMPONENT_CAP * total)

    queries: list[dict] = []
    components = _Components()

    def append(
        query_type: str,
        number: int,
        query: str,
        gold: list[str],
        unjudged: list[str],
        vendor_product: str | None,
    ) -> dict:
        row = {
            "id": f"{ID_PREFIX[query_type]}-{number:04d}",
            "query": query,
            "query_type": query_type,
            "gold": gold,
            "unjudged": unjudged,
            "split": "",
            "vendor_product": vendor_product,
        }
        queries.append(row)
        return row

    for number, record_id in enumerate(rng.sample(sorted(corpus_ids), N_CVE_EXPLICIT), start=1):
        template = rng.choice(CVE_TEMPLATES)
        row = append("cve_explicit", number, template.format(cve=record_id), [record_id], [], None)
        components.add(query_keys(row))

    for number, cve_id in enumerate(
        _no_answer_ids(rng, corpus_ids | cited_cve_ids(records), N_NO_ANSWER), start=1
    ):
        template = rng.choice(CVE_TEMPLATES)
        row = append("no_answer", number, template.format(cve=cve_id), [], [], None)
        components.add(query_keys(row))

    eligible = [key for key, ids in index.items() if len(ids) <= MAX_PRODUCT_GOLD]
    rng.shuffle(eligible)
    accepted = 0
    over_cap = 0
    for vendor_product in eligible:
        if accepted == N_PRODUCT_SYMPTOM:
            break
        gold = list(index[vendor_product])
        keys = {f"cve:{record_id}" for record_id in gold} | {f"product:{vendor_product}"}
        if components.merged_size(keys) > cap:
            over_cap += 1
            continue
        accepted += 1
        template = rng.choice(PRODUCT_TEMPLATES)
        row = append(
            "product_symptom",
            accepted,
            template.format(vendor_product=readable_vendor_product(vendor_product)),
            gold,
            product_unjudged(records, vendor_product),
            vendor_product,
        )
        components.add(query_keys(row))
    if accepted < N_PRODUCT_SYMPTOM:
        raise ProductShortageError(f"only {accepted} products fit the component cap {cap}")

    for row in queries:
        if row["query_type"] != "product_symptom" and extract_cve_ids(row["query"]) == []:
            raise ValueError(f"{row['id']}: CVE template did not carry a CVE ID")
        if row["query_type"] == "product_symptom" and extract_cve_ids(row["query"]):
            raise ValueError(f"{row['id']}: product query must not contain a CVE ID")
    stats = {
        "cap_queries": cap,
        "large_component_products": over_cap,
        "gold_over_max_products": sum(1 for ids in index.values() if len(ids) > MAX_PRODUCT_GOLD),
    }
    return queries, stats


def _split_problem(queries: Sequence[Mapping]) -> str | None:
    dev = sum(1 for query in queries if query["split"] == "dev")
    ratio = dev / len(queries)
    if not DEV_RANGE[0] <= ratio <= DEV_RANGE[1]:
        return f"dev ratio {ratio:.3f} outside {DEV_RANGE[0]}-{DEV_RANGE[1]}"
    for query_type in QUERY_TYPES:
        sides = {q["split"] for q in queries if q["query_type"] == query_type}
        if sides != {"dev", "test"}:
            return f"{query_type} missing from a split"
    return None


def build(
    records: Sequence[Mapping], input_sha256: str, seed: int = SEED
) -> tuple[list[dict], dict]:
    """질의 목록과 manifest(딕셔너리, 질의 파일 해시 제외)를 만든다.

    분할이 비율(30~50%)을 못 맞추면 seed+1, seed+2 ...로 표본을 다시 뽑는다(최대 MAX_REDRAWS회).
    """
    index = product_index(records)
    attempts: list[dict] = []
    for redraw in range(MAX_REDRAWS + 1):
        attempt_seed = seed + redraw
        try:
            queries, stats = _draw(records, index, attempt_seed)
        except ProductShortageError as error:
            attempts.append({"seed": attempt_seed, "accepted": False, "reason": str(error)})
            continue
        splits = assign_splits(queries)
        for query, split in zip(queries, splits, strict=True):
            query["split"] = split
        problem = _split_problem(queries)
        if problem is not None:
            attempts.append({"seed": attempt_seed, "accepted": False, "reason": problem})
            continue
        attempts.append({"seed": attempt_seed, "accepted": True, "reason": "ok"})
        break
    else:
        raise RuntimeError(f"no valid split after {MAX_REDRAWS} redraws: {attempts}")

    queries.sort(key=lambda row: (QUERY_TYPES.index(row["query_type"]), row["id"]))
    assert_public_split(queries, records)
    return queries, _manifest(records, queries, stats, attempts, input_sha256, seed)


def _manifest(
    records: Sequence[Mapping],
    queries: Sequence[Mapping],
    stats: Mapping,
    attempts: Sequence[Mapping],
    input_sha256: str,
    seed: int,
) -> dict:
    by_type = Counter(q["query_type"] for q in queries)
    by_split = Counter(q["split"] for q in queries)
    by_type_split = {
        query_type: dict(Counter(q["split"] for q in queries if q["query_type"] == query_type))
        for query_type in QUERY_TYPES
    }
    statuses = Counter(record["vendor_products_status"] for record in records)
    product_queries = [q for q in queries if q["query_type"] == "product_symptom"]
    return {
        "protocol_version": PROTOCOL_VERSION,
        "track": "public",
        "seed": seed,
        "seed_used": next(a["seed"] for a in attempts if a["accepted"]),
        "attempts": list(attempts),
        "language": {"query": "ko", "document": "en"},
        "input": {"path": FIXTURE_PATH, "sha256": input_sha256, "records": len(records)},
        "counts": {
            "total": len(queries),
            "by_type": dict(sorted(by_type.items())),
            "by_split": dict(sorted(by_split.items())),
            "by_type_split": {k: dict(sorted(v.items())) for k, v in by_type_split.items()},
            "dev_ratio": round(by_split["dev"] / len(queries), 4),
            "minimum_by_type": MIN_COUNTS,
        },
        "excluded_products": {
            "gold_over_max": {
                "max_gold": MAX_PRODUCT_GOLD,
                "count": stats["gold_over_max_products"],
            },
            "large_component": {
                "cap_fraction": COMPONENT_CAP,
                "cap_queries": stats["cap_queries"],
                "count": stats["large_component_products"],
            },
        },
        "unjudged": {
            "vendor_products_status_counts": dict(sorted(statuses.items())),
            "product_queries": len(product_queries),
            "product_queries_with_unjudged": sum(1 for q in product_queries if q["unjudged"]),
            "unjudged_ids_per_product_query": sorted({len(q["unjudged"]) for q in product_queries}),
            "from_cpe_truncation": 0,
        },
        "cpe_rules": {
            "vendor_product_extraction": (
                "CPE 2.3 형식 문자열을 이스케이프되지 않은 ':'로 나눠 13개 필드를 확인하고 4번째(vendor)와 "
                "5번째(product) 필드를 원문 그대로(소문자·역슬래시 이스케이프 유지) 'vendor:product'로 잇는다. "
                "vendor나 product가 '*'·'-'이면 제품을 특정할 수 없어 거부한다."
            ),
            "truncation": (
                "cpe_total이 담긴 cpe 수보다 크면 cpe 목록은 절단된 것이다(비-KEV 3건, KEV 25건 상한). "
                "정답과 unjudged는 절단된 cpe가 아니라 절단 없는 vendor_products에서 정한다. "
                f"절단된 레코드 {sum(1 for r in records if r['cpe_total'] > len(r['cpe']))}건도 "
                "제품 소속이 확정되므로 CPE 절단 때문에 unjudged가 되는 레코드는 없다(unjudged.from_cpe_truncation). "
                "빌드 때 모든 레코드에서 cpe의 vendor:product가 vendor_products의 부분집합인지 검사한다."
            ),
        },
        "generation_rules": {
            "cve_explicit": (
                f"레코드 {N_CVE_EXPLICIT}건을 seed로 무작위 추출해 CVE ID가 든 한국어 템플릿 질문을 만든다. "
                "gold = 그 레코드 하나."
            ),
            "product_symptom": (
                f"vendor_products에 든 vendor:product {N_PRODUCT_SYMPTOM}개를 seed로 뽑아 CVE ID 없는 한국어 템플릿 "
                "질문을 만든다. gold = vendor_products에 그 제품이 있는 레코드 전부. unjudged = "
                "vendor_products_status가 no_configurations인 레코드, 그리고 drifted인데 그 제품이 vendor_products에 "
                "없는 레코드. 그 밖은 비관련. 이 표본에서 gold가 비는 질문은 없다(제품은 gold가 1건 이상인 것만 뽑는다)."
            ),
            "no_answer": (
                f"코퍼스에 없는 형식상 유효한 CVE ID {N_NO_ANSWER}개(연도 {list(NO_ANSWER_YEARS)})를 seed로 만든다. "
                "gold = 빈 집합. 부재는 이 fixture 코퍼스 기준이며 NVD 전체에 없다는 뜻이 아니다."
            ),
            "explanation_comparison": (
                "만들지 않는다. 개념·조치·차이를 묻는 질문은 fixture 메타데이터로 기계적 정답을 정할 수 없고 "
                "LLM 판정은 쓰지 않는다."
            ),
        },
        "split_rules": {
            "group_keys": (
                "CVE ID(질문에 적힌 ID와 gold 레코드 id)와 vendor:product(product_symptom 질의의 제품). "
                "같은 키를 가진 질의를 연결 성분으로 묶어 같은 split에 둔다."
            ),
            "assignment": "연결 성분을 큰 것부터 목표 dev 비율 0.4의 부족분이 큰 쪽에 둔다(동점은 dev).",
            "dev_ratio_range": list(DEV_RANGE),
            "redraw": (
                f"비율 미달이거나 유형이 한 split에 없으면 seed+1, seed+2 ...로 표본을 다시 뽑는다(최대 "
                f"{MAX_REDRAWS}회). 시도는 attempts에 기록한다."
            ),
            "component_cap": (
                f"질의 {COMPONENT_CAP:.0%}({stats['cap_queries']}건)를 넘는 연결 성분을 만드는 제품은 표본에서 뺀다. "
                f"gold 레코드가 {MAX_PRODUCT_GOLD}건을 넘는 제품도 뺀다."
            ),
            "checks": "빌드마다 키 교차 검사와 splits.assert_disjoint를 통과해야 쓴다.",
        },
        "query_fields": list(OUTPUT_FIELDS),
        "query_file": f"{OUT_DIR}/{QUERIES_FILE}",
    }


def render_queries(queries: Iterable[Mapping]) -> str:
    return "".join(
        json.dumps(dict(row), ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
        for row in queries
    )


def render_manifest(manifest: Mapping) -> str:
    return json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def build_files(root: Path, seed: int = SEED) -> dict[str, str]:
    """root 아래 fixture를 읽어 출력 파일 이름 -> 내용을 만든다(쓰지 않는다)."""
    raw = (root / FIXTURE_PATH).read_bytes()
    records = load_records(raw)
    queries, manifest = build(records, hashlib.sha256(raw).hexdigest(), seed)
    queries_text = render_queries(queries)
    manifest["query_file_sha256"] = hashlib.sha256(queries_text.encode("utf-8")).hexdigest()
    return {QUERIES_FILE: queries_text, MANIFEST_FILE: render_manifest(manifest)}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="공개 평가 트랙 질의셋 생성(#35)")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--seed", type=int, default=SEED)
    args = parser.parse_args(argv)
    files = build_files(args.root, args.seed)
    out_dir = args.root / OUT_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    for name, text in files.items():
        # 텍스트 모드는 Windows에서 LF를 CRLF로 바꿔 파일 바이트가 manifest의 sha256과 어긋난다
        data = text.encode("utf-8")
        (out_dir / name).write_bytes(data)
        print(f"{OUT_DIR}/{name} sha256={hashlib.sha256(data).hexdigest()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
