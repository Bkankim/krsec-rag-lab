"""dev/test 분할 검사 - docs/eval-protocol.md 6절의 기준을 구현한다.

분할 단위는 질의가 아니라 그룹이다. dev와 test 사이에서 아래 세 종류의 그룹이 겹치면 누수다.

- notice: 같은 공지(nttId)를 정답으로 삼는 질의
- cve: 같은 CVE ID와 연결된 질의 (질의가 직접 적은 CVE + 정답 공지가 인용한 CVE)
- near_dup: 근접중복 공지 묶음 (정규화한 제목이 같고 게시일 간격이 14일 이하인 공지의 연결 성분)
  + 정규화한 질의 문장이 같은 질의

표준 라이브러리만 쓴다. 지표 계산(hit@k 등)은 여기에 두지 않는다.
"""

import re
import unicodedata
from collections import defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import date

NEAR_DUP_WINDOW_DAYS = 14
SPLITS = ("dev", "test")
KINDS = ("notice", "cve", "near_dup")

CVE_ID_RE = re.compile(r"CVE-\d{4}-\d{4,}")
# \b는 한글 조사가 붙은 "CVE-2026-12345를"에서 끝 경계를 못 찾는다(\w가 한글을 포함).
# ASCII 영숫자 기준 look-around를 쓴다.
_CVE_IN_TEXT_RE = re.compile(r"(?<![A-Za-z0-9])CVE-\d{4}-\d{4,}(?![0-9])", re.IGNORECASE)


class SplitLeakError(AssertionError):
    """dev/test 사이에 그룹이 겹친다."""

    def __init__(self, overlaps: "list[Overlap]"):
        self.overlaps = overlaps
        super().__init__(
            "dev/test group overlap: "
            + "; ".join(
                f"{o.kind}={o.key} dev={list(o.dev_items)} test={list(o.test_items)}"
                for o in overlaps
            )
        )


@dataclass(frozen=True)
class Overlap:
    kind: str
    key: str
    dev_items: tuple[str, ...]
    test_items: tuple[str, ...]


def extract_cve_ids(text: str) -> list[str]:
    """텍스트에서 CVE ID를 대문자로 정규화해 등장 순서대로(중복 제거) 뽑는다."""
    found: dict[str, None] = {}
    for match in _CVE_IN_TEXT_RE.finditer(text):
        found.setdefault(match.group(0).upper(), None)
    return list(found)


def normalize_cve_id(cve_id: str) -> str:
    normalized = cve_id.strip().upper()
    if not CVE_ID_RE.fullmatch(normalized):
        raise ValueError(f"malformed CVE ID: {cve_id!r}")
    return normalized


def normalize_text(text: str) -> str:
    """NFKC + casefold + 공백 접기. 제목과 질의 문장의 동일성 비교에 쓴다."""
    return " ".join(unicodedata.normalize("NFKC", text).casefold().split())


def near_dup_groups(notices: Iterable[Mapping]) -> dict[str, str]:
    """nttId -> 근접중복 그룹 ID. 근접중복이 없는 공지는 자기 nttId가 곧 그룹 ID다.

    두 공지는 정규화한 제목이 같고 게시일 간격이 NEAR_DUP_WINDOW_DAYS 이하이면 근접중복이다.
    관계는 추이적으로 닫는다(A-B, B-C가 근접중복이면 A, B, C가 한 그룹).
    그룹 ID는 구성원 중 가장 작은 nttId다(길이 -> 사전순).
    """
    by_title: dict[str, list[tuple[date, str]]] = defaultdict(list)
    seen: set[str] = set()
    for notice in notices:
        ntt_id = str(notice["nttId"])
        if ntt_id in seen:
            raise ValueError(f"duplicate nttId in catalog: {ntt_id}")
        seen.add(ntt_id)
        by_title[normalize_text(notice["title"])].append(
            (date.fromisoformat(notice["date"]), ntt_id)
        )

    groups: dict[str, str] = {}
    for members in by_title.values():
        members.sort()
        components: list[list[str]] = []
        previous: date | None = None
        for published, ntt_id in members:
            if previous is not None and (published - previous).days <= NEAR_DUP_WINDOW_DAYS:
                components[-1].append(ntt_id)
            else:
                components.append([ntt_id])
            previous = published
        for component in components:
            group_id = min(component, key=lambda value: (len(value), value))
            for ntt_id in component:
                groups[ntt_id] = group_id
    return groups


def group_keys(
    item: Mapping, notices_by_id: Mapping[str, Mapping], groups: Mapping[str, str]
) -> dict[str, set[str]]:
    """질의 하나의 그룹 키. 키 이름은 KINDS와 같고 near_dup에는 질의 문장 키도 들어간다."""
    ntt_ids = {str(value) for value in item.get("ntt_ids", ())}
    cve_ids = {normalize_cve_id(value) for value in item.get("cve_ids", ())}
    for ntt_id in ntt_ids:
        if ntt_id not in notices_by_id:
            raise ValueError(f"item {item['id']!r}: nttId {ntt_id} not in notice catalog")
        cve_ids.update(normalize_cve_id(value) for value in notices_by_id[ntt_id]["cve_ids"])
    near_dup = {f"notice:{groups[ntt_id]}" for ntt_id in ntt_ids}
    if item.get("query"):
        near_dup.add(f"query:{normalize_text(item['query'])}")
    return {"notice": ntt_ids, "cve": cve_ids, "near_dup": near_dup}


def find_overlaps(items: Iterable[Mapping], notices: Iterable[Mapping]) -> list[Overlap]:
    """dev와 test에 모두 걸친 그룹을 종류별로 모은다. 비어 있으면 분할이 깨끗하다.

    item: {"id", "split": "dev"|"test", "ntt_ids": [...], "cve_ids": [...], "query": "..."}
    (ntt_ids, cve_ids, query는 생략 가능 - 답 없음 질의는 ntt_ids가 비어 있다)
    notices: fixtures/kisa/metadata.jsonl 한 줄과 같은 형태 {"nttId", "title", "date", "cve_ids"}
    """
    catalog = list(notices)
    notices_by_id = {str(row["nttId"]): row for row in catalog}
    groups = near_dup_groups(catalog)

    seen_ids: set[str] = set()
    # kind -> key -> split -> item ids
    index: dict[str, dict[str, dict[str, list[str]]]] = {
        kind: defaultdict(lambda: {"dev": [], "test": []}) for kind in KINDS
    }
    # near_dup 성분 안에서 dev/test가 서로 다른 공지로 갈라지는지 보려고 공지도 모은다
    members: dict[str, dict[str, set[str]]] = defaultdict(lambda: {"dev": set(), "test": set()})
    for item in items:
        item_id, split = str(item["id"]), item["split"]
        if split not in SPLITS:
            raise ValueError(f"item {item_id!r}: split must be one of {SPLITS}, got {split!r}")
        if item_id in seen_ids:
            raise ValueError(f"duplicate item id: {item_id!r}")
        seen_ids.add(item_id)
        for kind, keys in group_keys(item, notices_by_id, groups).items():
            for key in keys:
                index[kind][key][split].append(item_id)
        for ntt_id in item.get("ntt_ids", ()):
            members[groups[str(ntt_id)]][split].add(str(ntt_id))

    overlaps: list[Overlap] = []
    for kind in KINDS:
        for key, by_split in sorted(index[kind].items()):
            if not (by_split["dev"] and by_split["test"]):
                continue
            if kind == "near_dup" and key.startswith("notice:"):
                # 같은 공지가 양쪽에 있는 경우는 notice 종류가 이미 잡는다.
                sides = members[key.removeprefix("notice:")]
                if not any(d != t for d in sides["dev"] for t in sides["test"]):
                    continue
            overlaps.append(Overlap(kind, key, tuple(by_split["dev"]), tuple(by_split["test"])))
    return overlaps


def assert_disjoint(items: Iterable[Mapping], notices: Iterable[Mapping]) -> None:
    """겹치는 그룹이 하나라도 있으면 SplitLeakError."""
    overlaps = find_overlaps(items, notices)
    if overlaps:
        raise SplitLeakError(overlaps)
