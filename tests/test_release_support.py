"""릴리스 테스트 공용 도구 - 합성 리포(두 트랙, exact+BM25 결과, README, 릴리스 노트)를 만든다.

KISA 캐시·모델·네트워크를 쓰지 않는다. 결과 파일·manifest·metrics는 실제 실행기(`runner.run_baseline`)로
만들어서 검증 대상 파일이 실제 산출물과 같은 모양을 갖게 한다. 이 파일에는 테스트가 없다.
"""

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

from krsec_rag_lab.baselines import data, runner

ROOT = Path(__file__).resolve().parents[1]
RETRIEVERS = ("exact", "bm25")


def load_script(name: str):
    """scripts/<name>.py를 모듈로 읽는다(여러 테스트 파일이 같은 모듈 객체를 쓴다)."""
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


tables = load_script("make_readme_tables")
release = load_script("check_release")

PUBLIC_RECORDS = {
    "CVE-2026-0001": "Acme Router firmware allows remote buffer overflow",
    "CVE-2026-0002": "Acme Router web console allows command injection",
    "CVE-2026-0003": "Globex Gateway improper authentication in the admin panel",
    "CVE-2026-0004": "Globex Gateway cross site scripting in the login page",
    "CVE-2026-0005": "Initech Database server SQL injection through the search box",
    "CVE-2026-0006": "Initech Database backup tool path traversal",
    "CVE-2026-0007": "Umbrella Camera firmware hard coded credentials",
    "CVE-2026-0008": "Umbrella Camera streaming service denial of service",
}
NTT_IDS = ["90001", "90002", "90003", "90004", "90005", "90006"]
KISA_BODIES = {
    "90001": "Acme 라우터 보안 업데이트 CVE-2026-1001 CVE-2026-1002 를 인용한다",
    "90002": "Globex 게이트웨이 인증 우회 CVE-2026-1003 을 인용한다",
    "90003": "Initech 데이터베이스 패치 안내 CVE-2026-1004 취약점",
    "90004": "스미싱 문자 주의 안내 본문 CVE 없음",
    "90005": "Umbrella 카메라 펌웨어 업데이트 CVE-2026-1002 도 인용한다",
    "90006": "일반 보안 점검 방법 설명 문서 서버 패치 절차",
}


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + "\n", "utf-8")


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


def sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def kisa_question(qid, query, query_type, split, answers=(), unjudged=(), excluded=False):
    row = {
        "answers": [
            {
                "doc_id": doc,
                "doc_sha256": sha(doc),
                "evidence": [
                    {"end": 12, "judge": "A", "parser_version": "kisa-html-v1", "start": 0},
                    {"end": 12, "judge": "B", "parser_version": "kisa-html-v1", "start": 0},
                ],
                "reason": "A:cve_discussed B:cve_discussed",
            }
            for doc in answers
        ],
        "cve_ids": [],
        "excluded": excluded,
        "query": query,
        "query_type": query_type,
        "question_id": qid,
        "split": split,
        "surface_cve": False,
        "unjudged": list(unjudged),
    }
    if query_type == "no_answer":
        row["no_answer_reason"] = "합성 부재 확인"
    return row


def write_inputs(root: Path) -> None:
    write_jsonl(
        root / data.PUBLIC_CORPUS,
        [{"id": cve, "description_en": text} for cve, text in PUBLIC_RECORDS.items()],
    )
    write_jsonl(
        root / data.PUBLIC_QUERIES,
        [
            public_query("q-cve-1", "CVE-2026-0001 취약점의 영향", "cve_explicit", "dev", ["CVE-2026-0001"]),
            public_query("q-prod-1", "globex gateway 취약점", "product_symptom", "dev", ["CVE-2026-0003"], ["CVE-2026-0004"]),
            public_query("q-na-1", "CVE-2026-9001를 설명하는 레코드", "no_answer", "dev"),
            public_query("q-cve-2", "CVE-2026-0005는 어떤 취약점인가요?", "cve_explicit", "test", ["CVE-2026-0005"]),
            public_query("q-cve-3", "CVE-2026-0007 취약점의 영향", "cve_explicit", "test", ["CVE-2026-0007"]),
            public_query("q-prod-2", "umbrella camera 취약점", "product_symptom", "test", ["CVE-2026-0007", "CVE-2026-0008"]),
            public_query("q-na-2", "CVE-2026-9002를 설명하는 레코드", "no_answer", "test"),
        ],
    )  # fmt: skip
    (root / "fixtures/kisa").mkdir(parents=True, exist_ok=True)
    manifest = {"documents": [{"nttId": ntt, "sha256": sha(ntt)} for ntt in NTT_IDS]}
    (root / data.KISA_MANIFEST).write_text(json.dumps(manifest), encoding="utf-8")
    write_jsonl(
        root / data.KISA_METADATA,
        [
            {
                "cve_ids": [],
                "date": "2026-01-01",
                "nttId": ntt,
                "title": f"공지 {ntt} 제목",
                "url": f"https://example.invalid/{ntt}",
            }
            for ntt in NTT_IDS
        ],
    )
    write_jsonl(
        root / data.KISA_GOLDEN,
        [
            kisa_question("k-cve-1", "CVE-2026-1001 관련 공지", "cve_explicit", "dev", ["90001"]),
            kisa_question("k-cve-2", "CVE-2026-1002를 인용한 공지", "cve_explicit", "dev", ["90001", "90005"]),
            kisa_question("k-prod-1", "Globex 게이트웨이 인증 우회 공지", "product_symptom", "dev", ["90002"]),
            kisa_question("k-exp-ex", "설명 질문이지만 정답이 판정 불가", "explanation_comparison", "dev", [], ["90006"], True),
            kisa_question("k-na-1", "CVE-2026-9999 관련 공지", "no_answer", "dev"),
            kisa_question("k-cve-3", "CVE-2026-1004 알려주세요", "cve_explicit", "test", ["90003"]),
            kisa_question("k-exp-1", "서버 패치 절차 설명", "explanation_comparison", "test", ["90006"], ["90003"]),
            kisa_question("k-na-2", "CVE-2026-9998 관련 공지", "no_answer", "test"),
        ],
    )  # fmt: skip
    for path in (
        "eval/public/manifest.json",
        "eval/golden/judge_manifest.json",
        "eval/golden/agreement.json",
        "eval/golden/error_rates.json",
        "fixtures/nvd/manifest.json",
    ):
        (root / path).parent.mkdir(parents=True, exist_ok=True)
        (root / path).write_text(json.dumps({"synthetic": path}) + "\n", encoding="utf-8")


def kisa_body(ntt_id: str, document) -> str:
    assert document["nttId"] == ntt_id
    return KISA_BODIES[ntt_id]


README_TEMPLATE = f"""# synthetic

## 결과

{tables.BEGIN}
{tables.END}

끝.
"""


def build_repo(root: Path) -> Path:
    """합성 리포: 입력, exact·BM25 x 두 트랙 결과, README(표 기록), 릴리스 노트(asset 목록)."""
    write_inputs(root)
    for track in data.TRACKS:
        for retriever in RETRIEVERS:
            runner.run_baseline(
                track,
                retriever,
                root,
                load_body=kisa_body if track == "kisa" else None,
            )
    (root / "README.md").write_text(README_TEMPLATE, encoding="utf-8")
    assert tables.main(["--root", str(root)]) == 0
    write_note(root)
    return root


def write_note(root: Path) -> None:
    """현재 파일 상태로 릴리스 노트의 asset 목록을 다시 쓴다."""
    table = release.render_asset_table(root, release.default_assets(root))
    note = root / release.NOTE_PATH
    note.parent.mkdir(parents=True, exist_ok=True)
    note.write_text(f"# note\n\n{release.BEGIN}\n\n{table}\n{release.END}\n", encoding="utf-8")


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]
