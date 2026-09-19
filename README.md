# krsec-rag-lab

한국어 보안 문서 RAG 평가 하네스 - 온프렘 스택 ablation 리포트.

KISA 보안공지(한국어)와 NVD CVE(영어)를 코퍼스로, 검증된 골든 평가셋 위에서
RAG 파이프라인의 각 구성요소(청킹·하이브리드 검색·리랭킹·임베딩)를 하나씩 바꿔가며
검색·생성 품질과 비용(지연시간·VRAM)을 측정한 기록을 남긴다.

핵심 원칙:

- **측정이 먼저다.** 모든 실험은 가설 → 측정 → 판정(기각 포함)으로 종료한다. 데모는 부록이다.
- **재현 가능해야 한다.** README의 모든 수치는 릴리스에 첨부된 질문별 원시 결과에서 재생성된다.
- **온프렘으로 돌아간다.** 로컬 임베딩(bge-m3) + Qdrant + 로컬 LLM. 외부 API 의존 없음.

## 상태

스캐폴딩 단계. 로드맵은 [PLAN.md](PLAN.md)와 [Milestones](../../milestones) 참조.

## 데이터와 라이선스

원본 데이터의 소스별 라이선스와 재배포 범위는 [LICENSES/](LICENSES/) 참조.
KISA 보안공지 본문은 재배포하지 않는다(수집 스크립트와 메타데이터 인덱스만 제공).

## 실행

```bash
uv sync
uv run pytest
```

## KISA 소표본 (별도 로컬 실행)

공개 기본 테스트는 자작 합성 데이터만 사용하며 네트워크나 KISA 캐시가 필요 없다.
KISA 원문을 사용하는 후속 평가는 아래 수집과 캐시 검사를 별도로 실행한 환경에서만
진행한다. 원문·요약·발췌는 출력하거나 평가 결과에 포함하지 않는다.

```bash
uv run python scripts/fetch_kisa.py --limit 50 --delay 1.5
uv run python scripts/fetch_kisa.py --check-cache
```

- `fixtures/kisa/metadata.jsonl`: URL·제목·날짜·nttId·CVE ID만 저장한다.
- `fixtures/kisa/manifest.json`: 대상 ID, UTC 수집 시각, 본문 SHA256, 파서 버전을 고정한다.
- `data/kisa/<nttId>/source.html`, `body.txt`: 원 응답과 추출 본문의 로컬 캐시다.
  `/data/*` gitignore 차단을 유지하며 커밋·릴리스·CI artifact로 업로드하지 않는다.

manifest가 없을 때만 공식 [RSS](https://www.boho.or.kr/kr/rss.do?bbsId=B0000133)와
[목록 페이지](https://www.boho.or.kr/kr/bbs/list.do?bbsId=B0000133&menuNo=205020)를
함께 사용해 50~100건을 선택한다. 고정 공지와 RSS의 중복은 `nttId`로 제거하고
날짜·ID 역순으로 표본을 고른다. 표본은 당시 두 경로에서 발견한 공지의 일부이며,
전체 KISA 공지의 대표성을 보장하지 않는다. 이후에는 고정 ID만 사용하므로 `--limit`은
기존 manifest에 영향을 주지 않는다. 정상 캐시는 재요청하지 않고, 새 clone에서는
동일 ID를 수집해 기존 해시와 대조한다. 중단된 최초 수집은 완료된 ID를 건너뛰어 재개한다.

파서 `kisa-html-v1`은 `b_title`의 제목·날짜와 `content_html`의 텍스트를 추출한다.
HTML 엔티티를 해제하고 script/style/noscript를 제외한 뒤 블록 요소의 줄 경계,
줄 내부 공백, 빈 줄을 정규화한다. **SHA256은 이 본문의 UTF-8 바이트**를 대상으로
하며 마지막 개행은 없다. 조회수 등 바깥 UI 변화는 해시에 영향을 주지 않는다.
이미지 OCR·첨부파일 다운로드는 수행하지 않으며 CVE는 추출 본문의 명시적 ID만 수집한다.

```bash
uv run python scripts/fetch_kisa.py --refresh
```

`--refresh`는 고정 ID를 재수집한다. 본문 해시나 허용 메타데이터가 바뀌면 종료 코드 1과
ID·해시만 보고하고, 기존 manifest·메타·정상 캐시는 보존한다. 관찰한 응답은 같은
무시 디렉터리의 `observed.html`·`observed.txt`에만 남긴다. 같은 본문이면 최초 수집 시각도
보존한다. 파서 버전이 다른 manifest나 손상된 캐시는 자동으로 승인하지 않는다.
`--check-cache`는 오프라인으로 원 응답의 재파싱 결과까지 대조하고, 캐시 부재 시
수집 명령을 안내하며 실패한다. 평가 코드에서는 `load_cached_body`를 이 경계로 사용할 수 있다.

모든 HTTP 요청은 명시적 UA와 기본 1.5초 간격을 사용한다(`--delay`는 1~2초).
robots.txt를 먼저 확인하고 더 긴 crawl-delay/request-rate가 있으면 이를 따른다.
접근 차단·리다이렉트·robots 금지는 즉시 중단하며 자동 우회하지 않는다.
그 외 요청·파싱 실패도 실행 중 누적 3건이면 중단한다.
실행 종료 시 `report`의 `success`(수집·검증 성공), `failed`(요청·캐시 오류),
`parse_failed`(파싱 오류), `new`(새 ID), `cached`, `restored`, `unchanged`,
`changed`, `metadata_changed`, `pending` 건수를 출력한다. 변경·실패 시 종료 코드는 1이다.

커밋할 변경을 stage한 뒤 본문 유출 표본 검사도 실행한다.

```bash
uv run python scripts/check_kisa_leaks.py
git status --short --ignored -- data/kisa
git ls-files -- data/kisa
```

검사기는 최소 3개 문서의 고유 본문 문자열을 메모리에서 선택해 `git grep -I -F`의
표준 입력으로 전달한다. tracked 작업 파일과 staged index, JSON 이스케이프 형태를
검색하며 원 문자열 대신 SHA256·일치 건수만 출력한다. 이는 표본 검사이므로 모든 변형의
유출 부재를 보장하는 것은 아니다. 커밋 diff의 허용 필드와 노트북 출력도 함께 검토한다.
