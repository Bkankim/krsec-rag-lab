# M4 수집: KISA 보안공지 게시판 전체 수집과 계측

게시판(`bbsId=B0000133`) 전체를 한 번 수집하고, 누락·중복·파싱 실패를 센 결과와 규칙이다. 평가 트랙의 고정 50건
(`fixtures/kisa`)은 바꾸지 않는다. 전체 코퍼스는 `fixtures/kisa_full/`(메타데이터·manifest)와 로컬 캐시
`data/kisa_full/`(gitignore)에 따로 둔다. 본문·요약·발췌는 어떤 커밋 파일에도 없다(`LICENSES/README.md` KISA 행).
이 프로젝트는 Bkankim의 단독 프로젝트다.

## 수집 규칙

- 구현: `src/krsec_rag_lab/corpus/collect.py`, CLI `scripts/collect_kisa_full.py`. `scripts/fetch_kisa.py`는 고치지
  않고 모듈로 읽어 `Client`, `parse_list`, `parse_detail`, `parse_rss`, `canonical_url`, `content_hash`, `metadata`, `CVE`를 쓴다.
- 요청은 전부 `fetch_kisa.Client`로만 보낸다: robots.txt 준수, 요청 간격 1.5초(허용 1~2초), 리다이렉트 거부.
- 발견: 목록을 1쪽부터 넘기며 nttId를 모은다. 끝 조건은 (a) 정상 게시판 구조(목록 표와 `pagination` 영역)를 가진 빈 목록,
  (b) 새 ID가 0건인 페이지가 연속 2쪽이다. 구조가 없는 응답이나 그 밖의 목록 파싱 오류는 발견 미완료로 남기고
  `discovery_complete`를 true로 만들지 않는다. 끝나면 ID 집합을 manifest `target_ids`로 고정한다. RSS는 한 번 읽어 목록에
  없는 ID(RSS 전용)를 센다(수집 대상에는 넣지 않는다).
- 상세: 고정 ID마다 상세 페이지를 받아 `parse_detail`로 본문을 만들고 `<cache-root>/data/kisa_full/<nttId>/{source.html,body.txt}`에 쓴다.
  캐시가 있고 본문 sha256과 재파싱 결과가 manifest와 맞으면 다시 받지 않는다. 없거나 다르면 다시 받아 복구한다.
- 종결 결과: ID마다 `ok`, `parse_failed:<reason>`, `fetch_failed:<reason>` 중 하나가 manifest `documents[].result`에 남는다.
  파싱 실패와 영구 HTTP 실패(403·429 제외 4xx)는 종결이라 재개 때 다시 받지 않는다(`--retry-failed`로만 재시도).
  네트워크 오류·타임아웃·5xx는 미처리로 남아 재개 때 다시 받는다.
- 중단: 403·429(401 포함)·robots 거부·리다이렉트 거부는 즉시 중단한다. 그 밖의 `FetchError`(네트워크·HTTP 오류)가 연속 3회면
  중단한다(파싱 실패는 세지 않고, 성공·파싱 실패가 나오면 카운터가 0이 된다). 중단해도 그때까지의 manifest·메타데이터·보고서를
  저장하고 exit 1이다. 다시 실행하면 이어서 받는다. 저장은 25건마다와 종료 때다.
- 종료 코드: 이번 실행이 중단됐으면 `complete` 값과 무관하게 1. 아니면 `complete: true`(발견 완료 + 모든 고정 ID가 종결 결과)면 0,
  기록된 파싱 실패가 있어도 0. 미처리가 남으면 1.
- 재실행: 목록의 첫 페이지부터 고정 집합 안의 ID만 있는 페이지를 만날 때까지만 다시 훑고(새 글은 앞쪽에 나온다), 고정 집합
  밖에서 새로 보인 ID는 받지 않고 보고서 `new_since_freeze`에 ID만 적는다.
- 출력 규율: 화면·로그에는 진행 수치와 고정 reason code만 찍는다. 보고서·manifest 문자열 값은 `/`로 시작하지 않고 500자 이하다.

## 재현 명령

```sh
# 수집(중단되면 같은 명령으로 재개). <KISA-ROOT>는 본문 캐시를 둘 체크아웃 경로다.
uv run python scripts/collect_kisa_full.py --cache-root <KISA-ROOT>

# 재실행 확인: 산출물 사본에 돌려 커밋된 파일과 비교한다.
cp -r fixtures/kisa_full <scratch>/fx && mkdir -p <scratch>/res
uv run python scripts/collect_kisa_full.py --cache-root <KISA-ROOT> \
  --fixtures-dir <scratch>/fx --results-dir <scratch>/res

# 전체 코퍼스 유출 점검(코디네이터가 캐시가 있는 체크아웃에서 실행)
uv run python scripts/check_kisa_leaks.py --cache data/kisa_full --metadata fixtures/kisa_full/metadata.jsonl
```

`--delay`(1~2초), `--retry-failed`, `--fixtures-dir`, `--results-dir`, `--fixed-manifest`(기본 `fixtures/kisa/manifest.json`)가 있다.

## 산출물

| 파일 | 내용 |
|---|---|
| `fixtures/kisa_full/metadata.jsonl` | `ok` 문서마다 한 줄: `url`, `title`, `date`, `nttId`, `cve_ids`. nttId 오름차순 |
| `fixtures/kisa_full/manifest.json` | `schema_version`, `parser_version`(`kisa-html-v1`), `started_at`, `finished_at`, `discovery_complete`, `complete`, `target_ids`, `discovery`(발견 계측), `documents`(`nttId`, `collected_at`, `sha256`, `result`) |
| `results/m4/collection/report.json` | 아래 계측 |

## report.json 키

| 키 | 뜻 |
|---|---|
| `schema_version`, `parser_version` | 보고서 형식 버전, 파서 버전(`kisa-html-v1`) |
| `discovery_complete`, `complete` | 발견 완료 여부, 발견 완료 + 모든 고정 ID가 종결 결과를 가졌는지 |
| `discovered_ids` | 발견해 고정한 ID 수(`manifest.target_ids` 길이) |
| `list_pages`, `list_pages_with_rows` | 받은 목록 페이지 수(끝 판정 페이지 포함), 행이 있던 페이지 수 |
| `list_rows` | 목록 원시 행 수(고정 공지의 반복 포함) |
| `displayed_total`, `displayed_total_gap` | 1쪽에 표시된 총 게시물 수(못 읽으면 null), 표시 총수 - 발견 ID 수 |
| `rss_ids`, `rss_only_ids`, `rss_error` | RSS 항목 수, 목록에 없는 RSS 전용 ID, RSS 읽기 실패 reason(없으면 null) |
| `discovery_error` | 발견 미완료 사유 reason code(정상이면 null) |
| `list_duplicate_in_page` | 같은 페이지 안에서 같은 nttId 행이 반복된 초과 횟수(원시 `td.sbj` 행 수 - 고유 ID 수의 합) |
| `list_duplicate_across_pages` | 같은 nttId가 여러 페이지에 나온 초과 횟수(고정 공지 포함) |
| `list_duplicate_ids`, `list_conflict_ids` | 원시 행이 2회 이상 나온 ID, 그중 제목·날짜가 서로 다른 ID |
| `detail_ok` | 상세 수집과 파싱 성공 수 |
| `detail_failed`, `parse_failed` | 실패 reason code별 건수(`fetch_failed:<code>`, `parse_failed:<code>`) |
| `failed_ids` | reason code별 실패 ID 목록 |
| `detail_pending` | 종결 결과가 없는 고정 ID 수 |
| `missing_ids` | 발견했지만 `ok`가 아닌 ID(표시 총수와의 차이는 `displayed_total_gap`) |
| `content_duplicate_group_count`, `content_duplicate_doc_count`, `content_duplicate_groups` | 서로 다른 nttId인데 본문 sha256이 같은 묶음 수, 묶음에 든 문서 수, 묶음(`sha256`, `ids`) |
| `fixed_expected`, `fixed_present`, `fixed_missing_ids` | 고정 50건 수, 전체 코퍼스에 `ok`로 있는 수, 없는 ID |
| `fixed_hash_match`, `fixed_hash_mismatch_ids` | 고정 manifest의 sha256과 같은 수, 다른 ID(ID만 적는다) |
| `new_since_freeze`, `rediscovery_pages`, `rediscovery_complete` | 재실행 때 고정 집합 밖에서 새로 보인 ID, 다시 훑은 목록 페이지 수, 그 훑기가 끝 조건에 닿았는지(첫 수집이면 null) |
| `aborted` | 이번 실행의 중단 reason code(없으면 null) |
| `resumed`, `retry_failed` | 기존 manifest에서 이어 받았는지, `--retry-failed` 사용 여부 |
| `requests` | 이번 실행의 요청 수: `rss`, `list`, `detail`, `robots`, `total` |
| `elapsed_seconds` | 이번 실행의 소요 시간(초) |

`discovery`(manifest)의 키는 보고서의 같은 이름 키와 같은 값이다. `requests`·`elapsed_seconds`·`aborted`는 실행 한 번의 값이라
중간에 끊겨 이어 받은 경우 마지막 실행 값만 남는다.

## 계측 결과

2026-10-30 03:01 KST에 시작해 04:24 KST에 끝났다(exit 0, 중단 없음, 한 번에 완료). 아래는 `results/m4/collection/report.json` 값이다.

| 항목 | 값 |
|---|---|
| 목록 페이지 수 | 262 (행이 있던 페이지 262; 260쪽이 마지막 일반 페이지, 261·262쪽은 고정 공지 5행만) |
| 발견 ID 수 | 2592 |
| 게시판 표시 총수 | 2592 (차이 0) |
| RSS 항목 / RSS 전용 ID | 10 / 0 |
| 상세 성공 | 2590 |
| 상세 실패(fetch_failed) | 0 |
| 파싱 실패 | 2 (`parse_failed:empty_article`: 71467, 71509) |
| 미처리 | 0 |
| 목록 원시 행 | 3902 |
| 목록 중복: 페이지 안 / 페이지 사이 | 5 / 1305 |
| 목록 중복 ID / 제목·날짜 충돌 ID | 5 (72027, 72132, 72133, 72207, 72230) / 0 |
| 내용 중복 묶음 | 0 |
| 누락(발견했지만 `ok` 아님) | 2 (71467, 71509) |
| 고정 50건 포함 / 본문 sha256 일치 | 50 / 50 (불일치 0) |
| 요청 수 | 2856 (robots 1, RSS 1, 목록 262, 상세 2592) |
| 소요 시간 | 4935.4초 (약 82분, 간격 1.5초) |

메타데이터 2590행 중 1832행에 CVE ID가 있고, 서로 다른 CVE ID는 21168개다.

재실행(같은 명령을 산출물 사본에 실행): 상세 요청 0건, 요청 2건(robots 1, 목록 1쪽), `new_since_freeze` 0건,
`metadata.jsonl`은 바이트 단위로 같고 `manifest.json`은 수집 시각(`started_at`, `finished_at`, `collected_at`)을 뺀 내용이 같았다.

## 해석

확인한 것(실행 결과로 본 사실)과 추정을 나눠 적는다.

- **목록 중복(확인)**: 고정 공지 5건은 모든 페이지에 반복되고, 그 5건은 일반 번호 행으로도 한 번씩 나온다. 그래서 페이지 사이 중복은
  5건 x 261쪽(첫 등장 제외) = 1305이다. 페이지 안 중복 5건은 일반 번호 행이 있는 쪽에서 같은 ID가 고정 공지 행과 일반 행으로 두 번 나온 것이다.
  `parse_list`는 같은 페이지의 같은 nttId를 dict로 접으므로 이 5건은 `parse_list` 결과만 보면 0으로 보인다. 원시 `td.sbj` 행 수와의 차이로 센다.
  같은 ID의 제목·날짜가 다른 경우(충돌)는 없었다.
- **표시 총수와 발견 수(확인)**: 둘 다 2592라 차이가 없다. 표시 총수가 고정 공지를 따로 세지 않는다는 뜻이므로(일반 행 번호 최댓값 = 총수),
  고정 공지는 일반 행과 같은 글이다. 고정 공지가 일반 번호가 없는 별도 글이었다면 발견 수가 총수보다 컸을 것이다.
- **RSS(확인)**: 항목 10건이 모두 목록에 있다. RSS 전용 ID는 0이다. RSS는 최근 10건만 담으므로 이 수치만으로 목록 누락이 없다는 증명은 되지 않는다.
- **파싱 실패 2건(확인과 추정)**: 71467, 71509는 `empty_article`이다. 이 두 건을 다시 받아 구조만 확인했다(본문은 출력하지 않았다):
  제목·날짜·`content_html` 영역은 정상이고 영역 안 텍스트가 0자, 이미지 3개가 있었다. 즉 본문이 이미지뿐인 공지라 텍스트 본문이 없다.
  파서 구조 변경이 아니다(확인). 이미지에 글이 들어 있다는 점은 확인하지 못했고(이미지를 열어 보지 않았다), 텍스트 코퍼스에서 제외하는 것이 맞다는 판단은 추정이다.
  두 건은 종결 결과 `parse_failed:empty_article`로 manifest에 남고, 재개 때 다시 받지 않는다.
- **내용 중복(확인)**: 서로 다른 ID인데 본문 sha256이 같은 묶음은 없다. 같은 글이 다른 ID로 재게시된 경우는 이 수집에서 보이지 않았다.
  본문이 조금만 달라도 다른 해시이므로 유사 중복(근접 중복)은 이 수치가 말해 주지 않는다.
- **고정 50건(확인)**: 50건이 모두 전체 코퍼스에 있고 본문 sha256이 `fixtures/kisa/manifest.json`과 모두 같다. 같은 파서로 다시 받은 본문이 평가 트랙의 고정본과 바이트 단위로 같다는 뜻이다.
- **누락(확인)**: 발견했지만 `ok`가 아닌 ID는 위 2건뿐이고 상세 HTTP 실패와 미처리는 0이다.

## 한계

- 목록 발견은 수집 시점의 스냅샷이다. 수집 도중이나 이후에 올라온 글은 `new_since_freeze`에만 적히고 코퍼스에 들어오지 않는다(이번 재실행은 0건).
- 재실행은 목록 첫 페이지부터 고정 집합 안의 ID만 있는 페이지까지만 훑는다. 오래된 글의 삭제·수정은 목록 전체를 다시 훑지 않아 보지 못한다.
  본문 변경은 캐시 해시가 맞는 종결 ID를 다시 받지 않으므로 감지하지 못한다(변경 감지는 `scripts/fetch_kisa.py --refresh`가 고정 50건에 대해서만 한다).
- 발견 도중(첫 수집의 목록 훑기) 중단되면 부분 발견 집합을 저장하지 않아 다음 실행이 1쪽부터 다시 시작한다(약 262요청).
- 중단·재개를 거치면 `requests`·`elapsed_seconds`는 마지막 실행 값이다. 이번 수집은 한 번에 끝났다.
- 첨부 파일(`attach`)과 이미지 속 글은 수집하지 않는다. 파싱 실패 2건이 그 예다.
- 본문 정규화·CVE 추출은 고정 수집기와 같은 규칙(`parse_detail`, `CVE` 정규식)이라 그 한계를 그대로 물려받는다.
- 전체 코퍼스 유출 점검은 이 문서의 재현 명령대로 캐시가 있는 체크아웃에서 돌린다. 문서가 2590개라 본문당 패턴 하나씩 git grep을
  돌리는 현재 방식은 시간이 오래 걸릴 수 있다(옵션 추가는 이 티켓의 범위 밖이다).
