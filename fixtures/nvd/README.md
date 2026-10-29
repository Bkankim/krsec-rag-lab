# NVD 소표본 fixture

KISA 보안공지 소표본(`fixtures/kisa/metadata.jsonl`)이 인용하는 CVE의 NVD 레코드 서브셋과 CISA KEV 교집합 스냅샷.
RAG 평가에서 KISA 공지의 CVE ID를 NVD 설명·CVSS·영향 제품(CPE)에 조인하는 데 쓴다(조인 후보 생성은 #27).

> This product uses the NVD API but is not endorsed or certified by the NVD.
> 이 디렉터리의 `cves.jsonl`은 NVD 응답에서 필드를 골라 옮긴 수정본이다. NVD 공식 데이터로 표기하지 않는다.
> NVD·MITRE·CISA 고지 전문은 [`NOTICE.md`](NOTICE.md).

## 파일

| 파일 | 내용 |
|---|---|
| `cves.jsonl` | CVE당 1줄(JSON, 키 정렬, `id` 오름차순). 아래 "레코드 스키마" |
| `kev.json` | CISA KEV 카탈로그 중 KISA 인용 CVE와 겹치는 항목만 + 카탈로그 버전·공개 시각 |
| `manifest.json` | 수집 UTC 시각, 소스 URL·버전, 기존 수집 원천(`base_sources`), 대상 CVE 목록, 레코드별 sha256, 파일 sha256, `vendor_products_status` 상태별 개수와 drifted ID |
| `NOTICE.md` | MITRE(CVE)·NVD·CISA KEV 고지 문구 |

합계는 약 2.0MB(상한 3MB). 원 응답(NVD 연도별 피드 42MB 등)은 리포 밖 캐시 `data/nvd/`(gitignore)에만 둔다.

## 서브셋 구성 판정 (열린 결정 #26)

**KISA 인용 고유 CVE 전체를 대상으로 하고, KEV 교집합 레코드는 CPE를 더 많이 싣는다.**

- 대상: `fixtures/kisa/metadata.jsonl`의 `cve_ids` 합집합 1,560개(이것이 KISA 쪽 유일한 입력).
- 비-KEV 레코드: 설명·CVSS·CWE·CPE 3건(총 개수 `cpe_total`은 유지).
- KEV 교집합 레코드(26개): CPE 25건까지.

근거:

1. 완료 기준의 커버리지(조인 성공률)가 "KISA 인용 고유 CVE 중 NVD에서 찾은 수"로 정의된다. KEV 교집합만 담으면 26/1,560이
   되어 나머지 1,534개는 조인이 되는지조차 측정하지 못한다. 전체를 담아야 분모가 같은 조인 성공률이 나온다.
2. #27의 KISA-NVD 조인 후보는 공지 하나당 인용 CVE 전체를 NVD에 대응시켜야 한다. 한 공지가 996개를 인용하므로
   교집합만으로는 그 공지의 질의 유형(CVE 열거, 영향 제품 질의)이 만들어지지 않는다.
3. 크기: 전체 레코드를 CPE 최대 10건으로 담으면 2.1MB로 상한을 넘었다. CPE가 레코드 크기의 약 60%였고(1.3MB / 2.1MB),
   설명은 0.24MB(중앙값 116자)에 불과하다. 그래서 필드를 줄이는 대신 CPE만 비-KEV 3건으로 줄였다(1.3MB).
4. KEV는 "실제 악용"이라 질의 가치가 높은 소수(26개)이므로 CPE를 25건까지 남긴다. KEV 중 `cpe_total`이 25를 넘는 레코드는 목록이
   잘려 있으니 `cpe_total`과 `len(cpe)`를 비교해 절단 여부를 본다.
5. 재검토 트리거: KISA 소표본이 커지면(공지 수 증가) 먼저 비-KEV CPE 상한을 줄이고, 그래도 3MB를 넘으면 KEV 교집합 우선으로 좁힌다. 상한은 처음 2MB였고 `vendor_products` 추가(#36)로 3MB로 올렸다.

## 커버리지 (수집 시점 2026-10-29 UTC)

| 수치 | 값 | 의미 |
|---|---|---|
| KISA 인용 고유 CVE 수 | **1,560** | `fixtures/kisa/metadata.jsonl` `cve_ids` 합집합 |
| NVD에서 찾은 수 | **1,560** (100%) | 수집한 NVD 소스에서 레코드가 있는 CVE |
| KEV 교집합 수 | **26** | 위 CVE 중 CISA KEV 카탈로그에 있는 것 |

레코드 상태(`vuln_status`): Analyzed 1,468, Modified 52, Awaiting Analysis 35, Undergoing Analysis 4, Deferred 1. 분석 대기 레코드는
CVSS(NVD 분석분)나 CPE가 비어 있을 수 있다(CPE 없음 39건).

계산 명령(리포 루트, 네트워크 없음):

```sh
jq -r '.cve_ids[]' fixtures/kisa/metadata.jsonl | sort -u | wc -l                      # 1560
jq -r '.id' fixtures/nvd/cves.jsonl | sort -u | wc -l                                   # 1560
comm -12 <(jq -r '.cve_ids[]' fixtures/kisa/metadata.jsonl | sort -u) \
         <(jq -r '.entries[].cve_id' fixtures/nvd/kev.json | sort -u) | wc -l           # 26
uv run python scripts/fetch_nvd.py --report   # report kisa_unique_cves=1560 found_in_nvd=1560 kev_intersection=26
```

같은 수치가 `manifest.json`의 `coverage`에도 들어 있다. NVD에 없는 CVE는 `manifest.json`의 `not_found`에
`CVE ID: 사유`로 남는다(이번 수집은 0건).

## 레코드 스키마 (`cves.jsonl`) - #27 조인 입력

**조인 키는 `id`** (대문자 `CVE-YYYY-NNNN+`, KISA `cve_ids`의 원소와 문자열 그대로 일치). 한 줄에 CVE 하나, 중복 없음.

| 필드 | 타입 | 내용 |
|---|---|---|
| `id` | string | CVE ID (조인 키) |
| `published` | string | NVD 공개 시각(UTC, 시간대 표기 없음) |
| `last_modified` | string | NVD 마지막 수정 시각 |
| `vuln_status` | string | NVD 분석 상태(`Analyzed`, `Awaiting Analysis` 등) |
| `description_en` | string | 영어 설명(NVD 원문, 없으면 `""`) |
| `cvss` | array | `{version, source, type, base_score, severity, vector}`. 버전 4.0, 3.1, 3.0만 담고 같은 버전의 Primary·Secondary를 모두 둔다. 없으면 `[]` |
| `cwe` | array of string | 약점 ID(`CWE-79`, `NVD-CWE-Other` 등), 정렬·중복 제거 |
| `cpe_total` | int | 취약(`vulnerable: true`)으로 표시된 CPE 매치 수(중복 제거) |
| `cpe` | array | 위 매치 중 `criteria` 정렬 순 앞 N건(비-KEV 3, KEV 25). 각 `{criteria, version_start_including?, version_start_excluding?, version_end_including?, version_end_excluding?}`(범위 키는 값이 있을 때만) |
| `kev` | bool | CISA KEV에 있으면 `true`. 항목은 `kev.json` |
| `vendor_products` | array of string | 취약(`vulnerable: true`) CPE 매치의 `vendor:product` 고유 집합, 정렬, **절단 없음**(`cpe`와 같은 필터, CPE 2.3의 vendor·product 필드를 원문 그대로). `drifted`는 아래 규칙 |
| `vendor_products_status` | string | `ok`, `no_configurations`, `drifted` (아래) |

`vendor_products_status`:

| 값 | 뜻 |
|---|---|
| `ok` | 새 원천의 취약 매치가 1건 이상이고, 기존 필드와 새 원천이 같다 |
| `no_configurations` | 새 원천에 취약 매치가 0건(`vendor_products: []`)이고 기존 필드도 새 원천과 같다(기존 `cpe`도 비어 있다) |
| `drifted` | 기존 필드 중 하나라도 새 원천과 다르거나, 새 원천에 레코드가 없다. `drifted`가 `no_configurations`보다 우선한다 |

`drifted` 레코드는 기존 필드를 그대로 두고, `vendor_products`는 새 원천 집합과 기존 `cpe`의 `vendor:product`의 합집합이다
(새 원천에 레코드가 없으면 기존 `cpe`의 것만). 어느 상태든 기존 `cpe`의 모든 `vendor:product`는 `vendor_products`에 들어 있다.
`drifted` ID 목록과 상태별 개수는 `manifest.json`의 `vendor_products_drifted_ids`·`vendor_products_status_counts`에 있다.
`vendor_products`가 절단되지 않았으니 레코드가 어떤 제품을 갖는지는 `cpe`가 아니라 이 필드로 본다(`cpe`는 여전히 절단 목록이다).

`kev.json`: `{source_url, catalog_version, date_released, catalog_count, license, selection, entries: [...]}`.
`entries[]`는 `{cve_id, vendor_project, product, vulnerability_name, date_added, due_date, known_ransomware_campaign_use}`.
`catalog_count`는 전체 카탈로그 건수이고 `entries`는 KISA 인용 CVE와 겹치는 항목만이다.

## 선정 필드와 이유

- **description_en**: RAG가 NVD 쪽 근거로 읽는 본문. 영어 외 번역은 일부 레코드에만 있어 버린다.
- **cvss(4.0, 3.1, 3.0)**: 심각도·벡터는 "이 취약점이 얼마나 위험한가" 질의의 근거. 2.0은 구식이라 제외.
  Primary(NVD)와 Secondary(CNA) 값이 다를 수 있어 둘 다 `source`·`type`과 함께 둔다.
- **cwe**: 약점 유형 질의와 KISA 공지의 유형 서술 대조용.
- **vendor_products**: 영향 제품 질의의 정답 후보(#35). `cpe`가 절단돼 있어 제품 목록은 이 필드로만 완전하다.
- **cpe, cpe_total**: 영향 제품·버전 범위 질의용. `vulnerable: true`만 둔다(실행 환경 조건 CPE는 영향 제품이 아니다).
  CPE가 레코드 크기를 지배하므로 상한을 두고, 절단 여부를 `cpe_total`로 알린다. CPE 매칭 로직 고도화는 범위 밖이다.
- **published, last_modified, vuln_status**: 시점 질의와 분석 대기 레코드를 걸러내는 데 쓴다.
- **kev**: 실제 악용 여부 질의의 근거. 상세는 `kev.json`.

버린 것: `references`(URL 목록, 크기만 큼), CVE 5 `affected`·`cpeApplicability` 등 신규 컨테이너, 설정의 `nodes` 연산자 구조(AND/OR),
`matchCriteriaId`, 비취약 CPE, `cveTags`, CVSS 세부 지표(벡터 문자열에서 복원 가능).

## 수집 방법

사용 소스(공식 경로만):

| 소스 | 용도 |
|---|---|
| NVD 연도별 JSON 피드 2.0 `https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-<연도>.json.gz` | 대상 CVE가 25개 이상인 연도(2026: 1,556개) |
| NVD API 2.0 `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=<CVE>` | 그보다 적은 연도(2021·2022·2025: 4개, 요청 4회) |
| CISA KEV `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | KEV 교집합 |

KISA 1,560개를 API로 하나씩 부르면 키 없는 한도(6.5초 간격)로 약 2시간 49분이라 연도별 피드를 쓴다. 피드와 API는 같은 CVE 객체를 준다.

규칙(코드: `scripts/fetch_nvd.py`):

- UA 명시. 401·403·429·리다이렉트는 재시도 없이 즉시 중단(종료 코드 2). 그 외 HTTP 오류·네트워크 오류도 중단(종료 코드 1)하고
  이미 받은 캐시는 남으므로 다시 실행하면 이어서 받는다.
- 요청 간격: 키 없음 6.5초(30초당 5요청 이하), 키 있음 0.7초(30초당 50요청 이하). 피드·KEV는 다른 호스트라 2초.
- `NVD_API_KEY`는 환경변수에서만 읽는다. 값은 API 호스트(`services.nvd.nist.gov`)로 가는 요청 헤더에만 실리고, 출력·파일에 남지 않는다.
  없거나 공백이면 키 없는 한도로 동작한다.
- 원 응답은 `data/nvd/`에 저장하고(`cache.json`에 응답 시각 `Date` 헤더·sha256 기록) 다시 실행하면 재사용한다. `--refresh`로 강제 재수집.
- `manifest.json`의 `collected_at`은 캐시한 원 응답의 `Date` 헤더 중 가장 늦은 값이다(재실행 시각이 아니다).
- **기존 fixture가 있으면 그것이 기존 필드의 출처다**(#36). `fetch_nvd.py`는 커밋된 `cves.jsonl`의 기존 필드(`id`부터 `kev`까지)를 그대로 두고
  `vendor_products`·`vendor_products_status`만 새로 받은 원천(캐시)에서 만든다. 새 원천과 다른 레코드는 `drifted`로 표시하고 기존 필드는 바꾸지 않는다.
  `kev.json`과 `manifest.json`의 `coverage`·`not_found`도 커밋된 값을 바이트 그대로 둔다(새 KEV 카탈로그로 다시 쓰지 않는다). 새 카탈로그와
  레코드의 `kev` 플래그가 다르면 그 레코드가 `drifted`다. 기존 수집 원천(`sources`)은 `base_sources`로 보존하고, `sources`·`collected_at`·`files`·`records`는 이번 수집 기준이다.
  fixture가 없으면(최초 수집) 모든 필드를 원천에서 만든다. **기존 필드를 원천에서 다시 만들려면 `fixtures/nvd/`를 지운 뒤 실행한다.**
- `--refresh`는 `data/nvd/` 캐시를 무시하고 원천을 다시 받는다. fixture를 지우는 것과는 별개다.
- NVD 피드는 수집 시점의 스냅샷이다. 이후 NVD가 레코드를 고치면 새로 받은 결과와 달라진다(`manifest.json`의 소스별 `version`에 피드 시각).

재현:

```sh
# 처음에는 피드 42MB 다운로드(수 분)와 API 4회(키 없이 약 30초)가 든다.
uv run python scripts/fetch_nvd.py
# 캐시가 있으면 요청 0회, fixtures/nvd 전 파일 sha256이 그대로다(기존 fixture가 있는 상태에서도 같다).
find fixtures/nvd -type f -print0 | sort -z | xargs -0 shasum -a 256 > /tmp/before.txt
uv run python scripts/fetch_nvd.py
find fixtures/nvd -type f -print0 | sort -z | xargs -0 shasum -a 256 | diff /tmp/before.txt -
```

테스트는 합성 응답으로 요청 간격, 403/429 즉시 중단, 키 미설정 경로, `vendor_products` 병합(`drifted`·`no_configurations`)을 검증한다(`tests/test_fetch_nvd.py`, 네트워크 없음).

기존 필드가 바뀌지 않았는지는 커밋 이력이 있는 체크아웃에서 확인한다(CI는 shallow clone이라 pytest에 넣지 않았다):

```sh
uv run python scripts/check_nvd_fields.py 1646a84   # base 커밋의 cves.jsonl과 레코드마다 비교, kev.json·coverage·not_found 동일 확인
```
