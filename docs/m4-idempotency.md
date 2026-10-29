# M4 색인: Qdrant 증분 동기화와 멱등성 검증

전체 코퍼스 스냅샷(`fixtures/kisa_full/manifest.json` + `metadata.jsonl` + 로컬 캐시 `data/kisa_full/`)과 Qdrant
컬렉션을 맞추는 증분 동기화와, 갱신·삭제·재인덱싱에 대한 멱등성 검증이다. 본문·요약·발췌는 어떤 커밋 파일에도
없다(`LICENSES/README.md` KISA 행). 이 프로젝트는 Bkankim의 단독 프로젝트다.

## 동기화 규칙

- 구현: `src/krsec_rag_lab/corpus/index_sync.py`, CLI `scripts/sync_index.py`. numpy·torch·sentence_transformers·
  qdrant_client는 함수 안에서만 import하므로 CI(`uv sync --locked --dev`)에서도 모듈이 import된다.
- 단위: 문서 하나 = point 하나(청킹 없음). point ID는 `uuid5(POINT_NAMESPACE, "kisa:<nttId>")`다. 같은 nttId는
  언제나 같은 ID이고, ID에서 본문을 알 수 없다.
- payload: `nttId`, `sha256`(본문), `input_sha256`(인코딩 입력의 sha256), `parser_version`, `date`, `cve_ids`뿐이다.
  본문과 제목 텍스트는 넣지 않는다.
- 임베딩: bge-m3 dense, revision `5617a9f61b028005a4858fdac845db406aefb181`(#11 베이스라인과 같다), CLS pooling,
  L2 정규화, float32, CPU. 입력은 `제목 + "\n" + 본문`이고 문서마다 한 번 인코딩한다.
- 스냅샷 읽기: manifest `target_ids` 중 `result == "ok"`인 문서만 색인 후보다. 캐시는
  `<cache-root>/data/kisa_full/<nttId>/body.txt`만 읽고(재파싱 없음) sha256을 manifest와 대조한다. 불일치는
  `cache_hash_mismatch`, 파일 없음은 `cache_missing`으로 실패한다.
- 동기화 계획: 스냅샷과 컬렉션의 payload를 비교해 아래로 나눈다.

  | 분류 | 조건 | 동작 |
  |---|---|---|
  | 추가 | point ID가 컬렉션에 없음 | 인코딩 + upsert |
  | 갱신 | `input_sha256`이 다름(제목이나 본문이 바뀜) | 재인코딩 + upsert |
  | payload 갱신 | 입력 지문은 같고 payload가 다름(날짜, CVE, parser_version, 본문 sha256) | payload만 덮어씀 |
  | 삭제 | 컬렉션에는 있는데 manifest `target_ids`에 없음 | delete |
  | 유지 | 둘 다 같음 | 아무것도 하지 않음 |

  manifest에서 `ok`가 아닌 대상 ID는 새로 색인하지 않지만 이미 색인된 point는 유지한다(`kept_unresolved`).
  계획(건수와 ID)은 실행 전에 출력한다(ID가 50개를 넘으면 앞 50개만, `--all-ids`로 전부). `--dry-run`은 계획만
  출력하고 쓰기 호출을 하지 않으며 모델도 읽지 않는다.
- 삭제 거부: 입력 manifest가 `complete: true`가 아니면 삭제가 들어간 동기화를 `incomplete_manifest_delete_refused`로
  거부한다(부분 수집을 삭제로 오해하지 않도록). 삭제가 없는 동기화는 미완료 manifest에서도 된다. 검증 모드는
  파생 스냅샷이 `complete: true`라 이 거부가 걸리지 않으므로, 입력 manifest가 미완료면 컬렉션을 건드리기 전에
  `incomplete_manifest_verify_refused`로 멈춘다. 검증 모드에 `--dry-run`을 주면 `verify_dry_run_unsupported`로 거부한다.
- 쓰기 순서: payload 갱신, 추가·갱신(32건 단위로 인코딩 후 upsert), 삭제 순이다. 중간에 실패해도 컬렉션은
  스냅샷의 부분 집합 + 이전 상태라 같은 명령을 다시 돌리면 이어진다.
- 출력 규율: 화면·오류·보고서에는 진행 수치와 고정 reason code만 찍는다. 예상 밖 예외는
  `unexpected_failure:<예외 클래스 이름>`만 남긴다.

고정 reason code: `snapshot_invalid`, `cache_missing`, `cache_invalid`, `cache_hash_mismatch`,
`incomplete_manifest_delete_refused`, `incomplete_manifest_verify_refused`, `dimension_mismatch`, `invalid_id`, `corpus_too_small`,
`verify_requires_batch_size_1`, `verify_dry_run_unsupported`, `report_string_rejected`, `unexpected_failure:<클래스>`.

## 재현 명령

`<KISA-ROOT>`는 `data/kisa_full/`을 가진 체크아웃 경로다(커밋 파일에는 쓰지 않는다).

```sh
# Qdrant (비기본 호스트 포트, 이 실행이 만든 컨테이너만 지운다)
docker run -d --name krsec-qdrant-m4 --label krsec-run=1 -p 127.0.0.1:16340:6333 qdrant/qdrant:v1.19.2
uv sync --locked --group qdrant --group embed
export KRSEC_QDRANT_URL=http://127.0.0.1:16340 OMP_NUM_THREADS=8

# 계획만 보기, 실제 동기화
uv run --no-sync python scripts/sync_index.py --cache-root <KISA-ROOT> --dry-run
uv run --no-sync python scripts/sync_index.py --cache-root <KISA-ROOT>

# 멱등성 검증 1~5단계 (results/m4/idempotency/report.json을 쓴다)
uv run --no-sync python scripts/sync_index.py --verify-idempotency --cache-root <KISA-ROOT>

docker rm -f krsec-qdrant-m4
uv sync --locked --dev
```

옵션: `--collection`(기본 `krsec_kisa_full`), `--qdrant-url`(기본 `$KRSEC_QDRANT_URL` 또는 `http://127.0.0.1:16333`),
`--fixtures-dir`, `--results-dir`, `--max-seq-length`(기본 8192), `--batch-size`(기본 1; 검증 모드는 1만 허용).
검증은 컬렉션 `krsec_m4_idem_main`, `krsec_m4_idem_scratch`를 처음에 지우고 다시 만든다(다른 컬렉션은 건드리지 않는다).

## 검증 시나리오 (k = 5)

세 집합은 서로 겹치지 않고, `ok` ID를 `sha256("59:<nttId>")` 순으로 정렬해 앞에서 고른다(고정 시드 59).
파생 스냅샷은 검증용 임시 디렉터리에만 쓰고 `target_ids`·`documents`·`metadata`를 파생 집합으로 다시 쓰며
`complete: true`를 유지한다. `fixtures/kisa_full/**`와 `data/kisa_full/` 원본은 바꾸지 않는다.

- 기준 스냅샷 = 전체에서 예비 5개를 뺀 것. 파싱 실패 2건은 `target_ids`에 남는다(색인되지 않는다).
- 변형 스냅샷 = 기준에서 갱신 5개(임시 사본의 `body.txt` 끝에 고정 표식 줄을 더하고 manifest sha256을 다시 계산),
  삭제 5개, 추가 = 예비 5개.

| 단계 | 동작 | 통과 조건 |
|---|---|---|
| 1 | 빈 컬렉션에 기준 스냅샷 전체 동기화 | point 수 = 기준 스냅샷 문서 수 |
| 2 | 같은 스냅샷으로 다시 동기화 | 계획 0/0/0, 인코딩 0건, 쓰기 호출 0건, point ID 집합·payload·벡터가 1단계 직후와 동일 |
| 3 | 변형 스냅샷으로 동기화 | 계획 정확히 5/5/5, 인코딩·upsert 10건, delete 5건, 영향 없는 point는 payload·벡터가 그대로 |
| 4 | 같은 변형 스냅샷으로 새 컬렉션에서 처음부터 생성 | 3단계 결과와 point ID 집합·payload 동일, 벡터 abs 1e-5 이내 |
| 5 | 기준 스냅샷으로 되돌려 동기화 | 계획 5/5/5, 1단계 상태와 point ID 집합·payload 동일, 벡터 abs 1e-5 이내 |

검증은 batch_size 1로 고정하고 sha256으로 벡터를 재사용하지 않는다(모든 추가·갱신을 실제로 인코딩한다).
계획 표기는 추가/갱신/삭제 순이다. Qdrant는 cosine 컬렉션에 벡터를 넣을 때 정규화하므로 저장된 벡터가 입력과 미세하게 다를 수
있다. 비교는 모두 Qdrant에서 되읽은 값끼리 한다.

## 결과

실행: 2026-10-30 05:10 KST에 시작해 05:53 KST에 끝났다(`elapsed_seconds` 2598.7, 약 43분). 명령은 위 재현 명령 그대로이고
exit 0, 1~5단계 모두 통과다. 값은 `results/m4/idempotency/report.json`에서 가져왔다.

| 항목 | 값 |
|---|---|
| Qdrant | 서버 1.19.2, 이미지 `qdrant/qdrant:v1.19.2`, qdrant-client 1.19.1 |
| 모델 | `BAAI/bge-m3` revision `5617a9f61b028005a4858fdac845db406aefb181` |
| 모델 모듈 | Transformer, Pooling, Normalize |
| pooling / dtype / 차원 | `cls` / float32 / 1024 |
| 벡터 노름(관측 최소 / 최대) | 0.99999980 / 1.00000024 (L2 정규화 확인) |
| `max_seq_length` / batch_size / 장치 | 8192 / 1 / CPU |
| 런타임 | Python 3.13.14, sentence-transformers 6.1.0, torch 2.14.1, numpy 2.5.3 |
| 환경 | Darwin arm64, 코어 18, `OMP_NUM_THREADS=8`(torch 스레드 8) |
| 스냅샷 | 대상 ID 2592, `ok` 2590(색인 후보), 파싱 실패 2(색인 안 함), 기준 스냅샷 `ok` 2585 |
| 고른 ID | 갱신 495 22426 67075 71956 72135 / 삭제 20109 35224 36169 72128 72248 / 추가 25970 27186 36091 36305 71807 |

단계별 결과(계획은 추가/갱신/삭제, 괄호는 payload 갱신·유지 수):

| 단계 | 계획 | point 수 | 인코딩 | 쓰기(upsert / payload / delete) | 비교 결과 | 소요(초) |
|---|---|---|---|---|---|---|
| 1 빈 컬렉션에 기준 전체 | 2585/0/0 (0, 0) | 2585 | 2585 | 2585 / 0 / 0 | point 수 = 기준 문서 수 2585 | 1298.6 |
| 2 같은 스냅샷 재동기화 | 0/0/0 (0, 2585) | 2585 | 0 | 0 / 0 / 0 | ID 집합·payload 동일, 벡터 최대 차 0.0 | 0.8 |
| 3 변형 스냅샷 증분 | 5/5/5 (0, 2575) | 2585 | 10 | 10 / 0 / 5 | 영향 없는 2575 point 전부 payload·벡터 동일, 갱신 5건 벡터 변경, 삭제 5건 없음, 추가 5건 있음 | 9.1 |
| 4 변형 스냅샷으로 처음부터 생성 | 2585/0/0 (0, 0) | 2585 | 2585 | 2585 / 0 / 0 | 3단계 결과와 ID 집합·payload 동일, 벡터 최대 차 0.0 (허용 1e-5) | 1283.6 |
| 5 기준 스냅샷으로 되돌림 | 5/5/5 (0, 2575) | 2585 | 10 | 10 / 0 / 5 | 1단계 상태와 ID 집합·payload 동일, 벡터 최대 차 0.0 (허용 1e-5) | 4.4 |

같은 장비·같은 스레드 수·batch_size 1에서는 인코딩이 결정적이라 4·5단계의 벡터 최대 차가 0.0이었다(허용오차 1e-5는 여유).
3단계의 갱신은 본문 끝에 표식 줄을 더한 문서 5건이고, 5건 모두 벡터가 바뀌었다.

### 인코딩 시간 추정과 `max_seq_length` 근거

소표본(무작위 20건, 스레드 8)으로 문서당 시간을 쟀다: 상한 512 토큰이면 0.41초, 1024면 0.41초, 8192면 0.63초.
전체 약 2590건 x 인코딩 횟수(1단계 전체 + 4단계 처음부터 전체 + 증분 10건씩 두 번)를 8192 상한의 0.63초로 계산하면
약 5200건 x 0.63초 = 약 55분이다. 3시간을 한참 밑돌아 상한을 낮출 이유가 없었다. 실제 인코딩은 문서당 약 0.50초였고
(1단계 1298.6초, 4단계 1283.6초) 검증 전체가 43분이었다.

상한별로 잘리는 문서 수(제목 + 본문 전체 2590건의 토큰 길이, 합계 1,817,888 토큰, 최대 31,753):

| `max_seq_length` | 잘리는 문서 수 | 인코딩하는 토큰 수 |
|---|---|---|
| 512 | 875 | 1,002,405 |
| 1024 | 367 | 1,284,963 |
| 2048 | 176 | 1,542,227 |
| 4096 | 27 | 1,719,601 |
| 8192 | 4 | 1,762,476 |

8192로 정했다. 근거: (1) #11 dense 베이스라인과 같은 표현이라 색인된 벡터를 같은 모델 설정의 검색과 비교할 수 있다,
(2) 문서 한 건 = point 한 건이고 청킹이 없어 낮은 상한은 긴 공지의 뒷부분을 통째로 버린다(512면 34%가 잘린다),
(3) 시간 비용이 총 1시간 안쪽이라 상한을 낮춰 얻는 이득이 작다. 8192를 넘는 4건은 모델이 잘라 쓴다(청킹은 범위 밖).

## report.json 키

`results/m4/idempotency/report.json`의 최상위 키다(#60이 읽는다). 문자열 값은 `/`로 시작하지 않고 500자 이하다.

| 키 | 뜻 |
|---|---|
| `schema_version` | 보고서 형식 버전(1) |
| `passed` | 1~5단계가 모두 통과했는지 |
| `failed_step` | 처음 실패한 단계 번호(통과면 null) |
| `error` | 검증이 중간에 멈춘 사유의 고정 reason code(정상이면 null) |
| `started_at`, `finished_at` | 검증 시작·끝 시각(UTC) |
| `elapsed_seconds` | 검증 전체 소요 시간(초, 인코딩 포함) |
| `k` | 갱신·삭제·추가 각각의 개수 |
| `seed` | 집합을 고른 고정 시드 |
| `tolerances` | 비교 허용오차: `unchanged_points`(영향 없는 point, 0), `vector_abs`(4·5단계 벡터) |
| `corpus` | 대상 ID 수, `ok` 문서 수, 기준 문서 수, 고른 ID(`update_ids`, `delete_ids`, `added_ids`), 토큰 통계(`max_tokens`, `total_tokens`, `truncated_docs`) |
| `model` | 모델 이름·revision·모듈·pooling·dtype·차원·`max_seq_length`·batch_size·장치·관측한 벡터 노름 최소/최대 |
| `qdrant` | 이미지 태그와 서버 버전 |
| `runtime` | python, sentence-transformers, torch, numpy, qdrant-client 버전과 torch 스레드 수 |
| `environment` | OS, 아키텍처, 코어 수, `OMP_NUM_THREADS` |
| `steps` | 단계별 기록: `step`, `name`, `collection`, `plan`(추가·갱신·payload 갱신·삭제·유지·유지된 비 ok 수), `plan_ids`(20개 이하일 때), `points`, `encoded_texts`, `writes`, `payload_keys_allowed`, `comparison`, `passed`, `elapsed_seconds` |

## 한계

- 문서 하나를 한 point로 둔다. 8192 토큰을 넘는 본문은 모델이 잘라 쓰고 청킹하지 않는다(M3 청킹 결과는 별도).
- 검증의 갱신은 본문 끝에 표식 줄을 더한 합성 변경이다. 8192 토큰을 넘는 문서에서는 표식이 잘려 벡터가 바뀌지 않을 수
  있다(보고서 `updated_vectors_changed`로 확인). 계획 판정은 본문 sha256 기반이라 영향이 없다.
- 벡터 비교 허용오차(1e-5)는 같은 장비·같은 스레드 수·batch_size 1에서의 값이다. 장비나 스레드 수가 다르면 부동소수점
  합산 순서가 달라질 수 있다.
- 한 번의 검증은 CPU 인코딩이 지배적이다(아래 소요 시간). 정기 실행 자동화, HNSW 튜닝, 검색 품질 평가는 범위 밖이다.
- 동시에 두 동기화를 같은 컬렉션에 돌리는 경우는 다루지 않는다(잠금 없음).
