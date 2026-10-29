# v0.3 릴리스 노트 (M4: KISA 전체 수집 + 멱등성 검증 + 재현 패키지)

Bkankim의 단독 프로젝트 [krsec-rag-lab](../README.md)의 세 번째 릴리스다. KISA 보안공지 게시판 전체를 한 번 수집해 누락·중복·파싱
실패를 센 계측(보고서 JSON, 메타데이터, manifest)과, 그 코퍼스를 Qdrant에 증분 동기화해 갱신·삭제·재인덱싱 멱등성을 1~5단계로
검증한 보고서를 v0.2의 asset 전부에 더해 묶었다. KISA 공지 본문은 배포하지 않는다. README의 M4 표와 이 노트의 M4 표는 두 보고서와
`fixtures/kisa_full/`의 manifest·메타데이터에서 스크립트로 다시 만든 값이다. 수치의 해석은 [m4-collection.md](m4-collection.md)와
[m4-idempotency.md](m4-idempotency.md)에 있다.

## 무엇이 들어 있나

| 구분 | 내용 | 정본 |
|---|---|---|
| 평가 규약 | eval-protocol v2 (v0.1·v0.2와 같다, 바꾸지 않았다) | [eval-protocol.md](eval-protocol.md) |
| v0.2의 asset 전부 | 베이스라인(v0.1)과 M3 실험 5개의 원시 결과·manifest·지표·판정, 번역 파일. M3 재계산 검사도 그대로 돈다 | [release-v0.1.md](release-v0.1.md), [release-v0.2.md](release-v0.2.md) |
| 전체 수집 | 게시판 전체 수집의 발견·상세·중복·누락 계측과 실행 정보 | [m4-collection.md](m4-collection.md), `results/m4/collection/report.json` |
| 전체 코퍼스 스냅샷 | 수집 대상 ID, 문서별 본문 sha256과 종결 결과, 발견 계측 / `ok` 문서마다 URL·제목·날짜·nttId·CVE ID 한 줄 | `fixtures/kisa_full/manifest.json`, `fixtures/kisa_full/metadata.jsonl` |
| 멱등성 검증 | 추가·갱신·삭제·재인덱싱 1~5단계의 계획, 쓰기 건수, 비교 결과와 모델·런타임·환경 | [m4-idempotency.md](m4-idempotency.md), `results/m4/idempotency/report.json` |
| 구현 | 수집기, Qdrant 증분 동기화(문서 하나 = point 하나, ID `uuid5`) | `src/krsec_rag_lab/corpus/`, `scripts/collect_kisa_full.py`, `scripts/sync_index.py` |
| 검사 | M4 표 재생성 대조, v0.3 asset 목록 검사 | `scripts/make_readme_tables.py`, `scripts/check_release.py` |

## M3 판정

v0.2의 판정 표다(M3 실험은 이 릴리스에서 다시 돌리지 않았다). 보조 판정과 `cve_explicit` 회귀 여부는
[experiments/summary.md](experiments/summary.md)에 있다.

<!-- BEGIN M3 RESULTS (scripts/make_readme_tables.py) -->

이 구간은 `scripts/make_readme_tables.py`가 `results/experiments/`의 질문별 원시 결과와 질의셋 라벨에서 하네스의 비교 함수(`krsec_rag_lab.experiments.compare`)로 다시 계산해 쓴다. 손으로 고치지 않는다. 검증: `uv run python scripts/make_readme_tables.py --check`. 지표는 test macro nDCG@10(condensed list, 정답이 있는 유형의 단순 평균)이고 delta = 실험 - 기준이다. 95% 구간은 test 질문을 유형별로 층화 복원추출한 paired bootstrap(10000회, 시드 20261029)의 2.5/97.5 백분위이며, delta > 0 이고 구간 하한 > 0 일 때만 `hypothesis-confirmed`다.

주 판정 5건: hypothesis-confirmed 0, hypothesis-rejected 5.

| 실험 | 주 트랙 (변형) | 기준 | test n | 기준 macro nDCG@10 | 실험 macro nDCG@10 | delta | 95% 구간 | 판정 |
|---|---|---|---|---|---|---|---|---|
| [hybrid](experiments/hybrid.md) | public (rrf) | bm25 | 74 | 0.8551 | 0.8775 | +0.0223 | [-0.0117, +0.0616] | `hypothesis-rejected` |
| [rerank](experiments/rerank.md) | public (rerank) | bm25 | 74 | 0.8551 | 0.8581 | +0.0030 | [-0.0206, +0.0244] | `hypothesis-rejected` |
| [chunking](experiments/chunking.md) | kisa (chunk_max) | dense | 23 | 0.8131 | 0.8785 | +0.0654 | [-0.0082, +0.1510] | `hypothesis-rejected` |
| [crossling](experiments/crossling.md) | public (bm25_ko2en) | bm25 | 74 | 0.8551 | 0.2771 | -0.5780 | [-0.6723, -0.4832] | `hypothesis-rejected` |
| [embedding](experiments/embedding.md) | public (swap) | dense | 74 | 0.4353 | 0.4393 | +0.0040 | [-0.0637, +0.0726] | `hypothesis-rejected` |

<!-- END M3 RESULTS (scripts/make_readme_tables.py) -->

## M4 결과

<!-- BEGIN M4 RESULTS (scripts/make_readme_tables.py) -->

이 구간은 `scripts/make_readme_tables.py`가 `results/m4/collection/report.json`, `results/m4/idempotency/report.json`, `fixtures/kisa_full/manifest.json`, `fixtures/kisa_full/metadata.jsonl`에서 다시 만들어 쓴다. 손으로 고치지 않는다. 검증: `uv run python scripts/make_readme_tables.py --check`. 보고서와 manifest의 건수가 서로 맞는지 대조한 뒤에 표를 만든다.

### 전체 수집: 규모, 누락, 중복, 파싱 실패 ([m4-collection.md](m4-collection.md))

| 항목 | 값 |
|---|---|
| 발견 ID (고정 대상) | 2592 |
| 게시판 표시 총수 / 차이 | 2592 / 0 |
| 상세 성공 | 2590 |
| 상세 실패 (fetch_failed) | 0 |
| 파싱 실패 | 2 (`parse_failed:empty_article`: 71467, 71509) |
| 미처리 | 0 |
| 누락 (발견했지만 `ok` 아님) | 2 (71467, 71509) |
| 목록 페이지 / 원시 행 | 262 / 3902 |
| 목록 중복: 페이지 안 / 페이지 사이 | 5 / 1305 |
| 목록 중복 ID / 제목·날짜 충돌 ID | 5 (72027, 72132, 72133, 72207, 72230) / 0 |
| 내용 중복 (본문 sha256이 같은 묶음 / 문서) | 0 / 0 |
| RSS 항목 / 목록에 없는 RSS 전용 ID | 10 / 0 |
| 고정 50건 포함 / 본문 sha256 일치 | 50 / 50 (기대 50) |
| 메타데이터 행 / CVE ID가 있는 행 / 서로 다른 CVE ID | 2590 / 1832 / 21168 |
| 수집 완료 / 중단 | 예 / 없음 |
| 요청 수 | 2856 (robots 1, RSS 1, 목록 262, 상세 2592) |
| 소요 시간 (초) | 4935.4 |

### 멱등성 검증 1~5단계 ([m4-idempotency.md](m4-idempotency.md))

검증 통과 (갱신·삭제·추가 각 5건, 시드 59, 실패 단계 없음, 소요 2598.7초).

| 항목 | 값 |
|---|---|
| 스냅샷 | 대상 ID 2592, `ok` 2590, `ok` 아님 2, 기준 스냅샷 2585 |
| 모델 | `BAAI/bge-m3` revision `5617a9f61b028005a4858fdac845db406aefb181` |
| pooling / dtype / 차원 | cls / float32 / 1024 |
| `max_seq_length` / batch_size / 장치 | 8192 / 1 / cpu |
| Qdrant | 서버 1.19.2, 이미지 `qdrant/qdrant:v1.19.2` |
| 런타임 | Python 3.13.14, sentence-transformers 6.1.0, torch 2.14.1, numpy 2.5.3, qdrant-client 1.19.1 |
| 환경 | Darwin arm64, 코어 18, `OMP_NUM_THREADS=8` |
| 허용오차 | 영향 없는 point 0.0, 벡터 abs 1e-05 |

| 단계 | 동작 | 계획 (추가/갱신/삭제) | point 수 | 인코딩 | 쓰기 (upsert/payload/delete) | 비교 | 통과 | 소요 (초) |
|---|---|---|---|---|---|---|---|---|
| 1 | `full_sync_baseline` | 2585/0/0 | 2585 | 2585 | 2585/0/0 | point 수 = 스냅샷 문서 수 | 예 | 1298.6 |
| 2 | `resync_same_snapshot` | 0/0/0 | 2585 | 0 | 0/0/0 | ID 집합·payload 동일, 벡터 최대 차 0.0 | 예 | 0.8 |
| 3 | `incremental_variant` | 5/5/5 | 2585 | 10 | 10/0/5 | point 수 = 스냅샷 문서 수, 영향 없는 2575건 중 2575건 동일, 갱신 벡터 변경 5건, 삭제 확인, 추가 확인 | 예 | 9.1 |
| 4 | `from_scratch_variant` | 2585/0/0 | 2585 | 2585 | 2585/0/0 | ID 집합·payload 동일, 벡터 최대 차 0.0 | 예 | 1283.6 |
| 5 | `revert_to_baseline` | 5/5/5 | 2585 | 10 | 10/0/5 | ID 집합·payload 동일, 벡터 최대 차 0.0 | 예 | 4.4 |

<!-- END M4 RESULTS (scripts/make_readme_tables.py) -->

## 재현

`<KISA-ROOT>`는 `data/kisa_full/`(본문 캐시)를 둘 체크아웃 경로다. 본문은 재배포하지 않으므로 캐시는 각자 수집해 만든다.
세 갈래로 나뉜다. 모델·네트워크 없이 되는 것, KISA 사이트에 접근해야 하는 것, Docker와 모델이 필요한 것.

### 새 클론에서 모델·네트워크·KISA 캐시 없이 되는 것

`uv sync --locked --dev`만 하면 된다. 커밋된 보고서와 manifest, 메타데이터, 문서의 생성 구간을 서로 대조한다.

```bash
git clone https://github.com/Bkankim/krsec-rag-lab.git && cd krsec-rag-lab
uv sync --locked --dev
# 베이스라인 표 + M3 판정 표 + M4 표(두 보고서, manifest, 메타데이터, README와 이 노트의 구간)를 다시 만들어 대조(불일치 exit 1)
uv run python scripts/make_readme_tables.py --check
uv run python scripts/check_release.py --note docs/release-v0.3.md     # 아래 asset 목록 검사 (v0.2의 검사를 모두 포함)
uv run python scripts/check_release.py --note docs/release-v0.2.md     # v0.2 asset 검사도 그대로 통과한다
uv run python scripts/check_release.py                                 # v0.1 asset 검사
for exp in hybrid rerank chunking crossling embedding; do
  uv run python scripts/run_experiment.py --exp "$exp" --compare       # M3 저장본 재계산 대조
done
```

M4의 대조는 `results/m4/collection/report.json`, `results/m4/idempotency/report.json`, `fixtures/kisa_full/manifest.json`,
`fixtures/kisa_full/metadata.jsonl`만 읽는다. 문서 수, 결과별 건수, 발견 계측, 메타데이터 ID가 보고서와 manifest에서 서로 맞는지
본 뒤 표를 만든다. 이 대조는 수집이나 색인을 다시 돌려 같은 값이 나오는지를 보는 것이 아니다.

### KISA 사이트 접근이 필요한 것: 전체 수집

게시판 `bbsId=B0000133`에 요청을 보낸다. 요청은 전부 `scripts/fetch_kisa.py`의 `Client`로만 보낸다: robots.txt를 먼저 읽고, 요청
간격은 1.5초(허용 1~2초)이며, 리다이렉트는 거부한다. 403·429·401, robots 거부, 리다이렉트 거부는 즉시 중단하고 우회하지 않는다.
중단되면 그때까지의 manifest·메타데이터·보고서를 저장하고 exit 1이며, 같은 명령으로 이어 받는다. 첫 수집은 요청이 약 2900건이라
간격 때문에 한 시간 반 안팎이 걸린다(보고서 `elapsed_seconds`).

```bash
uv run python scripts/collect_kisa_full.py --cache-root <KISA-ROOT>
```

재실행 확인(사본에 돌려 커밋된 파일과 비교)과 옵션은 [m4-collection.md](m4-collection.md)의 재현 명령에 있다. 본문 캐시는
`<KISA-ROOT>/data/kisa_full/<nttId>/{source.html,body.txt}`에만 쓰고 `/data/*` gitignore를 유지한다. 커밋·릴리스·CI artifact에 올리지 않는다.

### Docker와 모델이 필요한 것: 동기화와 멱등성 검증

Qdrant 컨테이너(비기본 호스트 포트)와 `embed`·`qdrant` 그룹(torch, sentence-transformers, qdrant-client), bge-m3 가중치(Hugging Face 공개
가중치, revision 고정)가 필요하다. 위 수집으로 만든 캐시도 있어야 한다. 아래는 [m4-idempotency.md](m4-idempotency.md)의 재현 명령과 같다.

```bash
docker run -d --name krsec-qdrant-m4 --label krsec-run=1 -p 127.0.0.1:16340:6333 qdrant/qdrant:v1.19.2
uv sync --locked --group qdrant --group embed
export KRSEC_QDRANT_URL=http://127.0.0.1:16340 OMP_NUM_THREADS=8

uv run --no-sync python scripts/sync_index.py --cache-root <KISA-ROOT> --dry-run     # 계획만 본다(쓰기·모델 없음)
uv run --no-sync python scripts/sync_index.py --cache-root <KISA-ROOT>               # 증분 동기화
uv run --no-sync python scripts/sync_index.py --verify-idempotency --cache-root <KISA-ROOT>   # 1~5단계 검증, results/m4/idempotency/report.json을 쓴다

docker rm -f krsec-qdrant-m4
uv sync --locked --dev
```

검증은 CPU 인코딩이 지배적이라 한 번에 약 한 시간 안쪽이 걸린다(보고서 `elapsed_seconds`). 점수의 소수 자리와 벡터 허용오차는 장비와
스레드 수에 따라 달라질 수 있다(아래 한계).

## 데이터와 모델

| 항목 | 값 |
|---|---|
| 평가 규약 | `eval-protocol-v2` ([eval-protocol.md](eval-protocol.md)) |
| 코퍼스 | KISA 보안공지 게시판 전체 스냅샷(수집 시점 고정). 평가 트랙의 고정 50건(`fixtures/kisa`)은 따로 두고 바꾸지 않았다. 고정 50건이 전체 코퍼스에 있고 본문 sha256이 같은지는 M4 표의 "고정 50건" 줄이 보여 준다 |
| 파서 | `kisa-html-v1` (고정 수집기와 같은 규칙, `scripts/fetch_kisa.py`를 고치지 않고 모듈로 읽는다) |
| 임베딩 모델 | `BAAI/bge-m3` revision `5617a9f61b028005a4858fdac845db406aefb181` (dense, CLS pooling, L2 정규화, float32, CPU, `max_seq_length` 8192, batch_size 1) |
| 벡터 DB | Qdrant 서버 1.19.2, 이미지 `qdrant/qdrant:v1.19.2`, cosine, 문서 하나 = point 하나(청킹 없음) |
| 색인 payload | `nttId`, `sha256`, `input_sha256`, `parser_version`, `date`, `cve_ids`뿐이다. 본문과 제목 텍스트는 넣지 않는다 |
| 검증 규칙 | 갱신·삭제·추가 각 5건(고정 시드 59), 1~5단계 통과 조건은 [m4-idempotency.md](m4-idempotency.md)의 검증 시나리오 표 |
| 실행 환경 | M4 표의 "모델", "런타임", "환경" 줄(`results/m4/idempotency/report.json`의 `model`, `runtime`, `environment`) |
| 그 밖 | KISA 고정 공지, NVD fixture, 교차 판정, M3 실험 모델은 [release-v0.1.md](release-v0.1.md), [release-v0.2.md](release-v0.2.md)의 같은 절과 같다 |

## asset

GitHub 릴리스 `v0.3`에 첨부하는 파일이다. v0.2의 asset 전부와 `fixtures/kisa_full/{metadata.jsonl,manifest.json}`,
`results/m4/collection/report.json`, `results/m4/idempotency/report.json`이다. 이 넷이 목록에 하나라도 없으면 검사가 실패한다.
asset 이름은 리포 경로의 `/`를 `__`로 바꾼 이름이고, 각 asset은 대응하는 리포 파일의 사본이다(sha256 동일). 모든 파일은 허용
필드만 갖는다: `kisa_full` 메타데이터는 `url`·`title`·`date`·`nttId`·`cve_ids`뿐이고, manifest와 보고서는 JSON이며 500자를 넘는
문자열과 `/`로 시작하는 문자열(키 포함, 절대 경로 모양)이 없다. KISA 공지 본문은 없다.

<!-- BEGIN ASSETS (scripts/check_release.py --print-assets) -->

| asset 이름 | 리포 경로 | 크기(바이트) | sha256 |
|---|---|---|---|
| `eval__golden__agreement.json` | `eval/golden/agreement.json` | 2694 | `9998fa9d41fc0659e78c5c7f880de52cf673f77667b3a703dc67bc937eef7510` |
| `eval__golden__error_rates.json` | `eval/golden/error_rates.json` | 2241 | `6b66e83947b2c6fd0d5ce31d8afa175f6726bd665f59f9a4f8ab2e3f1be3b221` |
| `eval__golden__golden_v1.jsonl` | `eval/golden/golden_v1.jsonl` | 29231 | `2f94253c6c0551c536973c95b830dcf123e7acb858304fa8678812a19360d3dc` |
| `eval__golden__judge_manifest.json` | `eval/golden/judge_manifest.json` | 13584 | `7eb6d0d8160cc35490a9c26c0d8482c6952388efe3c242caa2222540b189393b` |
| `eval__public__manifest.json` | `eval/public/manifest.json` | 4510 | `8d07aa30d93579317ec3d2dfe903b622f24828cd34e3db84fa2ca01ed74b0aa1` |
| `eval__public__queries.jsonl` | `eval/public/queries.jsonl` | 79561 | `1d8ab42360e3cee23e8d67bc933e5af7ec6a8365eb32d315105233016d294a99` |
| `fixtures__kisa__manifest.json` | `fixtures/kisa/manifest.json` | 11352 | `bf670ecd666e77139ae0c53a7be0badb5bdd82e8ff54d4876d59290b68c8b0c4` |
| `fixtures__kisa__metadata.jsonl` | `fixtures/kisa/metadata.jsonl` | 38254 | `c1512e8d234e0dbe4d32430877e61775612dd2248046122f74e227d446737eaf` |
| `fixtures__kisa_full__manifest.json` | `fixtures/kisa_full/manifest.json` | 533466 | `17362c4a515b56ba070b33595c82f7dcdc8d46e38ac8686f0eaf6f076da9c3c5` |
| `fixtures__kisa_full__metadata.jsonl` | `fixtures/kisa_full/metadata.jsonl` | 937882 | `f08b63276d39b5ca56885b28270d86813d9ffe059d2eb56b5bf1c34d243db722` |
| `fixtures__nvd__manifest.json` | `fixtures/nvd/manifest.json` | 266490 | `893bdee1c8454f4b78cc5257493e48038717a22c71dd3249a138fa3616d9cae6` |
| `results__baselines__kisa__bm25.jsonl` | `results/baselines/kisa/bm25.jsonl` | 161032 | `aa56a3aae836af708bb4f04df2d77adf181fab7a2636d5758aeb53ff405041f2` |
| `results__baselines__kisa__dense.jsonl` | `results/baselines/kisa/dense.jsonl` | 166222 | `9aacf60f0f9c4ba66d54f5855f9259c67d717caf1a0b0bca9e9cc5f14621c0a8` |
| `results__baselines__kisa__exact.jsonl` | `results/baselines/kisa/exact.jsonl` | 5988 | `992c1661fa6f9773deb5f312755018a1883b6b6462b5bfd62fafc828ded2c6b0` |
| `results__baselines__manifest.json` | `results/baselines/manifest.json` | 24764 | `5d539b6a98c2d379c9584e37ccbe474a699bdd08c19e4c06eca84074ab0e63e7` |
| `results__baselines__metrics.json` | `results/baselines/metrics.json` | 33318 | `c129a906ff1055f3dd3dafaeede2d7de12391ba95dad719a7a6460806e5385f0` |
| `results__baselines__public__bm25.jsonl` | `results/baselines/public/bm25.jsonl` | 298585 | `41556ebaeaa628bc78a27527447dc4f8dd86a82a4dd350f4c0092f74dfdf69e9` |
| `results__baselines__public__dense.jsonl` | `results/baselines/public/dense.jsonl` | 1035323 | `b159891e290360bdafc7efa556da8d6867d5880b0a1cbba267d0e37363259173` |
| `results__baselines__public__exact.jsonl` | `results/baselines/public/exact.jsonl` | 17051 | `699f0d51d7036e284107a33495a41c3857028308f653ebadaa921ac5f3ad2477` |
| `results__experiments__chunking__comparison.json` | `results/experiments/chunking/comparison.json` | 6488 | `f68f64c5b90e729eecce6f7c43d49c165e2a8ae739d4205914d2df09092bd0f1` |
| `results__experiments__chunking__kisa__chunk_max.jsonl` | `results/experiments/chunking/kisa/chunk_max.jsonl` | 166222 | `458b58ac05b0577d85bc00a826c4fe9af4204b5834d002c6a87157c14b417ee7` |
| `results__experiments__chunking__manifest.json` | `results/experiments/chunking/manifest.json` | 14914 | `64bd2632fc38fc3f97e000acc42804d440e6a482202ea02da88932723d3e8d20` |
| `results__experiments__chunking__metrics.json` | `results/experiments/chunking/metrics.json` | 6329 | `3979c50d4f7ddb506ba5cf179bff8aa23ae136dc4df1fe8b1a3d91e38fd65513` |
| `results__experiments__crossling__comparison.json` | `results/experiments/crossling/comparison.json` | 31450 | `284773f3d956456a4313476e068e4598a7f2d748e16a283b518e56e84b3eda47` |
| `results__experiments__crossling__manifest.json` | `results/experiments/crossling/manifest.json` | 15702 | `79f1da1353770d4bc0f0811b8c26e7f3f268e062817b2b9ba2173a90c048660e` |
| `results__experiments__crossling__metrics.json` | `results/experiments/crossling/metrics.json` | 10551 | `df51f9b6c1748b21481daee252304a62b09e8a9cef69c9ba7eb48358eb08a09e` |
| `results__experiments__crossling__public__bm25_ko2en.jsonl` | `results/experiments/crossling/public/bm25_ko2en.jsonl` | 1024380 | `b0e09d1b73cefd029e8f78f5f3b5d5a6f4ed51e47e068a85257fe18ba797a173` |
| `results__experiments__crossling__public__dense_ko2en.jsonl` | `results/experiments/crossling/public/dense_ko2en.jsonl` | 1037150 | `a8e4dfb2f9ce437210fdac37eb962002ffa9375a8d9c52ecc9049de8c24260d5` |
| `results__experiments__crossling__translations.jsonl` | `results/experiments/crossling/translations.jsonl` | 42960 | `46a0156b2875813d026c34e59a0e1faf7938f5622f86230e2b6a0bc1a94a0907` |
| `results__experiments__embedding__comparison.json` | `results/experiments/embedding/comparison.json` | 17324 | `2602a1eb8186bf55a77480245e46e6d2b34941be58d4e4b82e23eb0a3a65ebbe` |
| `results__experiments__embedding__kisa__swap.jsonl` | `results/experiments/embedding/kisa/swap.jsonl` | 165949 | `929bb7433643f076788ce24b04252151a8153beecedbc6d30ac4547afe4239bc` |
| `results__experiments__embedding__manifest.json` | `results/experiments/embedding/manifest.json` | 14574 | `4809f4b46de9fd2cdbfe4d5557ce1251354e9134dc25a630e087df2517ec063e` |
| `results__experiments__embedding__metrics.json` | `results/experiments/embedding/metrics.json` | 11391 | `e754e187e7e84fa20add576cf42636804786ce0cf485777dcc1efd0ce912622f` |
| `results__experiments__embedding__public__swap.jsonl` | `results/experiments/embedding/public/swap.jsonl` | 1034962 | `3d83140928054a792c2990f7dbd9b56b4aece7e2c61e95fdb4e008d3022b2f52` |
| `results__experiments__hybrid__comparison.json` | `results/experiments/hybrid/comparison.json` | 13080 | `c2b17027640dc161fffe00ea0606e6db794c0ba3ea8612964bb367fc26aec3d0` |
| `results__experiments__hybrid__kisa__rrf.jsonl` | `results/experiments/hybrid/kisa/rrf.jsonl` | 168271 | `1dfd4b344ddf1a4d95a7d3d93657fcfd541dd1470c7d836b76ef14fb09ee4641` |
| `results__experiments__hybrid__manifest.json` | `results/experiments/hybrid/manifest.json` | 10653 | `882ebcd05ac9d86f8fe0a085e43b6c66af58182867ca46204ab2268a1131eb3e` |
| `results__experiments__hybrid__metrics.json` | `results/experiments/hybrid/metrics.json` | 11374 | `e809b657c52ccd0c9c666f29193e00ff64f0c80f79e5f48702d42f1609e7631c` |
| `results__experiments__hybrid__public__rrf.jsonl` | `results/experiments/hybrid/public/rrf.jsonl` | 1045704 | `659911050cd6c05911ef4962e8586de152aaf255dcb4d8686d4e229b49249f4e` |
| `results__experiments__rerank__comparison.json` | `results/experiments/rerank/comparison.json` | 11741 | `46fdb29557725983b478f5cca4633154f839b74d85a0c9abcba1bc15a8c5fdbd` |
| `results__experiments__rerank__kisa__rerank.jsonl` | `results/experiments/rerank/kisa/rerank.jsonl` | 161888 | `58232c4ef91f9f8fc64d2fac88d65b9e4309665da40868523962a7fe02d2a368` |
| `results__experiments__rerank__manifest.json` | `results/experiments/rerank/manifest.json` | 11040 | `a3d23b47bd06d2d571ef5b9363e187441b7dd34996168439920a5386b4258a72` |
| `results__experiments__rerank__metrics.json` | `results/experiments/rerank/metrics.json` | 11309 | `57032ab408a5e80d93f6ba5b9ba9450f2779d9be82123cdc924c8679e1406f1c` |
| `results__experiments__rerank__public__rerank.jsonl` | `results/experiments/rerank/public/rerank.jsonl` | 300662 | `4cc1f66632dc12a4ab5c552992b24d9e1ea34a9c3f3864f196e8fe338cfa4739` |
| `results__m4__collection__report.json` | `results/m4/collection/report.json` | 1344 | `08fe27adcb994555b55931510af0448d7909c400a1e359bdcc892ff23dfd030d` |
| `results__m4__idempotency__report.json` | `results/m4/idempotency/report.json` | 6433 | `f8b33bbd4d62ce70cd09256beb74ff52d0d87d247a2e5e4659b60ea249f4bd61` |

<!-- END ASSETS -->

내려받은 asset은 `shasum -a 256 <파일>`로 위 표와 대조한다. 리포 쪽 검사는 `uv run python scripts/check_release.py --note docs/release-v0.3.md`다:

1. 목록의 항목이 허용 asset이고 파일이 있다. v0.3 허용 asset은 v0.2 목록에 M4 파일 넷을 더한 것이다.
2. v0.2의 필수 파일(베이스라인과 실험 manifest가 요구하는 결과·질의셋·재현 입력, 실험 JSON 3종)과 M4 파일 넷이 모두 목록에 있다.
   M3 asset 하나만 빠져도 실패한다.
3. asset 사본의 sha256이 목록, 대응하는 리포 원본 파일, manifest의 입력 해시와 같다.
4. 허용 필드만 있다(v0.2의 규칙에 더해 `kisa_full` 메타데이터의 정해진 키, M4 JSON의 긴 문자열과 `/`로 시작하는 문자열 거부).
5. asset 사본만으로 리포 레이아웃을 복원해 README의 베이스라인 표를 다시 계산하면 README와 같다.
6. 같은 사본으로 실험 5개의 `metrics.json`·`comparison.json`을 다시 계산하면(abs 1e-9) 저장된 파일과 같고, README의 M3 판정 구간,
   `docs/experiments/summary.md`의 표 구간, 이 노트의 M3 구간이 그 값으로 만든 표와 같다.
7. 같은 사본의 두 보고서, manifest, 메타데이터가 서로 맞고(문서 수, 결과별 건수, 발견 계측, 메타데이터 ID), README와 이 노트의
   M4 구간이 그 값으로 만든 표와 같다.

NVD 코퍼스 파일(`fixtures/nvd/cves.jsonl`)은 asset이 아니다(v0.2 노트의 같은 절과 같다).

### 발행 뒤 검증 (내려받은 asset)

릴리스를 발행한 뒤 asset을 빈 디렉터리에 내려받아(`gh release download v0.3 --dir "$DL"`) 같은 검사를 그 파일들에 대해 돌린다.
리포 파일 사본이 아니라 실제로 올라간 파일이 대상이고, 목록에 없는 파일이 섞여 있으면 실패한다:

```bash
DL=$(mktemp -d)
gh release download v0.3 --repo Bkankim/krsec-rag-lab --dir "$DL"
uv run python scripts/check_release.py --note docs/release-v0.3.md --assets-dir "$DL"
```

## 본문 유출 점검 (LICENSES/README.md 체크리스트 적용)

[LICENSES/README.md](../LICENSES/README.md)의 "본문 유출 방지 점검 대상"을 이 릴리스에 적용한 결과다.

| 점검 대상 | 이 릴리스에서의 적용 | 결과 |
|---|---|---|
| 노트북 입력/출력 셀 | 노트북은 asset에 없고 이 릴리스에서 바뀌지 않았다 | 해당 없음 |
| 검색 결과 원시 JSON | v0.2와 같다. 결과 파일 전부 `scoring.validate_record`로 허용 필드만 허용한다 | `check_release.py` 통과 |
| 전체 코퍼스 메타데이터 | `fixtures/kisa_full/metadata.jsonl`은 URL·제목·날짜·nttId·CVE ID 다섯 키만 허용하고 각 문자열은 500자 이하다 | `check_release.py` 통과 |
| manifest·보고서 JSON | 건수, ID, sha256, reason code, 시각, 실행 환경 값만 있다. 500자를 넘는 문자열과 `/`로 시작하는 문자열(키 포함)이 없다. 본문 캐시 경로는 적지 않는다 | `check_release.py` 통과 |
| 색인 payload | Qdrant point의 payload에 본문·제목 텍스트를 넣지 않는다. 컬렉션 자체는 asset이 아니다 | 해당 없음 |
| 판정자 요청·응답 로그 | `eval/golden/judgments/*.jsonl`은 asset이 아니다. 정답 파일은 v0.1과 같은 키 목록 검사를 받는다 | `check_release.py` 통과 |
| 릴리스 첨부 파일 | asset 전부 허용 필드 검사 | `check_release.py` 통과 |
| README·블로그의 예시 인용 | README·노트의 표는 건수·ID·모델 정보뿐이고 공지 본문 인용이 없다 | 해당 없음 |
| `scripts/check_kisa_leaks.py` (total_matches=0) | 전체 코퍼스 본문 표본 검색은 `data/kisa_full/` 캐시가 있는 체크아웃에서 돌려야 한다. 이 노트를 쓴 작업에서는 실행하지 않았고 머지 전·후 점검 결과는 PR에 기록한다 | 이 문서에는 결과를 적지 않음 |

길이와 경로 검사는 본문 유출 검증의 일부 경로만 막는다. 본문 유출의 확인은 위 `check_kisa_leaks.py` 결과로 한다.

## 한계

이 릴리스의 수치는 아래 한계 안에서만 읽는다. v0.1·v0.2의 한계(정답은 사람 검수가 아니라 교차 판정, 표본 크기, M3 판정은 작은 표본의
한 번 측정)는 그대로 적용되고 [release-v0.1.md](release-v0.1.md), [release-v0.2.md](release-v0.2.md)의 한계 절에 있다.

**수집.**

- 목록 발견은 수집 시점의 스냅샷이다. 이후 올라온 글은 코퍼스에 들어오지 않고, 재실행은 목록 앞쪽만 훑어 새 글 ID만 센다. 오래된
  글의 삭제·수정과 본문 변경은 감지하지 못한다([m4-collection.md](m4-collection.md) 한계 절).
- 이미지뿐인 공지는 텍스트 본문이 없어 파싱 실패로 남고(M4 표의 파싱 실패 줄), 첨부 파일과 이미지 속 글은 수집하지 않는다.
- 내용 중복은 본문 sha256이 같은 묶음만 센다. 본문이 조금만 달라도 다른 해시이므로 근접 중복은 이 수치가 말해 주지 않는다.
- 본문 정규화와 CVE 추출은 고정 수집기와 같은 규칙이라 그 한계를 그대로 물려받는다.

**멱등성 검증.**

- 문서 하나를 한 point로 둔다. 모델의 `max_seq_length`(8192)를 넘는 본문은 모델이 잘라 쓰고 청킹하지 않는다.
- 검증의 갱신은 본문 끝에 표식 줄을 더한 합성 변경이다. 긴 문서에서는 표식이 잘려 벡터가 바뀌지 않을 수 있다.
- 벡터 비교 허용오차(1e-5)는 같은 장비·같은 스레드 수·batch_size 1에서의 값이다. 장비나 스레드 수가 다르면 부동소수점 합산 순서가 달라질 수 있다.
- 동시에 두 동기화를 같은 컬렉션에 돌리는 경우는 다루지 않는다(잠금 없음). 정기 실행 자동화, HNSW 튜닝, 검색 품질 평가는 범위 밖이다.

**재현 범위.**

- 저장본의 대조(`make_readme_tables.py --check`, `check_release.py`)는 모델·Docker·네트워크·KISA 캐시 없이 통과한다. 수집과 멱등성 검증은
  각 작업에서 한 번 측정한 값이고 이 릴리스 준비 작업에서는 다시 돌리지 않았다.
- 전체 코퍼스 유출 점검(`check_kisa_leaks.py`)은 본문 캐시가 있는 환경에서 돌려야 하고, 문서가 많아 시간이 오래 걸릴 수 있다.
- 모델은 Hugging Face의 공개 가중치이고 revision을 고정했지만, 가중치 자체의 재배포는 하지 않는다.

## 라이선스

코드·문서·자작 평가 데이터는 MIT다. NVD·CISA KEV 서브셋은 `fixtures/nvd/NOTICE.md`의 고지를 따르며(NVD 공식 데이터로
표기하지 않는다), KISA 보안공지 본문은 재배포 조건이 확인되지 않아 포함하지 않는다. 소스별 범위는 [LICENSES/README.md](../LICENSES/README.md).
