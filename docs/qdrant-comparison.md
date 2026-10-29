# Qdrant 대조: NumPy 전수 vs exact vs HNSW

이슈 #6. 같은 벡터를 Qdrant에 적재해 (1) NumPy 전수 계산과 Qdrant exact 검색이 일치하는지 확인하고,
(2) HNSW 근사 검색이 exact와 얼마나 다른지(ANN recall, 지연)를 따로 관찰한다.
두 실험은 입력이 다르다. exact 대조는 `fixtures/embeddings_demo/`(실제 bge-m3 벡터, 10건)이고,
ANN 실험은 seed 고정 합성 벡터(50,000건)다. 이유는 [한계](#한계와-주의)에 있다.

## 결론

| 질문 | 결과 |
|---|---|
| exact top-k가 NumPy와 일치하는가 | 일치. 질의 11개 x k 4종 = 44건 전부 통과, 점수 최대 차이 1.6e-7 (허용 오차 1e-5) |
| HNSW는 exact와 같은가 | 아니다. ef=10에서 recall@10 약 0.1, ef=1024에서 약 0.98. ef를 키울수록 오르지만 1.0에 닿지 않았다 |
| 이 규모에서 HNSW가 빠른가 | 아니다. 50,000 x 128차원에서 exact(전수) 중앙값 1.6 ms, HNSW는 ef=1024에서 2.8 ms |
| 관련성 문제와 근사 손실 | 서로 다른 원인이다. 아래 [구분](#임베딩의-관련성-문제와-인덱스의-근사-손실) 참조 |

## 사전에 정한 규칙 (실행 전 고정)

규칙은 `scripts/qdrant_rules.py`에 코드로 있고, 단위 테스트(`tests/test_qdrant_rules.py`)가 경계 조건을 고정한다.
실험 스크립트를 처음 실행하기 전에 이 값들을 정했고, 결과를 보고 바꾸지 않았다.

- **점수 허용 오차**: `SCORE_TOLERANCE = 1e-5` (절대 차이). 1024차원 float32 내적의 반올림 오차는 1e-7 안팎이다.
  1e-5는 그 100배로, 반올림 오차는 흡수하되 순위가 실제로 바뀌는 차이는 숨기지 않는다.
  데모 질의의 인접 순위 점수 간격 최솟값은 1.87e-3이라 이 허용 오차 안에서 동점이 생기지 않는다.
- **동점**: 점수 차이가 허용 오차 이하이면 동점이다. 동점인 id는 어떤 순서로 나와도 되고,
  top-k 경계에서 동점이면 동점 후보 중 아무거나 들어와도 된다.
- **기준 순서(NumPy)**: 점수 내림차순, 같으면 `doc_id`(합성 fixture는 정수 id) 오름차순.
- **일치 판정** (`compare_topk`): 아래를 모두 만족하면 일치.
  1. 결과 개수 = k, id 중복 없음
  2. 순위별 점수 차이 <= 허용 오차 (양쪽 점수를 내림차순으로 정렬해 순위별 비교)
  3. 결과의 모든 id가 NumPy 점수 >= (k번째 NumPy 점수 - 허용 오차)
  4. NumPy 점수가 k번째 점수 + 허용 오차보다 큰 id는 결과에 모두 있음
  5. 결과 순서가 NumPy 점수 기준으로 (허용 오차 안에서) 내림차순
- **recall@k** (`recall_at_k`): 동점 인식. 결과 id의 NumPy 점수가 (k번째 NumPy 점수 - 허용 오차) 이상이면 적중.
  recall@k = 적중 수 / k. 질의별로 구한 뒤 평균(mean)과 최솟값(min)을 낸다.
- 거리: Cosine. fixture 벡터가 L2 정규화돼 있어 코사인 = 내적이다. NumPy 쪽은 `doc_vectors @ query_vector`(float32).

## 1. 서버 버전, 벡터 수, 인덱싱 증거

- 이미지: `qdrant/qdrant:v1.19.2` (`sha256:b7b0444c4c351c970b98e90a6f89c2ee4287c65b44e52b4cb503fa5b2aa927ad`)
- `GET /` 응답 원문: `{"title":"qdrant - vector search engine","version":"1.19.2","commit":"016542aa5deb6c66380bb137badf73d54f742bde"}`
- 클라이언트: `qdrant-client` 1.19.1, `numpy` 2.5.3, Python 3.13.14 (`uv.lock` 고정)
- 환경: Docker 29.6.1 (Ubuntu 24.04 aarch64 VM, 6 CPU) 위의 컨테이너, REST 호출

### 1-a. exact 대조용 컬렉션 `krsec6_demo` (10건, HNSW 없음)

`GET /collections/krsec6_demo` 응답에서 인덱싱과 payload 관련 필드 원문:

```json
{"status": "green", "optimizer_status": "ok", "indexed_vectors_count": 0, "points_count": 10, "segments_count": 3,
 "config": {"params": {"vectors": {"size": 1024, "distance": "Cosine"}},
            "hnsw_config": {"m": 16, "ef_construct": 100, "full_scan_threshold": 10000},
            "optimizer_config": {"indexing_threshold": 10000}},
 "payload_schema": {"cve": {"data_type": "keyword", "points": 10},
                    "product": {"data_type": "keyword", "points": 10},
                    "doc_id": {"data_type": "keyword", "points": 10}}}
```

`indexed_vectors_count: 0`이 핵심이다. 10건은 인덱싱 임계치(10000 KB)보다 훨씬 작아서 Qdrant가 HNSW를 만들지 않는다.
따라서 이 컬렉션의 검색은 어떤 파라미터로 불러도 전수 비교이고, 여기서는 "HNSW 근사 손실"을 관찰할 수 없다.
이 컬렉션은 exact 일치만 본다. (`exact=True`로 명시해서 호출한다.)

### 1-b. ANN 실험용 컬렉션 `krsec6_ann` (50,000건, HNSW 생성됨)

벡터 50,000 x 128차원 float32 = 25,600 KB로 임계치 10,000 KB를 넘는다.
`GET /collections/krsec6_ann` 응답 원문(`result` 부분, 들여쓰기만 정리):

```json
{
  "status": "green",
  "optimizer_status": "ok",
  "indexed_vectors_count": 50000,
  "points_count": 50000,
  "segments_count": 2,
  "config": {
    "params": {"vectors": {"size": 128, "distance": "Cosine"}, "shard_number": 1,
               "replication_factor": 1, "write_consistency_factor": 1, "on_disk_payload": true},
    "hnsw_config": {"m": 16, "ef_construct": 128, "full_scan_threshold": 10000,
                    "max_indexing_threads": 0, "on_disk": false},
    "optimizer_config": {"deleted_threshold": 0.2, "vacuum_min_vector_number": 1000,
                         "default_segment_number": 1, "max_segment_size": null, "memmap_threshold": null,
                         "indexing_threshold": 10000, "flush_interval_sec": 5,
                         "max_optimization_threads": null, "prevent_unoptimized": null},
    "wal_config": {"wal_capacity_mb": 32, "wal_segments_ahead": 0, "wal_retain_closed": 1},
    "quantization_config": null
  },
  "payload_schema": {},
  "update_queue": {"length": 0}
}
```

`indexed_vectors_count` 50000 = `points_count` 50000. 전부 HNSW 인덱스에 들어갔다는 증거다.
`segments_count: 2`의 내역(인덱싱된 세그먼트 1개와 비어 있는 쓰기용 세그먼트 1개로 추정)은 응답만으로는 확인하지 않았다.

**적재 순서가 결과를 좌우한다.** 옵티마이저를 켠 채 업로드하면, 임계치를 넘는 순간까지 쌓인 벡터만 인덱싱되고
나머지는 인덱싱되지 않은 세그먼트에 남는다. 개발 중 30,000건 컬렉션에서 `indexed_vectors_count` 20000 / `points_count` 30000을
실제로 관찰했다(그 부분은 전수 비교로 검색된다). 그래서 `scripts/qdrant_ann.py`는
`indexing_threshold=0`으로 컬렉션을 만들어 전부 적재한 뒤 임계치를 10000으로 올려 한 번에 인덱싱하고,
`indexed_vectors_count >= 벡터 수`가 될 때까지 기다린다. 못 채우면 raw 응답과 함께 실패한다.

## 2. exact vs NumPy 대조 (`fixtures/embeddings_demo`)

- 입력: `documents.json`의 문서 10건(합성 한국어 보안 공지 요약), `doc_embeddings.npy` (10, 1024), `query_embedding.npy` (1024,).
  파일은 바이트 불변이고, 스크립트가 `documents.json`의 sha256이 `manifest.json`과 같은지 확인한다
  (`244451c38d8502418af7faee11dfe5062a6ff76291e71d8a99b7592b38a4ff55`).
- 질의: fixture 질의 1개 + 문서 벡터 10개를 각각 질의로 쓴 자기 검색 10개 = 11개. k = 1, 3, 5, 10. 총 44건.
- Qdrant 호출: `query_points(..., search_params=SearchParams(exact=True))`.

결과:

| 항목 | 값 |
|---|---|
| 판정 통과 | 44 / 44 |
| NumPy 순서와 id 순서까지 완전 일치 | 44 / 44 |
| 점수 최대 차이 | 1.6e-7 (허용 오차 1e-5) |
| `baseline_scores.json`과 재계산 점수의 최대 차이 | 4.6e-9 |
| `baseline_scores.json` top-3 id와 재계산 top-3 | 일치 |
| fixture 질의의 exact top-1 | DOC-001 (`expected_doc_id`와 같음) |

fixture 질의, k=10의 순위별 비교 (NumPy는 float32 내적, Qdrant는 응답 점수):

| 순위 | doc_id | NumPy | Qdrant |
|---|---|---|---|
| 1 | DOC-001 | 0.78568411 | 0.78568417 |
| 2 | DOC-008 | 0.61337286 | 0.61337286 |
| 3 | DOC-004 | 0.60262907 | 0.602629 |
| 4 | DOC-003 | 0.54255545 | 0.54255545 |
| 5 | DOC-007 | 0.49467126 | 0.49467117 |
| 6 | DOC-005 | 0.49280003 | 0.49280006 |
| 7 | DOC-002 | 0.47313124 | 0.4731312 |
| 8 | DOC-009 | 0.46428049 | 0.4642805 |
| 9 | DOC-006 | 0.4577978 | 0.45779774 |
| 10 | DOC-010 | 0.44897318 | 0.44897324 |

이 데이터에서 동점 규칙은 발동하지 않았다(인접 순위 최소 간격 1.87e-3 > 1e-5). 규칙 자체의 동작은 단위 테스트가 검증한다.

payload 설계: 점 id는 `documents.json` 순서의 정수(0..9), payload는 `doc_id`, `cve`, `product`, `text`.
`doc_id`, `cve`, `product`는 필터 대상이라 keyword 인덱스를 만들고(위 `payload_schema`), 본문 `text`는 인덱스 없이 보관한다.
검색 결과를 `doc_id`로 읽으므로 점 id와 문서 id의 대응이 payload에 남는다.

## 3. HNSW: ef별 recall@10와 지연 (`krsec6_ann`)

- 벡터: `numpy.random.default_rng(20261029).standard_normal((50000, 128), float32)`를 행 단위 L2 정규화.
  질의 200개는 seed 20261030으로 따로 만든다. 파일은 커밋하지 않고 실행 때마다 같은 seed로 다시 만든다.
  `base_sha256` `6225d6f27836e54701f8376fb5329659d31f8aa72d17d00b988db7e0cf1fa99e`,
  `query_sha256` `5d75abf2610964101a1fb5e8dd3f76e8ef412ae739fdc4b61589a7b9ac6368fc` (`scripts/qdrant_synth.py`가 출력)
- 인덱스: m=16, ef_construct=128, Cosine, 양자화 없음.
- 기준(ground truth): 같은 벡터의 NumPy 전수 계산 top-10 (200개 질의 전부).
- 지연: 질의 1개씩 순차 호출한 클라이언트 측 왕복 시간(REST, 같은 호스트 컨테이너). 워밍업 20개 제외. 중앙값과 p95.
  NumPy 행은 프로세스 안에서 `base @ query` + 정렬 시간이라 HTTP 왕복이 없다.

| search | recall@10 mean | recall@10 min | queries with top-k != NumPy | median ms | p95 ms |
|---|---|---|---|---|---|
| hnsw ef=10 | 0.0925 | 0.00 | 200 | 0.947 | 1.1 |
| hnsw ef=16 | 0.1340 | 0.00 | 200 | 0.956 | 1.034 |
| hnsw ef=32 | 0.2255 | 0.00 | 200 | 1.132 | 1.289 |
| hnsw ef=64 | 0.3730 | 0.00 | 200 | 1.195 | 1.316 |
| hnsw ef=128 | 0.5415 | 0.20 | 199 | 1.307 | 1.446 |
| hnsw ef=256 | 0.7660 | 0.40 | 183 | 1.506 | 1.634 |
| hnsw ef=512 | 0.9120 | 0.60 | 115 | 1.88 | 2.141 |
| hnsw ef=1024 | 0.9800 | 0.80 | 38 | 2.759 | 3.251 |
| qdrant exact=True | 1.0000 | 1.00 | 0 | 1.575 | 1.965 |
| numpy full scan (in-process) | 1.0000 | 1.00 | 0 | 2.764 | 2.978 |

읽는 법:

- **exact=True는 200개 질의 모두 NumPy와 일치**한다(위 판정 규칙). 이 컬렉션에서도 exact 검색이 NumPy와 같으므로,
  HNSW 행의 recall 손실은 인덱스의 근사에서만 온다.
- ef를 키우면 recall이 단조롭게 오르고 지연도 오른다. recall@10 0.9를 넘으려면 ef=512가 필요했다.
- ef=1024에서도 38개 질의(19%)는 top-10이 NumPy와 다르다(recall@10 평균은 0.98이지만 min은 0.80).
  "평균 recall이 높다"와 "모든 질의가 정확하다"는 다르다.
- 이 규모(5만 x 128차원)에서 exact 전수 검색은 1.6 ms다. HNSW는 ef=256(1.5 ms)에서 비슷해지고 ef>=512에서는 exact가 더 빠르다.
  HNSW의 지연 이점은 벡터 수가 훨씬 많거나 차원이 높고 CPU 전수 비용이 클 때 나타난다. 여기서는 관찰되지 않았다.
- 인덱스는 멀티스레드로 만들어져 재빌드마다 그래프가 조금 다르다. 같은 명령을 한 번 더 돌린 두 번째 실행은
  ef=10 0.1065, ef=128 0.5535, ef=256 0.7525, ef=512 0.9120, ef=1024 0.9845였고,
  컨테이너를 새로 띄워 4절 명령을 그대로 돌린 세 번째 실행은
  ef=10 0.0975, ef=128 0.5490, ef=256 0.7610, ef=512 0.9280, ef=1024 0.9840이었다. 값이 ±0.02 안에서 움직이고
  경향(ef에 따라 단조 증가, 1024에서도 1.0 미만, exact는 1.0)은 같았다. 지연도 호스트 부하에 따라 달라진다.
  재현할 때 비교할 것은 정확한 숫자가 아니라 이 경향이다.

## 임베딩의 관련성 문제와 인덱스의 근사 손실

검색이 기대 문서를 못 찾는 이유는 두 가지이고, 처방이 다르다.

| | 임베딩의 관련성 문제 | 인덱스의 근사 손실 |
|---|---|---|
| 정의 | 벡터 공간에서 정답 문서가 질의와 가깝지 않다 (모델, 청킹, 질의 표현의 문제) | 벡터 공간에서는 top-k인 문서를 ANN 인덱스가 놓친다 |
| 기준 | 사람이 정한 정답 라벨 (`expected_doc_id`) | 같은 벡터의 exact 검색 결과 (라벨 불필요) |
| 지표 | hit@k, MRR 등 (정답 라벨 대비) | recall@k (exact top-k 대비) |
| exact 검색에서 | 정답이 top-k에 없다 | 정답이 top-k에 있다 (exact 결과가 곧 기준이므로) |
| 처방 | 모델, 청킹, 질의 재작성, 하이브리드 | ef 상향, m / ef_construct 상향, 필요하면 전수 검색 |
| 이 문서의 측정 | 2절: 정답 DOC-001이 exact 1위, 2위와 점수 차 0.172 | 3절: ef별 recall@10 |

진단 순서: 먼저 **exact 검색**으로 정답이 top-k에 들어오는지 본다.
들어오지 않으면 인덱스 파라미터를 아무리 조정해도 소용없는 관련성 문제다.
들어오는데 ANN 검색에서만 빠지면 근사 손실이다. 이 순서를 지키려면 exact 경로가 믿을 만해야 하고,
그것이 2절(NumPy와 완전 일치)이 확인한 내용이다. ANN의 recall을 임베딩 품질 지표로 읽거나
hit@k를 인덱스 품질 지표로 읽으면 원인을 잘못 짚는다.

## 한계와 주의

- 관련성 쪽 증거는 질의 1개, 문서 10건이다. 관련성 문제의 발생률은 추정할 수 없다. 이 문서는 구분 방법과 exact 경로의 신뢰성만 확립한다.
- ANN 쪽 벡터는 독립 가우시안 합성 벡터다. 의미 구조가 없어 HNSW에게 어려운 편이고,
  실제 임베딩(군집 구조가 있음)의 recall은 다를 수 있다. 이 문서는 실제 임베딩의 ANN recall을 측정하지 않았다.
  그래서 데모 fixture(실제 임베딩)로는 인덱스 근사를 볼 수 없고(1-a: 10건은 HNSW 미생성), 합성 벡터로는 관련성을 볼 수 없어 두 실험을 나눴다.
- 지연은 이 머신, 이 VM, REST 왕복 기준이다. 절대값이 아니라 같은 실행 안의 상대 비교로 읽는다.
- 범위 밖: bge-m3 새 임베딩, KISA·NVD 코퍼스 적재, sparse·하이브리드, 운영 배포 설정, 양자화.

## 4. 재현 명령

`uv sync --group qdrant` 뒤 실행할 명령 그대로다. 컨테이너는 이름 `krsec-qdrant-6`, 라벨 `krsec-run=1`, 호스트 포트 16333
(기본 6333/6334가 아님)으로 띄우고, 끝나면 그 컨테이너만 지운다. 볼륨은 만들지 않는다(컬렉션은 컨테이너와 함께 사라진다).

```bash
# 0. 포트 충돌 확인 (읽기만). 16333이 쓰이고 있으면 아래 네 곳(`docker run -p`, readyz 대기 루프, 버전 확인 `curl`, `KRSEC_QDRANT_URL`)의 포트를 모두 바꾼다.
docker ps -a --format '{{.Names}} {{.Ports}}'

# 1. 서버 기동 (버전 고정 태그) + 준비 대기
docker run -d --name krsec-qdrant-6 --label krsec-run=1 -p 16333:6333 qdrant/qdrant:v1.19.2
until curl -fsS http://127.0.0.1:16333/readyz >/dev/null 2>&1; do sleep 1; done
curl -fsS http://127.0.0.1:16333/

# 2. 의존성과 실험
uv sync --group qdrant
export KRSEC_QDRANT_URL=http://127.0.0.1:16333
uv run --no-sync python scripts/qdrant_exact.py     # 2절. JSON 보고서, 불일치가 있으면 exit 1
uv run --no-sync python scripts/qdrant_ann.py       # 3절. stdout JSON, stderr 표
uv run --no-sync python scripts/qdrant_synth.py     # 합성 벡터 fingerprint (서버 불필요)

# 3. opt-in 테스트 (KRSEC_QDRANT_URL이 없으면 skip)
uv run --no-sync pytest -q tests/test_qdrant_live.py

# 4. 정리: 이 작업이 만든 컨테이너만 지우고, 라벨 자원이 남지 않았는지 확인
docker rm -f krsec-qdrant-6
docker ps -a --filter label=krsec-run=1      # 빈 목록이어야 한다

# 5. CI와 같은 환경으로 되돌리기 (numpy, qdrant-client가 빠진다)
uv sync --locked --dev
uv run --no-sync pytest -q                    # 서버 필요 테스트와 numpy 테스트는 skip으로 표시
```

기대하는 결론(숫자 자체가 아니라): `qdrant_exact.py`가 `"cases_ok": 44, "cases_total": 44`와 exit 0,
`qdrant_ann.py`가 `indexed_vectors_count == points_count == 50000`과 `qdrant exact=True` 행 recall 1.0000,
HNSW 행 recall이 ef와 함께 단조 증가하고 ef=1024에서도 1.0 미만.

## 파일

| 파일 | 역할 |
|---|---|
| `scripts/qdrant_rules.py` | 허용 오차, 동점, 일치 판정, recall 규칙 (순수 Python) |
| `scripts/qdrant_common.py` | URL 해석, 컬렉션 재생성, 인덱싱 완료 대기, raw 응답 조회 |
| `scripts/qdrant_exact.py` | 2절 실험 |
| `scripts/qdrant_synth.py` | seed 고정 합성 벡터 |
| `scripts/qdrant_ann.py` | 3절 실험 |
| `tests/test_qdrant_rules.py` | 규칙과 import 위생 (CI에서 실행) |
| `tests/test_qdrant_synth.py` | 생성기 (numpy 없으면 skip) |
| `tests/test_qdrant_live.py` | 서버 필요 opt-in |

`numpy`와 `qdrant_client`는 스크립트 안에서 함수 호출 때 import한다. 모듈 최상단에는 없으므로
`uv sync --locked --dev`만 한 환경에서도 스크립트와 테스트를 import할 수 있다.
