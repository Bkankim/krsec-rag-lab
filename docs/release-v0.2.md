# v0.2 릴리스 노트 (M3: 실험 5개 + 재현 패키지)

Bkankim의 단독 프로젝트 [krsec-rag-lab](../README.md)의 두 번째 릴리스다. M3 실험 5개(하이브리드+RRF, 리랭커, 청킹, 한영 교차,
임베딩 교체)의 질문별 원시 결과, manifest(설정·모델 revision·test 잠금), 재계산한 지표와 판정, 한영 교차의 번역 파일을 v0.1의
베이스라인 asset에 더해 묶었다. 실험은 한 번에 한 요소만 바꿔 M2 베이스라인과 비교했고, 다섯 주 판정이 모두 `hypothesis-rejected`다.
README의 판정 표와 [experiments/summary.md](experiments/summary.md)의 표는 이 원시 결과에서 스크립트로 다시 계산한 값이다.
수치의 해석은 실험별 보고서에 있다.

## 무엇이 들어 있나

| 구분 | 내용 | 정본 |
|---|---|---|
| 평가 규약 | eval-protocol v2 (v0.1과 같다, 바꾸지 않았다) | [eval-protocol.md](eval-protocol.md) |
| 베이스라인 | v0.1의 asset 전부(질의셋, 정답, 기준선 원시 결과·manifest·metrics). 실험 판정을 다시 계산하려면 기준선 저장본이 필요해 함께 낸다 | [release-v0.1.md](release-v0.1.md), `results/baselines/` |
| 하네스 | 실험 모듈 인터페이스, CLI, 판정 규칙(test 잠금, 층화 paired bootstrap), `--compare` | [experiments/README.md](experiments/README.md) |
| 실험 5개 | hybrid, rerank, chunking, crossling, embedding. 가설·구성·재현 명령·결과·실패 사례·한계 | [experiments/hybrid.md](experiments/hybrid.md), [rerank](experiments/rerank.md), [chunking](experiments/chunking.md), [crossling](experiments/crossling.md), [embedding](experiments/embedding.md) |
| 원시 결과 | 질문 하나 = 한 줄: 질문 ID, `unjudged`를 지운 상위 100건의 문서 ID·순위·점수, 지우기 전 1위 점수, 지운 문서 수 | `results/experiments/<exp>/<트랙>/<변형>.jsonl` |
| 실험 manifest·지표·판정 | 설정, 입력 해시, 선택 근거, test 잠금(`config_hash`), 환경 / 저장본에서 다시 계산한 유형별 지표 / 기준 대비 delta·95% 구간·판정·악화·개선 질문 | `results/experiments/<exp>/{manifest,metrics,comparison}.json` |
| 번역 파일 | 한영 교차의 KO->EN 번역 결과(질문 ID, 모델, revision, 원문 sha256, 번역문). 재현 입력이라 test 설정 해시에 들어간다 | `results/experiments/crossling/translations.jsonl` |
| 요약 | 5개 실험의 가설, 판정, 보조 판정, `cve_explicit` 회귀를 한 표로, 다음 실험 후보(판정 없음) | [experiments/summary.md](experiments/summary.md) |

## M3 판정

주 판정 한 행씩이다. 보조 판정과 `cve_explicit` 회귀 여부는 [experiments/summary.md](experiments/summary.md)에 있다.

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

## 재현

`<KISA-ROOT>`는 KISA 캐시(`data/kisa`)가 있는 체크아웃이다(본문은 재배포하지 않는다, 수집·검사 절차는 [README](../README.md)의 "KISA 소표본").
측정은 `OMP_NUM_THREADS=4`로 했다.

### 새 클론에서 모델·KISA 캐시 없이 되는 것

`uv sync --locked --dev`만 하면 된다. 네트워크도 필요 없다.

```bash
git clone https://github.com/Bkankim/krsec-rag-lab.git && cd krsec-rag-lab
uv sync --locked --dev
# 실험 5개의 metrics.json·comparison.json을 저장된 원시 결과·질의셋 라벨·기준선 저장본에서 다시 계산해 대조(불일치 exit 1)
for exp in hybrid rerank chunking crossling embedding; do
  uv run python scripts/run_experiment.py --exp "$exp" --compare
done
uv run python scripts/make_readme_tables.py --check                    # 베이스라인 표 + M3 판정 표, summary, 이 노트의 판정 구간
uv run python scripts/check_release.py --note docs/release-v0.2.md     # 아래 asset 목록 검사
# 번역 모델 없이 한영 교차의 BM25 변형 검색을 다시 돌려 커밋된 저장본과 비교(커밋된 결과를 건드리지 않는 --out-dir)
OUT=$(mktemp -d)
uv run python scripts/run_experiment.py --exp crossling --track public --variant bm25_ko2en --out-dir "$OUT"
cmp "$OUT/crossling/public/bm25_ko2en.jsonl" results/experiments/crossling/public/bm25_ko2en.jsonl
```

`--compare`는 파일을 쓰지 않고 모델·KISA 캐시를 읽지 않는다. 숫자는 절대 허용오차 1e-9로, 판정·문자열·목록은 정확히 같아야
통과한다. 한영 교차 BM25 변형은 커밋된 번역 파일로 검색만 돌리므로 번역 모델이 필요 없다. v0.1의 exact·BM25 재현 명령은
[release-v0.1.md](release-v0.1.md)와 같다.

### 모델이 필요한 것 (`embed` 그룹, Hugging Face 가중치 revision 고정)

`uv sync --locked --group embed`로 torch, sentence-transformers를 설치하고 모델 가중치를 내려받는다. 아래는 공개 트랙 실행이고,
실험마다 `--out-dir <빈 디렉터리>`를 주면 커밋된 결과를 건드리지 않고 같은 저장본이 나오는지 확인할 수 있다. 이미 test 잠금이
있는 이 리포에 같은 설정으로 다시 쓰는 것은 허용되고, 설정·입력이 바뀌면 `LockError`다(새 가설로 등록해야 한다).

```bash
uv sync --locked --group embed
OMP_NUM_THREADS=4 uv run --no-sync python scripts/run_experiment.py --exp hybrid --track public --out-dir <빈 디렉터리>
OMP_NUM_THREADS=4 uv run --no-sync python scripts/run_experiment.py --exp rerank --track public --out-dir <빈 디렉터리>
OMP_NUM_THREADS=4 uv run --no-sync python scripts/run_experiment.py --exp crossling --track public --out-dir <빈 디렉터리>   # dense 변형까지(번역 모델은 불필요)
OMP_NUM_THREADS=4 uv run --no-sync python scripts/run_experiment.py --exp embedding --track public --out-dir <빈 디렉터리>
```

실험별 전체 명령(dev 선택, `--split test`, 최초 측정에 쓴 번역 생성 명령)은 각 보고서의 3절에 있다. 점수의 소수 자리는 환경(torch 등)에
따라 달라질 수 있고, 이 릴리스는 모델 실행을 다른 환경에서 다시 돌려 확인하지 않았다(아래 한계).

### KISA 캐시가 필요한 것

KISA 트랙(hybrid, rerank, chunking, embedding)은 본문 캐시와 위 모델이 모두 필요하다. 캐시가 없는 환경에서는 저장본의
`--compare`와 표 검증까지만 된다.

```bash
OMP_NUM_THREADS=4 uv run --no-sync python scripts/run_experiment.py --exp hybrid --track kisa --kisa-root <KISA-ROOT> --out-dir <빈 디렉터리>
```

`chunking`은 KISA 트랙만 있고, `embedding`의 KISA 트랙은 공개 트랙이 고른 모델을 읽으므로 공개 트랙을 먼저 끝낸다. 나머지 명령은
각 보고서의 3절을 따른다.

## 데이터와 모델

| 항목 | 값 |
|---|---|
| 평가 규약 | `eval-protocol-v2` ([eval-protocol.md](eval-protocol.md)) |
| 기준 dense 모델 | `BAAI/bge-m3` revision `5617a9f61b028005a4858fdac845db406aefb181` (hybrid, chunking, embedding의 기준·구성요소) |
| 리랭커 | `BAAI/bge-reranker-v2-m3` revision `953dc6f6f85a1b2dbfca4c34a2796e7dde08d41e` (rerank) |
| 번역 모델 | `Helsinki-NLP/opus-mt-ko-en` revision `e42d1f41b66194e6d10512f8a27bebc1f4f5097e` (crossling, 번역 결과는 `translations.jsonl`에 커밋) |
| 교체 임베딩 | `intfloat/multilingual-e5-large` revision `3d7cfbdacd47fdda877c5cd8a79fbcc4f2a574f3` (embedding) |
| 입력 해시 | `results/experiments/<exp>/manifest.json`의 `runs.<트랙>/<변형>.inputs`와 `reproduction_inputs`에 질의셋·코퍼스·재현 입력 sha256 |
| 판정 규칙 | test macro nDCG@10 delta > 0 이고 유형별 층화 paired bootstrap(10000회, 시드 `20261029`) 95% 구간 하한 > 0 이면 `hypothesis-confirmed`, 그 밖은 `hypothesis-rejected` |
| 실험 실행 | Apple M5 Pro(18코어), `OMP_NUM_THREADS=4`, CPU 추론 (`manifest.json`의 `environment`, 실험을 같은 맥에서 병렬로 돌려 시간은 참고값) |
| 그 밖 | KISA 고정 공지, NVD fixture, 교차 판정은 [release-v0.1.md](release-v0.1.md)의 같은 절과 같다 |

## asset

GitHub 릴리스 `v0.2`에 첨부하는 파일이다. v0.1의 asset 전부와 `results/experiments/`의 파일이다. asset 이름은 리포 경로의 `/`를 `__`로
바꾼 이름이고, 각 asset은 대응하는 리포 파일의 사본이다(sha256 동일). 모든 파일은 허용 필드만 갖는다: 결과 파일은 질문 ID·문서 ID·순위·점수
(와 지우기 전 1위 점수, 지운 문서 수)뿐이고, 번역 파일은 정해진 다섯 키뿐이며, 그 밖은 manifest·지표·판정(JSON)과 정답 파일이다.
KISA 공지 본문은 없다. 실험 JSON에는 리포 기준 상대 경로만 있다(절대 경로 모양의 문자열은 검사에서 거부한다).

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

<!-- END ASSETS -->

내려받은 asset은 `shasum -a 256 <파일>`로 위 표와 대조한다. 리포 쪽 검사는 `uv run python scripts/check_release.py --note docs/release-v0.2.md`다:

1. 목록의 항목이 허용 asset이고 파일이 있다. v0.2 허용 asset은 v0.1 목록에 `results/experiments/**`의 원시 결과·manifest·metrics·comparison과
   `translations.jsonl`을 더한 것이다.
2. `results/baselines/manifest.json`이 요구하는 원시 결과·질의셋과, 각 실험 manifest가 요구하는 저장 결과 경로·재현 입력·입력 파일,
   실험 JSON 3종(실험마다)이 모두 목록에 있다. 하나라도 없으면 실패한다.
3. asset 사본의 sha256이 목록, 대응하는 리포 원본 파일, manifest의 입력 해시와 같다.
4. 허용 필드만 있다(결과 파일은 `scoring.validate_record`, 번역 파일은 정해진 키, 질의·정답 파일은 키 목록, JSON은 긴 문자열 없음,
   실험 JSON은 절대 경로 모양의 문자열도 없음).
5. asset 사본만으로 리포 레이아웃을 복원해 README의 베이스라인 표를 다시 계산하면 README와 같다.
6. 같은 사본으로 실험 5개의 `metrics.json`·`comparison.json`을 하네스의 비교 함수로 다시 계산하면(abs 1e-9) 저장된 파일과 같고,
   README의 M3 판정 구간, `docs/experiments/summary.md`의 표 구간, 이 노트의 판정 구간이 그 값으로 만든 표와 같다.

NVD 코퍼스 파일(`fixtures/nvd/cves.jsonl`)은 asset이 아니다. 사본 재계산에서는 실험 manifest에 적힌 코퍼스 해시를 쓰고, 그 값이 기준선
manifest의 같은 해시와 같은지를 비교 전 검사가 확인한다. 리포에서는 파일의 실제 해시와 대조한다.

### 발행 뒤 검증 (내려받은 asset)

릴리스를 발행한 뒤 asset을 빈 디렉터리에 내려받아(`gh release download v0.2 --dir "$DL"`) 같은 검사를 그 파일들에 대해 돌린다.
리포 파일 사본이 아니라 실제로 올라간 파일이 대상이고, 목록에 없는 파일이 섞여 있으면 실패한다:

```bash
DL=$(mktemp -d)
gh release download v0.2 --repo Bkankim/krsec-rag-lab --dir "$DL"
uv run python scripts/check_release.py --note docs/release-v0.2.md --assets-dir "$DL"
```

## 본문 유출 점검 (LICENSES/README.md 체크리스트 적용)

[LICENSES/README.md](../LICENSES/README.md)의 "본문 유출 방지 점검 대상"을 이 릴리스에 적용한 결과다.

| 점검 대상 | 이 릴리스에서의 적용 | 결과 |
|---|---|---|
| 노트북 입력/출력 셀 | 노트북은 asset에 없고 이 릴리스에서 바뀌지 않았다 | 해당 없음 |
| 검색 결과 원시 JSON | 결과 파일(베이스라인과 실험) 전부 `scoring.validate_record`로 허용 필드(질문 ID·문서 ID·순위·점수, `top1_score_raw`, `n_unjudged_removed`)만 허용. 청크 순위 파일은 저장하지 않는다 | `check_release.py` 통과 |
| 생성 답변 로그·평가 로그 | 이 릴리스에는 생성 답변과 로그 asset이 없다 | 해당 없음 |
| 판정자 요청·응답 로그 | `eval/golden/judgments/*.jsonl`은 asset이 아니다. 정답 파일은 v0.1과 같은 키 목록 검사를 받는다 | `check_release.py` 통과 |
| 번역 파일 | `translations.jsonl`은 공개 트랙(NVD fixture, 합성 템플릿 질문)의 번역뿐이다. 정해진 다섯 키와 500자 이하 문자열만 허용. KISA 질문·본문의 번역은 없다 | `check_release.py` 통과 |
| 실험 manifest·지표·판정 JSON | 질문 ID·유형·순위·점수·설정 값만 있다. 긴 문자열과 절대 경로 모양의 문자열이 없다. KISA 캐시 경로(`--kisa-root`)와 모델 캐시 경로는 적지 않는다 | `check_release.py` 통과 |
| 릴리스 첨부 파일 | asset 전부 허용 필드 검사, JSON의 500자 초과 문자열 없음 | `check_release.py` 통과 |
| README·블로그의 예시 인용 | README·summary에 공지 본문 인용 없음(표는 지표 값, 질문 ID는 합성 데이터와 공개 메타데이터뿐) | 해당 없음 |
| `scripts/check_kisa_leaks.py` (total_matches=0) | 본문 표본 검색은 KISA 캐시가 있는 체크아웃에서 돌려야 한다. 이 노트를 쓴 작업에서는 실행하지 않았고 머지 전·후 점검 결과는 PR에 기록한다 | 이 문서에는 결과를 적지 않음 |

## 한계

이 릴리스의 수치는 아래 한계 안에서만 읽는다. v0.1의 한계(정답은 사람 검수가 아니라 교차 판정, `unjudged`·`excluded`, 표본 크기, 트랙별
한계)는 그대로 적용되고 [release-v0.1.md](release-v0.1.md)의 한계 절에 있다.

**판정은 작은 표본의 한 번 측정이다.**

- 주 트랙별 test 질문 수(정답이 있는 비제외 질문)는 판정 표의 `test n` 열이다. 질문 단위 층화 bootstrap은 같은 공지·CVE를 쓰는 질문의 의존을
  독립으로 다뤄 구간을 좁게 낼 수 있다. dev와 test 사이는 그룹 분할로 분리돼 있다.
- `hypothesis-rejected`는 이 설정이 이 표본에서 기준을 이긴다는 증거가 없다는 뜻이다. 효과가 없다는 증명이 아니다. 구간이 0을 걸친 실험과
  구간 전체가 0 아래인 실험은 표의 delta와 구간으로 구분해 읽는다.
- 설정은 dev에서만 골랐고 test는 확정 설정으로 한 번 돌았다. 결과를 본 뒤 설정·가설·판정 규칙을 바꾸지 않았다. 누적 조합(여러 요소를
  함께 바꾼 구성)은 판정하지 않았다.
- n_scored < 10인 유형(KISA 트랙의 여러 유형)은 관찰로만 읽는다.

**재현 범위.**

- 저장본에서의 재계산(`--compare`, 표 검증, asset 검사)은 모델·KISA 캐시 없이 통과한다. 모델이 필요한 실행(검색 결과 자체의 재생성)과
  KISA 트랙의 재실행은 이 릴리스 준비 작업에서 다시 돌리지 않았다. 점수는 환경(torch 등)에 따라 달라질 수 있다. 한영 교차의 BM25 변형만
  모델 없이 검색을 다시 돌려 저장본과 같음을 확인했다.
- 번역 파일은 번역 모델 실행 결과이고 런타임 버전이나 CPU가 다르면 달라질 수 있다. 번역 재생성은 커밋된 파일을 덮어쓰는 선택 단계이며
  test 잠금이 해시로 막는다(한영 교차 보고서 3절).
- 청킹의 청크 단위 지표와 색인 시간은 모델 실행 때의 관측값으로 manifest의 `description`에만 있고 `--compare`가 다시 계산하지 않는다.
- 색인 시간·질의 지연은 한 대의 맥(Apple M5 Pro, CPU 추론)에서 실험을 병렬로 돌려 잰 참고값이다.
- 임베딩 교체는 공개 트랙 dev로 로드되는 후보 2개를 비교해 고른 모델 하나만 test에서 판정했다. 다른 후보는 지금 lock의 `transformers`가 모델 유형을 인식하지 못해 제외했다(임베딩 보고서 2.1절).
- 실험 모델은 모두 Hugging Face의 공개 가중치이고 revision을 고정했지만, 가중치 자체의 재배포는 하지 않는다.
- 본문 유출 점검: 위 표의 `check_kisa_leaks.py`는 이 노트에서 실행 결과를 적지 않았다. 필드 허용 검사는 본문 유출의 일부 경로만 막는다.

## 라이선스

코드·문서·자작 평가 데이터는 MIT다. NVD·CISA KEV 서브셋은 `fixtures/nvd/NOTICE.md`의 고지를 따르며(NVD 공식 데이터로
표기하지 않는다), KISA 보안공지 본문은 재배포 조건이 확인되지 않아 포함하지 않는다. 소스별 범위는 [LICENSES/README.md](../LICENSES/README.md).
