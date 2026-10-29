# 지표 교차검증 (metrics-crosscheck)

`src/krsec_rag_lab/metrics.py`의 hit@k, recall@k, MRR, nDCG를 검증된 구현과 합성 순위·라벨로 대조한
기록이다. 정의의 정본은 `docs/eval-protocol.md`(eval-protocol-v1) 2~4절과 7절이고, 이 문서는 그 정의를
고치지 않는다. 규약과 검증 구현이 다르면 규약을 따르고 차이를 아래 "규약과 다른 동작"에 적는다.

## 명령

```
uv run --with ranx==0.3.21 python scripts/crosscheck_metrics.py
```

- 검증 패키지: [ranx](https://pypi.org/project/ranx/) **0.3.21** (PyPI 최신, 2025-08-07 배포).
  `uv run --with`로만 부른다. `pyproject.toml`·`uv.lock`은 바꾸지 않고, CI(`uv sync --locked --dev`)에도
  넣지 않는다. 스크립트는 pytest가 import하지 않으며 ranx는 `main()` 안에서만 import한다.
- 종료 코드: 일치하면 0, 불일치 있으면 1, ranx가 없으면 2(설치 명령을 stderr에 출력).
- 첫 실행은 ranx의 의존성(numba 등)을 받느라 오래 걸린다. 네트워크가 필요하다. 이 명령은 CI 테스트와
  별개이며 `uv run --no-sync pytest -q`는 네트워크 없이 통과한다.

## 입력과 허용 오차

- 합성 질의 309개: 규약 7.2의 B1~B8 입력 9건 + 시드 고정(`random.Random(20261029)`) 무작위 300건.
  문서 30종(`d01`~`d30`), 정답 1~6개, 순위 길이 {0, 1, 2, 3, 5, 8, 10, 12, 15}(빈 결과와 k보다 짧은 목록
  포함), 정답이 목록 밖에 있는 경우 포함. 점수는 순위에 대해 strictly decreasing이라 동점이 없다.
- k = 1, 5, 10. 지표 4종 x k 3개 = 12조합을 **질의 단위**로 대조하고(평균만 비교하면 질의 간 오차 상쇄가
  가려진다), 평균도 비교한다. MRR은 `mrr_at_k` 집계값을 ranx `mrr@10`과 따로 대조한다.
- **허용 오차: 절대값 1e-9** (실행 전에 정함). 두 구현 모두 float64 산술이라 차이는 1e-15 수준이어야 한다.
  규약 7절 표의 허용오차 1e-4는 표가 소수 4자리로 반올림되어 있어서이고, 구현 간 대조에는 쓰지 않는다.
- 지표 이름 대응: hit@k = `hit_rate@k`, recall@k = `recall@k`, RR@k = `mrr@k`(질의 단위 값), nDCG@k = `ndcg@k`.
  ranx의 `ndcg`는 gain = rel, 할인 = 1/log2(i+1)이다(`ndcg_burges`는 gain = 2^rel - 1). 이진 라벨에서는 둘이
  같은 값이다(아래 출력 마지막 INFO 줄).
- 스크립트가 불일치를 검출하는지 음성 대조도 했다: `ndcg_at_k`에 1e-6을 더한 채 같은 스크립트를 돌리면
  ndcg 3행이 `MISMATCH`, 종료 코드 1이 나온다.

## 결과 (원문)

실행: 2026-10-29, Python 3.13.14, macOS arm64. 아래는 위 명령의 stdout 전체다.

```
ranx==0.3.21  seed=20261029  queries=309  abs_tol=1e-09
metric        k     n     max|per-query diff|     |mean diff|  result
hit@1         1   309               0.000e+00       0.000e+00  OK
hit@5         5   309               0.000e+00       0.000e+00  OK
hit@10       10   309               0.000e+00       0.000e+00  OK
recall@1      1   309               0.000e+00       0.000e+00  OK
recall@5      5   309               0.000e+00       0.000e+00  OK
recall@10    10   309               0.000e+00       1.110e-16  OK
rr@1          1   309               0.000e+00       0.000e+00  OK
rr@5          5   309               0.000e+00       1.110e-16  OK
rr@10        10   309               0.000e+00       1.665e-16  OK
ndcg@1        1   309               0.000e+00       0.000e+00  OK
ndcg@5        5   309               0.000e+00       5.551e-17  OK
ndcg@10      10   309               1.665e-16       1.110e-16  OK
mrr_at_k (aggregate) @10: ours=0.205635177480 ranx=0.205635177480  OK

behavior differences (INFO, not part of PASS/FAIL):
  no-answer query: ours=None ranx raises ValueError: max() iterable argument is empty
  tie d2=d7, gold d2, mrr@2: ours=1.0 (sorted by doc_id), ranx insertion order d7,d2 -> 0.5, d2,d7 -> 1.0
  empty result: ours=0.0, ranx empty dict (mean with a perfect 2nd query) -> 0.5, query id missing from run raises AssertionError (make_comparable=True would fill 0)
  k=0: ours raises ValueError, ranx returns 1.0
  binary labels, ndcg vs ndcg_burges: 0.386852807235 vs 0.386852807235

PASS: 0 mismatching comparison(s)
```

판정: 12개 조합 전부 질의 단위 최대 차이 1.7e-16 이하, 평균 차이 1.7e-16 이하로 허용 오차 1e-9 안에서
일치한다. `mrr_at_k` 집계값도 일치한다.

## 규약과 다른 동작

ranx와 규약(eval-protocol-v1)의 동작이 다른 곳이다. 모두 **규약을 따른다**. 위 대조 범위(정답이 있고 동점이
없는 질의)는 이 차이에 걸리지 않는다. 이 표의 관측 값은 출력의 INFO 줄에서 온다.

| # | 입력 | 규약(자체 구현) | ranx 0.3.21 | 처리 |
|---|---|---|---|---|
| 1 | 답 없음(`G` 비어 있음) | 네 지표 모두 `None`, 평균에서 제외(7.3) | `ValueError: max() iterable argument is empty` | 대조에서 제외. 답 없음은 규약 표 N1·N2 테스트로 고정 |
| 2 | 동점(같은 점수) | 지표 함수는 점수를 받지 않는다. 하네스가 `(-score, doc_id)`로 정렬한 목록을 넘긴다(7.4). `sort_by_score`가 이 규칙이다 | 입력 dict의 삽입 순서에 의존(같은 입력이 `mrr@2` 0.5 또는 1.0) | 대조 입력에서 동점 제거. 규약 표 T1~T3 테스트로 고정 |
| 3 | 빈 검색 결과 | 정답이 있는 질의에서 0점으로 평균에 포함(7.2 B8) | 빈 dict면 0점. query id가 Run에서 빠지면 `AssertionError`(`make_comparable=True`로 0 채움) | 빈 dict로 입력. 규약 B8 테스트로 고정 |
| 4 | `k <= 0` | `ValueError`(7.1) | `ndcg@0`이 `1.0`을 돌려줌 | 규약을 따름 |
| 5 | `ranked`의 중복 ID | `ValueError`(7.1, 하네스가 먼저 접어야 함) | dict라 중복을 표현할 수 없음 | 규약을 따름. 중복은 테스트로 고정 |
| 6 | 질의 순서 | 입력 순서 | ranx는 query id 문자열 순으로 정렬 | 스크립트가 id를 0 채움(`q0000`)해 맞춤 |

위 1~6 중 1, 4는 ranx가 오류를 내거나 의미 없는 값을 돌려주는 경우이고, 2는 규약이 ranx에 없는 결정성
규칙을 추가한 경우다. 지표 수식 자체(hit/recall/RR/nDCG 정의, `IDCG`의 `min(|G|, k)`, recall 분모 `|G|`)는
규약과 ranx가 같다.

## 규약에 없어 구현에서 정한 것

- `ann_recall_at_k`에서 `Exact`가 비어 있으면(코퍼스가 비어 있음) 규약 7.5에 행이 없다. 0으로 세지 않고
  `None`(정의되지 않음)을 돌려준다. 코디네이터 확인 대상이다.
- `ann_recall_at_k`의 두 목록에도 중복 ID와 `k <= 0` 검사(7.1)를 같게 적용했다.
- `macro_mean`이 채점 질의가 있는 유형이 하나도 없으면 `None`을 돌려준다(5절은 분모가 채점 유형 수라고만 정함).
- 규약 7절 표에는 지표 4종 외에 `abstain`(7.3 A1~A3), 동점 정렬(T1~T3), `ann_recall@k`(R1~R4), 평균·macro(7.6)
  행이 있어, 표의 모든 행을 테스트하려고 `abstain`, `sort_by_score`, `ann_recall_at_k`, `mean_defined`,
  `macro_mean`, `mrr_at_k`를 `metrics.py`에 함께 두었다. 이 함수들은 ranx 대조 범위 밖이고 규약 표로만 검증한다.
