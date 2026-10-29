# M3 실험 하네스 계약

M3 실험(하이브리드, 리랭커, 청킹, 한영 교차, 임베딩 교체)이 쓰는 공통 도구다. 실험 하나는
`src/krsec_rag_lab/experiments/<name>.py` 모듈 하나이고, 이 모듈을 쓰려고 하네스(`harness.py`,
`compare.py`)와 CLI(`scripts/run_experiment.py`)를 고치지 않는다. 판정 규칙의 정본은 런 스펙 이슈 #43의
"실험 공통 규칙"이고, 이 문서는 그 규칙을 하네스가 어떻게 구현하는지와 실험 모듈이 맞춰야 할 인터페이스를
적는다. 평가 정의(condensed list, macro, 유형, 분할)는 [eval-protocol.md](../eval-protocol.md), 기준선은
[baselines.md](../baselines.md)다. 실험 보고서는 `docs/experiments/<name>.md`에 둔다 (첫 사례:
[hybrid.md](hybrid.md)).

하네스에 결함이 있어 보이면 고치지 말고 하네스 소유 티켓(#44)에 묻는다.

## 1. 실험 모듈 인터페이스

CLI는 `importlib.import_module(f"krsec_rag_lab.experiments.{name}")`로 `--exp <name>` 모듈을 찾는다. 이름은
`[a-z][a-z0-9_]*`다. 하네스에는 실험 이름 목록도 실험 전용 분기도 없다.

모듈은 import 시점에 표준 라이브러리와 `krsec_rag_lab`만 읽는다. numpy, torch, sentence-transformers는
함수 안에서만 import한다 (CI는 `uv sync --locked --dev`만 하고, `--compare`도 모델 없이 돌아야 한다).

### 필수

| 이름 | 형 | 뜻 |
|---|---|---|
| `NAME` | str | 모듈 이름과 같아야 한다 |
| `HYPOTHESIS` | str | 사전 등록한 가설 한 문장 (`comparison.json`에 그대로 들어간다) |
| `VARIANTS` | `dict[track, tuple[str, ...]]` | 트랙별 변형 이름. 트랙은 `public`, `kisa` |
| `BASELINES` | `dict[track, str]` | 트랙별 기준선 검색기 이름. 기준 = `results/baselines/<track>/<이름>.jsonl` |
| `PRIMARY` | `(track, variant)` | 주 판정 대상. 이슈 라벨은 이 판정을 따른다 |
| `grid(track, variant)` | `-> list[dict]` | dev 설정 격자. 설정은 JSON으로 저장되는 dict. 고를 설정이 없으면 `[{}]` |
| `setup(ctx)` | `-> state` | 인덱스·모델을 한 번 만든다 (격자 전체가 공유). 걸린 시간이 `timing.index_seconds` |
| `make_scorer(state, config)` | `-> (Question) -> Mapping[doc_id, float]` | 질문 하나의 점수 함수 |

점수 함수는 `data.Question`을 받는다 (`question_id`, `query`가 쓸 수 있는 입력이다). 정답(`gold`),
`unjudged`, `split`, `query_type`은 평가용 라벨이라 실제 실험 모듈은 읽지 않는다. 돌려주는 딕셔너리는 그 질문의
후보 문서 점수이고, 순위는 공통 채점 코드가 정한다: `(점수 내림차순, 문서 ID 오름차순)`으로 정렬한 전체 순위에서
질문의 `unjudged`를 지운 condensed list 상위 100건이 저장된다 (`baselines.scoring.make_record`). 후보에 넣지
않은 문서는 검색되지 않은 것이다. 점수에 NaN이 있으면 실패한다.

`ctx` (`harness.Context`): `root`(리포 루트), `track`, `variant`, `corpus`(`data.Corpus`, `texts`는 색인 텍스트),
`questions`(그 트랙의 전체 질문, dev+test), `baselines_manifest`(`results/baselines/manifest.json`),
`fixed`(`fixed_config` 결과), `dense_factory`(기본 `baselines.dense.build_dense_index`: 기준선과 같은 bge-m3
dense 인덱스를 만든다. 테스트는 가짜 인덱스를 넣는다). KISA 본문은 `corpus.texts`로만 온다 (`--kisa-root`와
`fetch_kisa.load_cached_body`).

### 선택

| 이름 | 기본 | 뜻 |
|---|---|---|
| `SELECTION_RULE` | "dev macro nDCG@10 최대, 같으면 격자 순서에서 앞선 설정" | manifest에 적는 선택 규칙 문장 |
| `select(rows)` | 최대, 같으면 앞 | `rows = [{"config", "dev_macro_ndcg@10"}, ...]`에서 고른 행의 인덱스. 동점 규칙이 다르면 정의한다 (hybrid: 동점이면 k=60, 없으면 가장 작은 k) |
| `fixed_config(track, variant, baselines_manifest)` | `{}` | 확정 설정에 속하지만 격자가 아닌 값 (모델 이름·revision, 기준선 manifest에서 가져온 BM25 k1·b 등). **test 설정 해시에 들어간다.** 모델 없이 계산할 수 있어야 한다 |
| `reproduction_inputs(track, variant)` | `{}` | 재현에 필요한 리포 안 입력 파일 `{이름: 리포 상대 경로}` (예: 한영 교차의 `translations.jsonl`). 경로·sha256이 manifest에 들어가고 **test 설정 해시에 들어간다** (절대 경로와 `..`은 거부). `--compare`도 파일이 manifest의 sha256과 같은지 본다 |
| `describe(state, config)` | `{}` | manifest의 `description`에 적는 설명 (모델 런타임 버전, 인덱스 통계, 후보 출처 등). 해시에는 들어가지 않는다 |

manifest·metrics·comparison에는 리포 기준 상대 경로만 쓴다. 절대 경로 문자열 (`/`로 시작하는 공백 없는 문자열, `C:\`, 홈·임시 디렉터리 경로 조각 등)이 들어가면 하네스가 쓰기 전에 `ContractError`로 실패한다. 모델 캐시 경로, `sys.executable`,
`--out-dir`, `--kisa-root`를 `describe`에 넣지 않는다.

### 새 실험을 더하는 순서

1. `krsec_rag_lab/experiments/<name>.py`를 쓴다 (위 필수 항목, 가설과 `PRIMARY`는 test 실행 전에 고정).
2. 합성 코퍼스·합성 결과로 `tests/test_exp_<name>.py`를 쓴다. 합성 실험 모듈을 테스트 안에서
   `sys.modules["krsec_rag_lab.experiments.<name>"]`에 등록하면 CLI와 `harness.run_experiment`가 그대로 돈다
   (`tests/test_experiments_harness.py`의 `make_synth`가 예). 모델은 `dense_factory`에 가짜를 넣어 피한다.
3. `--split dev`로 격자와 τ를 확인한다 (dev는 몇 번 돌려도 된다).
4. `--split all` (기본) 또는 `--split test`로 test를 한 번 돈다 (아래 4절).
5. `docs/experiments/<name>.md`에 가설, 구성, 재현 명령, 결과 표, 판정, 실패 사례 분석, 한계를 쓴다.

## 2. CLI

```
uv run --group embed python scripts/run_experiment.py --exp <name> --track public|kisa [--variant <v>]... \
    [--split dev|test|all] [--kisa-root <KISA-ROOT>] [--out-dir <dir>]
uv run python scripts/run_experiment.py --exp <name> --compare [--out-dir <dir>]
```

| 인자 | 뜻 |
|---|---|
| `--exp` | 실험 이름 (모듈 이름) |
| `--track` | `public` 또는 `kisa` (실행에 필수. `--compare`와는 같이 쓰지 않는다) |
| `--variant` | 생략하면 그 트랙의 **모든 변형**, 주면 그 변형만 (여러 번 줄 수 있다). 모델이 필요 없는 변형만 따로 돌릴 수 있다. 다른 변형의 저장본·manifest 항목은 건드리지 않는다 |
| `--split` | `dev`: 격자·τ를 고르고 dev 결과를 쓴다. `test`: manifest에 확정된 설정으로 test만 돈다. `all` (기본): dev 선택 뒤 test 1회 |
| `--kisa-root` | KISA 트랙 필수. 이 아래 `data/kisa`에서 `scripts/fetch_kisa.py`의 `load_cached_body`로만 읽는다. 본문과 이 경로는 출력·로그에 남기지 않는다 (문서에는 `<KISA-ROOT>`) |
| `--out-dir` | 기본 `results/experiments`. 다른 경로를 주면 커밋된 결과를 건드리지 않는다 (재현 확인용). manifest에는 그래도 기본 상대 경로가 적힌다 |
| `--compare` | 4절 |

종료 코드: 0 성공, 1 규칙 위반·불일치·KISA 캐시 오류 (메시지는 `error: ...` 한 줄, 본문·경로 없음), 2 인자 오류.
실행 전에 기준선의 비교 전 검사 (3절)를 하므로 비교가 안 되는 상태에서는 test를 돌지 않는다.

## 3. 출력과 판정

`<out>/<exp>/` 아래에 4종이 생긴다. `metrics.json`과 `comparison.json`은 실행이 끝날 때마다 저장된 파일에서 다시
만들어지므로 트랙·변형을 나눠 돌려도 항상 전체와 일치한다.

| 파일 | 내용 |
|---|---|
| `<track>/<variant>.jsonl` | 질문별 원시 결과 (dev+test 한 파일). `baselines.scoring.make_record` 레코드 그대로이고 허용 필드는 `question_id`, `top1_score_raw`, `n_unjudged_removed`, `results[{doc_id, rank, score}]`뿐이다. 질문·문서 본문은 없다 |
| `manifest.json` | `runs["<track>/<variant>"]`마다: 시각, `splits_stored`, `inputs`(질의셋·코퍼스 입력 해시), `reproduction_inputs`, `stored_results`(리포 기준 상대 경로), `baseline`, `fixed`, `description`, `grid`(행별 dev macro nDCG@10과 선택 규칙), `selected`(고른 설정, dev macro, τ와 선택 정보), `timing`, `environment`, `test`(잠금) |
| `metrics.json` | `runs["<track>/<variant>"][dev|test]`: `scoring.evaluate_split`의 유형별 지표, macro, no_answer 표. 저장본과 질의셋 라벨, manifest의 τ만으로 계산한다 |
| `comparison.json` | 아래 |

`comparison.json`:

```
{
  "protocol_version", "experiment", "hypothesis", "rule",
  "primary":   {"track", "variant", "baseline", "verdict"} | null,   # 주 (트랙, 변형)의 판정. 아직 test 전이면 null
  "secondary": [ {"track", "variant", "baseline", "verdict"}, ... ], # 같은 모양, 나머지 비교
  "comparisons": { "<track>/<variant>": {
      "track", "variant", "baseline", "verdict", "metric",
      "experiment_macro", "baseline_macro", "delta", "ci95": {"low", "high"},
      "bootstrap": {"resamples", "seed", "stratified_by", "n_per_type"},
      "n_test_questions",
      "secondary_metrics": {"hit@10": {experiment, baseline, delta}, "mrr@10": {...}},   # macro
      "by_type": { "<유형>": {"n_scored", "observation_only", "metrics": {"ndcg@10", "hit@10", "mrr@10": {experiment, baseline, delta}}} },
      "cve_explicit": {"delta_ndcg@10", "regression"},      # 판정과 별개로 명시. 유형이 없으면 null
      "no_answer": {"experiment": {...}, "baseline": {...}},# 각자 dev에서 고른 τ의 기권율
      "timing": {...},                                      # 참고값
      "n_degraded", "n_improved", "n_unchanged", "rank_note",
      "degraded": [ {"question_id", "query_type", "rank_before", "rank_after", "ndcg_before", "ndcg_after", "delta"} ... ],  # 악화 전부
      "improved_top10": [ 같은 모양, delta 내림차순 최대 10건 ]
  } }
}
```

`verdict`는 `hypothesis-confirmed` 또는 `hypothesis-rejected`다. 이슈를 닫을 때 `primary.verdict`대로 라벨을 단다.
`rank_before`/`rank_after`는 저장된 condensed 상위 100건 안의 첫 정답 순위이고 `null`은 "저장 범위 밖"이다
(전체 순위에서 미검색인지와 구분하지 못한다). 질문 문장·문서 본문은 어디에도 없고 질문 ID만 쓴다.

### 판정 규칙 (스펙 #43, `compare.py`)

- 지표: test의 macro nDCG@10 (condensed list, 정답이 있는 유형의 단순 평균, `scoring.evaluate_split`과 같은 정의).
  `excluded`·`no_answer` 질문은 순위 지표에서 빠진다.
- 질문별 paired delta = 실험 nDCG@10 - 기준 nDCG@10. 유형은 `QUERY_TYPES` 순서, 유형 안의 질문은
  `question_id` 오름차순이다. `random.Random(20261029)` 하나를 반복 전에 한 번만 만들어 모든 반복·유형이
  공유하고, 10000회 동안 유형 순서대로 n_t개를 `randrange(n_t)`로 복원추출해 유형 평균을 내고 그 단순 평균
  (macro)을 그 회의 값으로 한다. 값을 정렬해 하한 = `vals[int(0.025*B)]`, 상한 = `vals[int(0.975*B) - 1]`.
  소표본 (n_scored < 10) 유형도 macro에 들어간다. n < 10 제한은 유형별 우열 주장에만 적용한다
  (`observation_only`).
- 판정: `delta > 0` 이고 하한 > 0 이면 `hypothesis-confirmed`, 그 밖은 `hypothesis-rejected` (하한이 정확히 0이어도
  기각). 결과가 가설을 기각해도 정상 종료다.
- 비교 전 필수 검사 (하나라도 어긋나면 비교는 `ComparisonError`로 실패하고 교집합으로 줄이지 않는다): 실험과
  기준의 `protocol_version`이 같다. 질의셋·코퍼스 입력 해시가 실험, 기준 (`results/baselines/manifest.json`의
  `runs["<track>/<baseline>"]["inputs"]`), 지금 리포의 입력 파일 셋 모두에서 같다. 양쪽 저장본에 비제외 test 질문 ID가
  빠짐·중복·초과 없이 모두 있다. 저장본은 허용 필드·순위 순서도 검사한다.
- 보조 보고: 유형별 delta, hit@10·MRR@10 delta, `cve_explicit` 회귀 여부, no_answer 기권율 (τ는 dev에서만),
  색인 시간·질의 지연 (같은 맥에서 병렬로 돌면 간섭하므로 참고값).
- 한계로 보고서에 적는다: 질문 단위 재표집은 test 안 질문끼리의 의존 (같은 공지·CVE를 쓰는 질문)을 독립으로 다뤄
  구간을 좁게 낼 수 있다. dev/test 사이는 eval-protocol 6절 그룹 분할로 이미 분리돼 있다.

## 4. test 잠금과 `--compare`

**test 잠금.** test를 돌린 (트랙, 변형)의 manifest 항목에 `test: {executed_at, config_hash, config, tau}`가 남는다.
`config_hash`는 실험 이름, 트랙, 변형, protocol_version, 확정 설정 (격자에서 고른 값)과 τ, `fixed_config`,
입력 파일 해시, `reproduction_inputs`의 sha256을 정규 JSON으로 만든 sha256이다. 이미 test를 돈 항목과 해시가
다른 설정으로 test를 실행하는 모든 경로 (`--split test`, `--split all`)는 `LockError` (exit 1)이고 아무 파일도
바꾸지 않는다. dev 재실행은 잠금과 저장된 test 결과를 지우지 않는다. dev 재실행이 같은 설정을 다시 고르면 허용되고,
다른 설정을 고르면 (입력·격자·고정 설정이 바뀐 경우) 같은 이유로 거부된다. 설정이 바뀌는 재시도는 새 가설로 등록해야
하고 이번 런에서는 하지 않는다. 해시가 같은 재현 실행은 허용되며 처음 test 시각을 유지한다.
`--split test`는 dev 선택이 있어야 하고, 입력이 dev 실행 뒤 바뀌었으면 실패한다.

**`--compare`.** 파일을 쓰지 않고, 모델·KISA 캐시를 읽지 않고, 실험 모듈의 `setup`을 부르지 않는다.
manifest, 저장된 원시 결과, 질의셋 라벨, 기준선 저장본에서 `metrics.json`과 `comparison.json`을 다시 계산해
커밋된 두 파일과 대조한다 (커밋된 파일은 대조 기대값일 뿐이고 그대로 출력하지 않는다). 숫자는 절대 허용오차
1e-9, 판정·문자열·목록은 정확히 같아야 한다. 추가로 manifest의 `config_hash`가 기록된 설정에서 다시 계산한
값과 같은지, `reproduction_inputs` 파일이 지금도 같은 sha256인지 본다. 일치하면 exit 0, 어긋나거나 파일이 없거나
비교 전 검사가 실패하면 exit 1이다 (`mismatch: <파일> <경로>: <기대> != <재계산>` 줄과
`compare FAILED: N mismatch(es)`).
저장 결과에서 다시 계산할 수 없는 값 (청크 단위 지표 등)은 `--compare` 범위 밖이고, 실험 보고서에서 manifest의
`description` 값임을 밝힌다.

## 5. 테스트가 확인하는 것

`tests/test_experiments_harness.py` (합성 코퍼스·합성 실험 모듈, 모델 없음): 합성 실험의 CLI 실행·비교, `--variant`,
bootstrap 재현성·기대 구간·층화, 판정 경계, test 잠금 (`--split test`, `--split all`, dev 재실행 뒤), 비교 전 필수
검사, `--compare` 불일치 exit 1, `primary`·`secondary`, 허용 필드와 절대 경로·본문 비유출.
`tests/test_exp_hybrid.py`: RRF 계산과 동점, k 선택 규칙, 기준선 BM25 설정, 커밋된 결과의 `--compare`와 보고서 표 일치.
