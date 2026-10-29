"""M3 실험 하네스 - 실험 하나 = `krsec_rag_lab.experiments.<name>` 모듈 하나.

하네스(`harness.py`)는 모듈을 이름으로 import해 쓰고, 비교·판정(`compare.py`)은 실험 모듈을 모른다.
새 실험을 더할 때 하네스·CLI 파일을 고치지 않는다. 모듈 인터페이스와 출력 계약의 정본은
docs/experiments/README.md다.

이 패키지는 CI(dev 그룹)에서 표준 라이브러리만으로 import돼야 한다. 모델 패키지(numpy, torch,
sentence-transformers)는 실험 모듈의 함수 안에서만 import한다.
"""


class ExperimentError(ValueError):
    """실험 실행·비교의 규칙 위반. CLI는 이 예외를 메시지 한 줄과 exit 1로 바꾼다."""


class ContractError(ExperimentError):
    """실험 모듈이 인터페이스 계약을 지키지 않았거나 요청 인자가 모듈과 맞지 않는다."""


class ComparisonError(ExperimentError):
    """비교 전 필수 검사 실패(입력 해시·protocol_version 불일치, test 질문 누락·중복)."""


class LockError(ExperimentError):
    """test 잠금 위반: 이미 test를 돈 설정과 다른 설정으로 test를 실행하려 했다."""
