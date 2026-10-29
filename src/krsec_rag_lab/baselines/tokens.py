"""BM25 토큰화 규칙 `bm25-tok-v1` - 판정과 근거는 docs/baselines.md "토큰화 규칙" 절.

입력 문자열을 casefold한 뒤 아래 세 종류의 토큰을 등장 순서대로 뽑는다. 다른 문자(문장부호, 한자, 일본어
등)는 구분자로 버린다.

1. CVE ID는 하이픈을 유지한 토큰 하나(`cve-2026-70283`). 경계는 splits.py와 같은 ASCII look-around다:
   `\\b`는 한글 조사가 붙은 `CVE-2026-12345를`에서 끝 경계를 못 찾는다(eval-protocol 5절).
2. 영문·숫자 연속열(`[a-z0-9]+`)은 토큰 하나. `_`·`:`·`.`·`-`는 구분자라 `windows_admin_center`는
   세 토큰이다. 어간 추출과 불용어 제거는 하지 않는다.
3. 한글 음절 연속열(`[가-힣]+`)은 겹치는 문자 2-gram. 한 글자짜리 연속열은 그 글자 하나.

NFKC 정규화는 하지 않는다. 정규화하면 `CVE-2026-1234²`의 위첨자가 숫자로 바뀌어 ID에 붙는다(5절).
"""

import re

TOKENIZER_ID = "bm25-tok-v1"
TOKENIZER_RULES = (
    "casefold, NFKC 없음 / CVE-YYYY-NNNN+ 하이픈 유지 단일 토큰(ASCII look-around 경계) / "
    "[a-z0-9]+ 영숫자 토큰(구분자 _ : . -, 어간·불용어 처리 없음) / 한글 음절 연속열은 겹치는 "
    "문자 2-gram(한 글자 연속열은 1-gram) / 그 밖의 문자는 버림"
)

_TOKEN_RE = re.compile(
    r"(?P<cve>(?<![a-z0-9])cve-[0-9]{4}-[0-9]{4,}(?![0-9]))"
    r"|(?P<latin>[a-z0-9]+)"
    r"|(?P<hangul>[가-힣]+)"
)


def tokenize(text: str) -> list[str]:
    """`bm25-tok-v1` 규칙으로 토큰 목록을 만든다(중복 유지, 등장 순서)."""
    tokens: list[str] = []
    for match in _TOKEN_RE.finditer(text.casefold()):
        run = match.group("hangul")
        if run is None:
            tokens.append(match.group(0))
        elif len(run) == 1:
            tokens.append(run)
        else:
            tokens.extend(run[i : i + 2] for i in range(len(run) - 1))
    return tokens
