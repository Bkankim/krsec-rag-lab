"""두 모델 교차 판정(이슈 #10) - 판정자 인터페이스, 인용 -> 오프셋, 일치 규칙, Cohen's kappa, 분할 배정.

판정자 A(`claude-opus-5-5`, `claude -p`)와 B(`gpt-6.1-sol`, `codex exec`)는 같은 지시문과 같은 입력(질문 1개 +
공지 묶음 1~8건)을 따로 받는다. 근거 인용은 메모리에서만 쓴다: 정규화 본문에서 정확히 찾아 `[start, end)`로
바꾼 뒤 버린다. 디스크(호출 캐시, 출력 파일)에는 오프셋과 고정 reason_code만 남고 본문·인용은 남지 않는다.

이 모듈은 모델을 직접 부르지 않는다: 실제 판정자(ClaudeJudge, CodexJudge)는 subprocess로 CLI를 부르고,
테스트는 FakeJudge를 쓴다. 표준 라이브러리만 쓴다.
"""

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
from collections import defaultdict
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from krsec_rag_lab.splits import extract_cve_ids, group_keys, near_dup_groups

JUDGE_NAMES = ("A", "B")
MAX_BUNDLE = 8
MAX_NOTICE_CHARS = 20_000
CVE_WINDOW_CHARS = 4_000
MIN_QUOTE_CHARS = 8
MAX_RETRIES = 1
QUESTION_MAX_CHARS = 80
COPY_WINDOW_CHARS = 15
COPY_SENTENCE_MIN_CHARS = 10
CALL_TIMEOUT_SECONDS = 1_200

RELEVANT = "relevant"
NOT_RELEVANT = "not_relevant"
STATUS_OK = "ok"
STATUS_NO_EVIDENCE = "no_evidence"
STATUS_INVALID = "invalid"

GOLD = "gold"
NONRELEVANT = "nonrelevant"
UNJUDGED = "unjudged"

# 판정 이유는 고정 코드만 쓴다(자유 서술 없음). 의미는 judge_manifest.json에 같은 표로 고정한다.
REASON_CODES = (
    (RELEVANT, "cve_discussed", "the notice itself discusses the exact CVE named in the question"),
    (
        RELEVANT,
        "product_matches",
        "the notice covers the product, version or symptom the question describes",
    ),
    (
        RELEVANT,
        "topic_answered",
        "the notice explains the concept, remedy or difference the question asks about",
    ),
    (NOT_RELEVANT, "cve_absent", "the question names a CVE and the notice does not discuss it"),
    (
        NOT_RELEVANT,
        "product_mismatch",
        "the notice is about a different product or vendor than the question",
    ),
    (NOT_RELEVANT, "topic_unanswered", "the notice does not contain what the question asks for"),
    (
        NOT_RELEVANT,
        "mention_only",
        "the notice touches the subject only in passing without answering",
    ),
)
REASON_CODE_NAMES = tuple(code for _label, code, _meaning in REASON_CODES)
CODE_RELEVANCE = {code: label for label, code, _meaning in REASON_CODES}

_CODE_LINES = "\n".join(f"  - {code}: {meaning}" for _label, code, meaning in REASON_CODES)

JUDGE_INSTRUCTION = f"""You are one of two independent judges deciding whether security notices answer a question.
The input is one JSON object on stdin: "question" (text) and "notices" (a list of objects with doc_id, title, date, partial, text).
You judge from the given text only. Do not use outside knowledge, tools or files.

For EVERY notice decide relevance:
- "relevant": the notice text itself contains information that answers the question. If the question names a CVE ID, the notice must discuss that exact CVE. If it describes a product, version or symptom, the notice must cover it. If it asks for an explanation or comparison, the notice must explain it.
- "not_relevant": anything else, including a passing mention, the same vendor with a different product or CVE, or a notice that does not answer.
If "partial" is true the text is only an excerpt of a longer notice; judge what you can see.

reason_code: choose exactly one of these fixed codes (a relevant notice takes a relevant code, a not_relevant notice a not_relevant code):
{_CODE_LINES}

quote: for a relevant notice copy ONE contiguous passage (a sentence or a line, 10 to 200 characters) from that notice's text EXACTLY as written, character for character, no ellipsis, no paraphrase. For a not_relevant notice use "".

If the input also has "retry" (a list of doc_ids), your earlier quote for those notices could not be found in the text. Answer again for all notices and copy the quote for those doc_ids verbatim from their text.

Answer with ONLY one JSON object and nothing else (no code fence):
{{"judgments": [{{"doc_id": "<doc_id>", "relevance": "relevant" | "not_relevant", "reason_code": "<code>", "quote": "<text>"}}]}}
with exactly one entry per notice, in the input order."""

QUESTION_INSTRUCTION = """You write one search question for a Korean security-notice retrieval test.
The input is one JSON object on stdin: "type" and "notice" (title, date, text).
Write ONE Korean question of at most 80 characters that the notice answers, in your own words.
- type "product_symptom": describe a product name, version or symptom and ask which notice applies.
- type "explanation_comparison": ask what, why or how about a concept or remedy in the notice, or how it differs from other notices.
Rules: no CVE ID; do not copy any phrase of 15 or more consecutive characters or any whole sentence from the notice text; no em dash; one line.
Answer with ONLY one JSON object and nothing else: {"question": "<text>"}"""

JUDGE_SYSTEM_PROMPT = "You are a careful relevance judge. Answer only with the requested JSON."

# codex exec --output-schema 용 JSON Schema(strict: 모든 속성 필수, 추가 속성 금지)
ANSWER_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["judgments"],
    "properties": {
        "judgments": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["doc_id", "relevance", "reason_code", "quote"],
                "properties": {
                    "doc_id": {"type": "string"},
                    "relevance": {"type": "string", "enum": [RELEVANT, NOT_RELEVANT]},
                    "reason_code": {"type": "string", "enum": list(REASON_CODE_NAMES)},
                    "quote": {"type": "string"},
                },
            },
        }
    },
}
QUESTION_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["question"],
    "properties": {"question": {"type": "string"}},
}


def text_sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def schema_sha256(schema: Mapping) -> str:
    return text_sha256(json.dumps(schema, sort_keys=True, separators=(",", ":")))


JUDGE_PROMPT_SHA256 = text_sha256(JUDGE_INSTRUCTION)
QUESTION_PROMPT_SHA256 = text_sha256(QUESTION_INSTRUCTION)


class JudgeError(RuntimeError):
    """판정자 호출이 실패했다(종료 코드, 시간 초과, 오류 응답). 메시지에 본문을 담지 않는다."""


class JudgeUnavailable(JudgeError):
    """사용량·한도 초과로 보이는 실패. 실행을 멈추고 코디네이터에게 알려야 한다."""


# ---------------------------------------------------------------- 공지 본문 준비


@dataclass(frozen=True)
class NoticeText:
    """판정자에게 보낼 공지. text는 정규화 본문의 [base, base+len(text)) 구간이다."""

    doc_id: str
    title: str
    date: str
    text: str
    base: int
    truncated: bool

    def payload(self) -> dict:
        return {
            "doc_id": self.doc_id,
            "title": self.title,
            "date": self.date,
            "partial": self.truncated,
            "text": self.text,
        }


def _cve_pattern(cve_id: str) -> re.Pattern[str]:
    # \b는 한글 조사가 붙은 끝 경계를 못 찾는다(splits.py와 같은 look-around를 쓴다)
    return re.compile(rf"(?<![A-Za-z0-9]){re.escape(cve_id)}(?![0-9])", re.IGNORECASE)


def prepare_notice(
    doc_id: str,
    title: str,
    date: str,
    body: str,
    cve_id: str | None = None,
    *,
    limit: int = MAX_NOTICE_CHARS,
    window: int = CVE_WINDOW_CHARS,
) -> NoticeText:
    """공지당 limit자 상한. 넘으면 cve_id가 처음 나오는 위치 앞뒤 window자, 없으면 앞에서 limit자를 보낸다."""
    if len(body) <= limit:
        return NoticeText(doc_id, title, date, body, 0, False)
    if cve_id:
        match = _cve_pattern(cve_id).search(body)
        if match:
            start = max(0, match.start() - window)
            end = min(len(body), match.end() + window)
            return NoticeText(doc_id, title, date, body[start:end], start, True)
    return NoticeText(doc_id, title, date, body[:limit], 0, True)


def locate_quote(notice: NoticeText, quote: str) -> tuple[int, int] | None:
    """인용을 보낸 본문에서 정확히 찾아 정규화 본문 기준 [start, end)로 돌려준다. 못 찾으면 None.

    정확히 일치하지 않으면 앞뒤 공백을 걷고, 그래도 안 되면 연속 공백 차이만 허용해 다시 찾는다.
    """
    needle = quote.strip()
    if len(needle) < MIN_QUOTE_CHARS:
        return None
    index = notice.text.find(needle)
    if index >= 0:
        return notice.base + index, notice.base + index + len(needle)
    tokens = needle.split()
    if len(tokens) > 1:
        pattern = re.compile(r"\s+".join(re.escape(token) for token in tokens))
        found = pattern.search(notice.text)
        if found:
            return notice.base + found.start(), notice.base + found.end()
    return None


# ---------------------------------------------------------------- 입력·응답


def build_payload(question: str, notices: Sequence[NoticeText], retry: Sequence[str] = ()) -> str:
    if not 1 <= len(notices) <= MAX_BUNDLE:
        raise ValueError(f"bundle must have 1..{MAX_BUNDLE} notices, got {len(notices)}")
    payload: dict = {"question": question, "notices": [n.payload() for n in notices]}
    if retry:
        payload["retry"] = list(retry)
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


def extract_json_object(text: str) -> dict | None:
    """응답 텍스트에서 JSON 객체 하나를 꺼낸다(코드 펜스·앞뒤 군말 허용). 못 꺼내면 None."""
    text = text.strip()
    for candidate in (text, text[text.find("{") : text.rfind("}") + 1]):
        if not candidate:
            continue
        try:
            value = json.loads(candidate)
        except ValueError:
            continue
        if isinstance(value, dict):
            return value
    return None


def interpret_answer(raw: str, notices: Sequence[NoticeText]) -> dict:
    """판정자 응답 -> {"valid": bool, "docs": {doc_id: {relevance, reason_code, evidence}}}.

    evidence는 relevant일 때 [[start, end], ...](인용을 찾은 경우), 못 찾았으면 None, not_relevant면 [].
    인용 텍스트는 여기서 버린다(반환값에 없다).
    """
    answer = extract_json_object(raw)
    entries = answer.get("judgments") if answer else None
    if not isinstance(entries, list):
        return {"valid": False, "docs": {}}
    by_id = {n.doc_id: n for n in notices}
    docs: dict[str, dict] = {}
    for entry in entries:
        if not isinstance(entry, Mapping):
            continue
        doc_id = str(entry.get("doc_id"))
        relevance, code = entry.get("relevance"), entry.get("reason_code")
        if (
            doc_id not in by_id
            or doc_id in docs
            or relevance not in (RELEVANT, NOT_RELEVANT)
            or code not in REASON_CODE_NAMES
            or CODE_RELEVANCE[code] != relevance  # relevant에 not_relevant 코드(또는 반대)는 무효
        ):
            continue
        evidence: list[list[int]] | None = []
        if relevance == RELEVANT:
            quote = entry.get("quote")
            span = locate_quote(by_id[doc_id], quote) if isinstance(quote, str) else None
            evidence = [list(span)] if span else None
        docs[doc_id] = {"relevance": relevance, "reason_code": code, "evidence": evidence}
    return {"valid": True, "docs": docs}


def _resolved(entry: Mapping | None) -> bool:
    return entry is not None and entry["evidence"] is not None


# ---------------------------------------------------------------- 판정자


class Judge:
    """판정자 하나. ask는 지시문과 stdin 입력을 받아 응답 텍스트를 돌려준다."""

    name: str
    model: str

    def ask(self, instruction: str, payload: str, schema: Mapping) -> str:
        raise NotImplementedError

    def describe(self) -> dict:
        raise NotImplementedError


_LIMIT_RE = re.compile(
    r"usage limit|rate.?limit|quota|limit reached|too many requests", re.IGNORECASE
)


_RETRY_HINT_RE = re.compile(r"try again at ([0-9:]+ ?[AP]M)")


def _failure(prefix: str, detail: str) -> JudgeError:
    """실패 예외. 응답·stderr 텍스트는 분류에만 쓰고 메시지에 넣지 않는다.

    모델 응답에는 공지 본문 인용이 들어 있을 수 있어서, 예외 문자열(stderr, 로그)에는 길이와 분류만 남긴다.
    사용량 한도면 메시지에서 재시도 시각 하나만 옮긴다.
    """
    text = " ".join(detail.split())
    if _LIMIT_RE.search(text):
        hint = _RETRY_HINT_RE.search(text)
        return JudgeUnavailable(
            f"{prefix}: usage limit" + (f", try again at {hint.group(1)}" if hint else "")
        )
    return JudgeError(f"{prefix}: error response omitted ({len(text)} chars)")


def _run_isolated(command: Sequence[str], payload: str, cwd_parent: Path | None = None):
    """빈 임시 디렉터리를 cwd로 하고 입력은 stdin으로만 준다."""
    workdir = tempfile.mkdtemp(prefix="judge-", dir=cwd_parent)
    try:
        return subprocess.run(
            list(command),
            input=payload,
            capture_output=True,
            text=True,
            encoding="utf-8",
            cwd=workdir,
            timeout=CALL_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise JudgeError("timeout") from None
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def _flag_text(args: Sequence[str]) -> list[str]:
    """argv 토큰을 '--flag value' 단위 문자열 목록으로 묶는다(manifest 표시용)."""
    flags: list[str] = []
    for token in args:
        if (
            flags
            and not token.startswith("-")
            and flags[-1].count(" ") == 0
            and flags[-1].startswith("-")
        ):
            flags[-1] += f" {token}"
        else:
            flags.append(token)
    return flags


def cli_version(binary: str) -> str:
    done = subprocess.run([binary, "--version"], capture_output=True, text=True, check=False)
    return done.stdout.strip() or "unknown"


class ClaudeJudge(Judge):
    """판정자 A. `claude -p`를 도구·MCP·사용자 설정·세션 저장 없이 부른다."""

    name = "A"
    model = "claude-opus-5-5"
    BINARY = "claude"
    ARGS = (
        "--model", "claude-opus-5-5",
        "--effort", "medium",
        "--output-format", "json",
        "--safe-mode",
        "--tools=",
        "--no-session-persistence",
        "--strict-mcp-config",
        "--disable-slash-commands",
        "--permission-mode", "dontAsk",
    )  # fmt: skip

    def command(self, instruction: str) -> list[str]:
        return [self.BINARY, "-p", instruction, *self.ARGS, "--system-prompt", JUDGE_SYSTEM_PROMPT]

    def ask(self, instruction: str, payload: str, schema: Mapping) -> str:
        done = _run_isolated(self.command(instruction), payload)
        try:
            result = json.loads(done.stdout)
        except ValueError:
            raise _failure(f"claude exit {done.returncode}", done.stderr or done.stdout) from None
        if (
            done.returncode != 0
            or result.get("is_error")
            or not isinstance(result.get("result"), str)
        ):
            raise _failure(f"claude exit {done.returncode}", str(result.get("result", "")))
        return result["result"]

    def describe(self) -> dict:
        return {
            "judge": self.name,
            "vendor": "Anthropic",
            "model": self.model,
            "cli": self.BINARY,
            "cli_version": cli_version(self.BINARY),
            "flags": [
                "-p <prompt>",
                *_flag_text(self.ARGS),
                "--system-prompt <fixed one-line judge prompt>",
            ],
        }


class CodexJudge(Judge):
    """판정자 B. `codex exec`를 읽기 전용 샌드박스·세션 저장 없이 부른다."""

    name = "B"
    model = "gpt-6.1-sol"
    BINARY = "codex"
    ARGS = (
        "exec", "--json",
        "-s", "read-only",
        "--skip-git-repo-check",
        "--ephemeral",
        "-m", "gpt-6.1-sol",
        "-c", 'model_reasoning_effort="medium"',
        "--ignore-user-config",
        "--ignore-rules",
        "--disable", "shell_tool",
        "--disable", "unified_exec",
        "--disable", "plugins",
        "--disable", "apps",
        "--disable", "hooks",
        "--disable", "multi_agent",
        "--disable", "browser_use",
        "--disable", "computer_use",
    )  # fmt: skip

    def command(self, instruction: str, schema_path: Path) -> list[str]:
        return [self.BINARY, *self.ARGS, "--output-schema", str(schema_path), instruction]

    def ask(self, instruction: str, payload: str, schema: Mapping) -> str:
        with tempfile.TemporaryDirectory(prefix="judge-schema-") as folder:
            schema_path = Path(folder) / "schema.json"
            schema_path.write_text(json.dumps(schema), encoding="utf-8")
            done = _run_isolated(self.command(instruction, schema_path), payload)
        answer: str | None = None
        errors: list[str] = []
        for line in done.stdout.splitlines():
            try:
                event = json.loads(line)
            except ValueError:
                continue
            if not isinstance(event, dict):
                continue
            item = event.get("item")
            if event.get("type") == "item.completed" and isinstance(item, dict):
                if item.get("type") == "agent_message" and isinstance(item.get("text"), str):
                    answer = item["text"]
            elif event.get("type") in ("error", "turn.failed"):
                errors.append(json.dumps(event, ensure_ascii=False))
        if answer is None or (done.returncode != 0 and errors):
            raise _failure(f"codex exit {done.returncode}", " ".join(errors) or done.stderr)
        return answer

    def describe(self) -> dict:
        return {
            "judge": self.name,
            "vendor": "OpenAI",
            "model": self.model,
            "cli": self.BINARY,
            "cli_version": cli_version(self.BINARY),
            "flags": [*_flag_text(self.ARGS), "--output-schema <fixed answer schema>", "<prompt>"],
        }


class FakeJudge(Judge):
    """테스트용 판정자. responder(instruction, payload) -> 응답 텍스트. 호출을 calls에 쌓는다."""

    def __init__(self, name: str, responder: Callable[[str, dict], str], model: str = "fake"):
        self.name = name
        self.model = model
        self.responder = responder
        self.calls: list[dict] = []
        self._lock = threading.Lock()

    def ask(self, instruction: str, payload: str, schema: Mapping) -> str:
        parsed = json.loads(payload)
        with self._lock:
            self.calls.append(parsed)
        return self.responder(instruction, parsed)

    def describe(self) -> dict:
        return {
            "judge": self.name,
            "model": self.model,
            "cli": "fake",
            "cli_version": "0",
            "flags": [],
        }


# ---------------------------------------------------------------- 호출 캐시(중단 뒤 재개)


class CallCache:
    """호출 결과 저장소. 키는 (판정자, 지시문, 입력) 해시이고 값은 해석된 결과뿐이다(본문·인용 없음).

    directory가 None이면 메모리에만 둔다. 항목마다 kind·task·judge·created_at을 같이 기록해서
    호출 수를 manifest에 적을 때 센다(실제로 모델을 부른 횟수 = 항목 수).
    """

    def __init__(self, directory: Path | None = None):
        self.directory = directory
        self._memory: dict[str, dict] = {}
        self.touched: set[str] = set()  # 이 실행이 읽거나 쓴 키(호출 수는 이 키만 센다)
        self._lock = threading.Lock()
        if directory is not None:
            directory.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def key(judge: Judge, instruction: str, payload: str) -> str:
        return text_sha256(
            json.dumps([judge.name, judge.model, text_sha256(instruction), text_sha256(payload)])
        )

    def get(self, key: str) -> dict | None:
        with self._lock:
            if key in self._memory:
                self.touched.add(key)
                return self._memory[key]
        if self.directory is not None:
            path = self.directory / f"{key}.json"
            if path.is_file():
                entry = json.loads(path.read_text(encoding="utf-8"))
                with self._lock:
                    self._memory[key] = entry
                    self.touched.add(key)
                return entry
        return None

    def put(self, key: str, entry: dict) -> None:
        with self._lock:
            self._memory[key] = entry
            self.touched.add(key)
        if self.directory is not None:
            path = self.directory / f"{key}.json"
            tmp = path.with_suffix(".tmp")
            tmp.write_text(json.dumps(entry, ensure_ascii=False, sort_keys=True), encoding="utf-8")
            os.replace(tmp, path)

    def entries(self, keys: Iterable[str] | None = None) -> list[dict]:
        """저장된 항목. keys를 주면 그 키의 항목만(디렉터리에 남은 이전 실행의 항목은 뺀다)."""
        wanted = None if keys is None else set(keys)
        if self.directory is None:
            found = {k: v for k, v in self._memory.items() if wanted is None or k in wanted}
        else:
            found = {
                path.stem: json.loads(path.read_text(encoding="utf-8"))
                for path in sorted(self.directory.glob("*.json"))
                if wanted is None or path.stem in wanted
            }
        return [found[k] for k in sorted(found)]


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def cached_call(
    cache: CallCache,
    judge: Judge,
    *,
    kind: str,
    task: str,
    instruction: str,
    payload: str,
    schema: Mapping,
    interpret: Callable[[str], dict],
) -> dict:
    """캐시에 있으면 그 결과, 없으면 판정자를 불러 해석한 결과를 저장한다."""
    key = cache.key(judge, instruction, payload)
    hit = cache.get(key)
    if hit is not None:
        return hit["result"]
    result = interpret(judge.ask(instruction, payload, schema))
    cache.put(
        key,
        {
            "kind": kind,
            "task": task,
            "judge": judge.name,
            "model": judge.model,
            "created_at": _now(),
            "result": result,
        },
    )
    return result


def count_calls(cache: CallCache, keys: Iterable[str] | None = None) -> dict:
    """캐시 항목에서 실제 호출 수를 센다: kind별(+판정자별, task별). 0회인 kind도 0으로 적는다.

    keys를 주면 그 키의 항목만 센다(같은 캐시 디렉터리에 남은 이전 실행의 항목은 이번 산출물의 호출이 아니다).
    """
    by_kind: dict[tuple[str, str], int] = defaultdict(int)
    for name in JUDGE_NAMES:
        by_kind[("judge", name)] = by_kind[("retry", name)] = 0
    by_kind[("question_generation", "A")] = 0
    by_task: dict[tuple[str, str], int] = defaultdict(int)
    times = []
    for entry in cache.entries(keys):
        by_kind[(entry["kind"], entry["judge"])] += 1
        by_task[(entry["task"], entry["judge"])] += 1
        times.append(entry["created_at"])
    return {
        "by_kind": [
            {"kind": kind, "judge": judge, "n": n} for (kind, judge), n in sorted(by_kind.items())
        ],
        "by_task": [
            {"task": task, "judge": judge, "n": n} for (task, judge), n in sorted(by_task.items())
        ],
        "total": sum(by_kind.values()),
        "first_at": min(times) if times else None,
        "last_at": max(times) if times else None,
    }


# ---------------------------------------------------------------- 묶음 판정


@dataclass(frozen=True)
class Judgment:
    """판정자 한 명의 (질문, 공지) 판정. evidence는 [start, end) 오프셋 목록이다."""

    question_id: str
    doc_id: str
    relevance: str | None
    reason_code: str | None
    evidence: tuple[tuple[int, int], ...]
    truncated: bool
    status: str

    def label(self) -> str | None:
        """유효한 이진 라벨(status ok)이면 relevance, 아니면 None."""
        return self.relevance if self.status == STATUS_OK else None

    def row(self) -> dict:
        return {
            "question_id": self.question_id,
            "doc_id": self.doc_id,
            "relevance": self.relevance,
            "reason_code": self.reason_code,
            "evidence": [{"start": s, "end": e} for s, e in self.evidence],
            "truncated": self.truncated,
            "status": self.status,
        }


def judge_bundle(
    judge: Judge,
    cache: CallCache,
    *,
    question_id: str,
    question: str,
    notices: Sequence[NoticeText],
    task: str,
) -> dict[str, Judgment]:
    """묶음 하나를 판정자 한 명에게 묻는다: 1회 + (인용을 못 찾은 공지가 있으면) 재질의 최대 1회."""

    def interpret(raw: str) -> dict:
        return interpret_answer(raw, notices)

    def call(kind: str, retry: Sequence[str]) -> dict:
        return cached_call(
            cache,
            judge,
            kind=kind,
            task=task,
            instruction=JUDGE_INSTRUCTION,
            payload=build_payload(question, notices, retry),
            schema=ANSWER_SCHEMA,
            interpret=interpret,
        )

    first = call("judge", ())
    pending = [n.doc_id for n in notices if not _resolved(first["docs"].get(n.doc_id))]
    second = call("retry", pending) if pending and MAX_RETRIES >= 1 else None

    judgments: dict[str, Judgment] = {}
    for notice in notices:
        entry = first["docs"].get(notice.doc_id)
        if not _resolved(entry) and second is not None:
            retried = second["docs"].get(notice.doc_id)
            entry = retried if retried is not None else entry
        if entry is None:
            status, relevance, code, evidence = STATUS_INVALID, None, None, ()
        elif entry["evidence"] is None:
            status, relevance, code, evidence = (
                STATUS_NO_EVIDENCE,
                entry["relevance"],
                entry["reason_code"],
                (),
            )
        else:
            status, relevance, code = STATUS_OK, entry["relevance"], entry["reason_code"]
            evidence = tuple((s, e) for s, e in entry["evidence"])
        judgments[notice.doc_id] = Judgment(
            question_id, notice.doc_id, relevance, code, evidence, notice.truncated, status
        )
    return judgments


# ---------------------------------------------------------------- 일치 규칙·kappa


@dataclass(frozen=True)
class Resolution:
    """(질문, 공지) 쌍의 교차 판정 결과. outcome은 gold / nonrelevant / unjudged."""

    question_id: str
    doc_id: str
    outcome: str
    why: str
    a: Judgment
    b: Judgment

    @property
    def valid(self) -> bool:
        """두 판정자 모두 유효한 이진 라벨을 냈는가(kappa와 '유효 응답' 기준)."""
        return self.a.label() is not None and self.b.label() is not None


def resolve_pair(a: Judgment, b: Judgment) -> Resolution:
    """일치 단위는 관련성 라벨이다.

    둘 다 relevant(근거 있음) -> gold. 둘 다 not_relevant -> 비관련, 단 잘린 공지의 not_relevant는 unjudged.
    갈림, no_evidence, 무효 응답 -> unjudged.
    """
    if (a.question_id, a.doc_id) != (b.question_id, b.doc_id):
        raise ValueError("judgments are for different pairs")
    if a.label() is None or b.label() is None:
        invalid = STATUS_INVALID in (a.status, b.status)
        why = STATUS_INVALID if invalid else STATUS_NO_EVIDENCE
        return Resolution(a.question_id, a.doc_id, UNJUDGED, why, a, b)
    if a.label() != b.label():
        return Resolution(a.question_id, a.doc_id, UNJUDGED, "disagree", a, b)
    if a.label() == RELEVANT:
        return Resolution(a.question_id, a.doc_id, GOLD, "agree_relevant", a, b)
    if a.truncated or b.truncated:
        return Resolution(a.question_id, a.doc_id, UNJUDGED, "truncated_not_relevant", a, b)
    return Resolution(a.question_id, a.doc_id, NONRELEVANT, "agree_not_relevant", a, b)


def cohen_kappa(pairs: Iterable[tuple[str, str]]) -> dict:
    """유효한 A·B 이진 라벨 쌍 전체의 Cohen's kappa. 정의되지 않으면 value None과 사유를 담는다."""
    pairs = list(pairs)
    n = len(pairs)
    if n == 0:
        return {
            "n": 0,
            "value": None,
            "observed_agreement": None,
            "expected_agreement": None,
            "null_reason": "no valid label pairs",
        }
    agree = sum(1 for x, y in pairs if x == y)
    a_rel = sum(1 for x, _ in pairs if x == RELEVANT) / n
    b_rel = sum(1 for _, y in pairs if y == RELEVANT) / n
    observed = agree / n
    expected = a_rel * b_rel + (1 - a_rel) * (1 - b_rel)
    if expected == 1:
        return {
            "n": n,
            "value": None,
            "observed_agreement": observed,
            "expected_agreement": expected,
            "null_reason": "both judges used a single label, kappa is undefined",
        }
    return {
        "n": n,
        "value": round((observed - expected) / (1 - expected), 6),
        "observed_agreement": round(observed, 6),
        "expected_agreement": round(expected, 6),
        "null_reason": None,
    }


def summarize(resolutions: Sequence[Resolution]) -> dict:
    """쌍 집계: 시도·유효 응답·일치·불일치·gold·비관련·unjudged(사유별)와 kappa."""
    valid = [r for r in resolutions if r.valid]
    reasons: dict[str, int] = defaultdict(int)
    for r in resolutions:
        if r.outcome == UNJUDGED:
            reasons[r.why] += 1
    return {
        "n_pairs": len(resolutions),
        "n_valid_pairs": len(valid),
        "n_agree": sum(1 for r in valid if r.a.label() == r.b.label()),
        "n_disagree": sum(1 for r in valid if r.a.label() != r.b.label()),
        "n_gold": sum(1 for r in resolutions if r.outcome == GOLD),
        "n_not_relevant": sum(1 for r in resolutions if r.outcome == NONRELEVANT),
        "n_unjudged": sum(1 for r in resolutions if r.outcome == UNJUDGED),
        "unjudged_reasons": [{"reason": k, "n": v} for k, v in sorted(reasons.items())],
        "kappa": cohen_kappa((r.a.label(), r.b.label()) for r in valid),
    }


def error_rate(
    resolutions: Sequence[Resolution], in_candidate: Mapping[tuple[str, str], bool]
) -> dict:
    """오라벨률(후보 안 쌍 중 일치 not_relevant)과 누락률(후보 밖 쌍 중 일치 relevant).

    분모는 unjudged를 뺀 일치 쌍(gold + 비관련)이다.
    """
    result = {}
    for name, inside in (("mislabel", True), ("omission", False)):
        scoped = [
            r
            for r in resolutions
            if in_candidate[(r.question_id, r.doc_id)] == inside and r.outcome != UNJUDGED
        ]
        errors = sum(1 for r in scoped if r.outcome == (NONRELEVANT if inside else GOLD))
        result[name] = {
            "scope": "in_candidate_set" if inside else "outside_candidate_set",
            "denominator": len(scoped),
            "n_error": errors,
            "rate": round(errors / len(scoped), 6) if scoped else None,
        }
    return result


# ---------------------------------------------------------------- 질문 복사 검사


def _squash(text: str) -> str:
    return "".join(text.split())


def copies_body(query: str, body: str, *, window: int = COPY_WINDOW_CHARS) -> bool:
    """질문이 본문을 베꼈는가: 15자 이상 연속으로 겹치거나 본문 문장 하나를 통째로 담으면 True.

    공백 차이는 무시한다: 공백을 모두 걷은 글자 기준과 공백을 한 칸으로 접은 글자 기준 둘 다 본다
    (걷은 기준만 보면 공백이 든 16자 겹침이 13자로 줄어 놓친다).
    """
    squashed_query, squashed_body = _squash(query), _squash(body)
    folded_query, folded_body = " ".join(query.split()), " ".join(body.split())
    for left, right in ((squashed_query, squashed_body), (folded_query, folded_body)):
        for start in range(len(left) - window + 1):
            if left[start : start + window] in right:
                return True
    for sentence in re.split(r"[.!?\n]+", body):
        sentence = _squash(sentence)
        if len(sentence) >= COPY_SENTENCE_MIN_CHARS and sentence in squashed_query:
            return True
    return False


def clean_question(raw: str) -> str | None:
    """생성 응답 -> 질문 문장(em dash는 하이픈으로). 형식이 틀리면 None."""
    answer = extract_json_object(raw)
    query = answer.get("question") if answer else None
    if not isinstance(query, str):
        return None
    query = " ".join(query.replace("\u2014", "-").split())
    return query or None


def check_question(query: str, body: str) -> str | None:
    """질문이 통과하지 못하는 사유(없으면 None)."""
    if len(query) > QUESTION_MAX_CHARS:
        return "too_long"
    if not re.search(r"[가-힣]", query):
        return "not_korean"
    if extract_cve_ids(query):
        return "has_cve_id"
    if copies_body(query, body):
        return "copies_body"
    return None


# ---------------------------------------------------------------- dev/test 분할


def assign_splits(
    records: Sequence[Mapping],
    notices: Sequence[Mapping],
    *,
    seed: int,
    dev_share: float = 0.4,
) -> dict[str, str]:
    """question_id -> "dev"|"test". docs/eval-protocol.md 6절: 그룹을 공유하는 질의는 한 블록이다.

    블록(union-find)을 큰 순서로 세우고, 질의 유형별 dev 비율이 dev_share에 가장 가까워지는 쪽에
    배정한다(동률은 seed 해시로 가른다). excluded 레코드는 비율에 세지 않지만 블록에는 들어간다.
    """
    notices = list(notices)
    by_id = {str(n["nttId"]): n for n in notices}
    groups = near_dup_groups(notices)
    parent: dict[str, str] = {}

    def find(x: str) -> str:
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    owner: dict[tuple[str, str], str] = {}
    for record in records:
        qid = record["question_id"]
        find(qid)
        item = {
            "id": qid,
            "ntt_ids": [a["doc_id"] for a in record["answers"]],
            "cve_ids": record.get("cve_ids", []),
            "query": record["query"],
        }
        for kind, keys in group_keys(item, by_id, groups).items():
            for key in keys:
                first = owner.setdefault((kind, key), qid)
                parent[find(qid)] = find(first)

    blocks: dict[str, list[Mapping]] = defaultdict(list)
    for record in records:
        blocks[find(record["question_id"])].append(record)

    def scored(record: Mapping) -> bool:
        return not record.get("excluded")

    totals: dict[str, int] = defaultdict(int)
    for record in records:
        if scored(record):
            totals[record["query_type"]] += 1

    def rank(block: Sequence[Mapping]) -> str:
        return text_sha256(f"{seed}:{min(r['question_id'] for r in block)}")

    ordered = sorted(blocks.values(), key=lambda b: (-sum(1 for r in b if scored(r)), rank(b)))
    dev_count: dict[str, int] = defaultdict(int)
    assignment: dict[str, str] = {}
    for block in ordered:
        counts: dict[str, int] = defaultdict(int)
        for record in block:
            if scored(record):
                counts[record["query_type"]] += 1

        def cost(extra: Mapping[str, int]) -> float:
            return sum(
                (dev_count[t] + extra.get(t, 0) - dev_share * total) ** 2
                for t, total in totals.items()
            )

        to_dev, to_test = cost(counts), cost({})
        if to_dev != to_test:
            side = "dev" if to_dev < to_test else "test"
        else:
            side = "dev" if int(rank(block)[:8], 16) % 2 == 0 else "test"
        if side == "dev":
            for t, n in counts.items():
                dev_count[t] += n
        for record in block:
            assignment[record["question_id"]] = side
    return assignment


# ---------------------------------------------------------------- 무답 CVE 후보


def absent_cve_candidates(seed: int, excluded: set[str]) -> Iterable[str]:
    """seed 고정으로 무한히 CVE 형식 ID를 만든다. excluded(코퍼스·NVD fixture에 있는 ID)는 건너뛴다."""
    seen: set[str] = set()
    k = 0
    while True:
        digest = int(text_sha256(f"{seed}:no-answer:{k}"), 16)
        k += 1
        cve_id = f"CVE-{2021 + digest % 6}-{10_000 + (digest >> 8) % 80_000}"
        if cve_id in excluded or cve_id in seen:
            continue
        seen.add(cve_id)
        yield cve_id


@dataclass
class CallBudget:
    """상한이 있는 호출 횟수 세기(질문 생성, no_answer 시도)."""

    cap: int
    used: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def take(self) -> bool:
        with self._lock:
            if self.used >= self.cap:
                return False
            self.used += 1
            return True
