"""Ollama HTTP API 호출 - 표준 라이브러리 `urllib`만 쓴다.

`OllamaLLM`은 `/api/chat`(`stream: false`, `format: "json"`)을 부르는 호출 가능 객체다. 파이프라인은 호출
가능한 객체 하나(`LLM` 규약)에만 기대므로 테스트는 같은 규약의 가짜 LLM을 쓴다. 응답 해석은 순수 함수
`parse_chat_response`로 분리해 HTTP 없이 시험한다. 서버 주소는 로컬 루프백이 기본이고 외부 API는 쓰지 않는다.

응답에서 읽는 값: `message.content`, `prompt_eval_count`(입력 토큰, 없으면 None), `eval_count`(출력 토큰),
지연 = (`total_duration` - `load_duration`) 나노초를 밀리초로 바꾼 값(모델 적재 시간 제외).
"""

import hashlib
import json
import re
import urllib.error
import urllib.request
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Protocol

DEFAULT_HOST = "http://127.0.0.1:11434"
DEFAULT_MODEL = "qwen3:8b"
DEFAULT_TIMEOUT_SECONDS = 900.0

# 컨텍스트 창과 출력 예약은 모델 한도(qwen3:8b = 40960) 안에서 k=5 + 문서당 상한 + 답을 담도록 정한다.
NUM_CTX = 16384
NUM_PREDICT = 512
SEED = 42
OPTIONS = {"temperature": 0, "seed": SEED, "num_ctx": NUM_CTX, "num_predict": NUM_PREDICT}

Messages = Sequence[Mapping[str, str]]


class LLMError(RuntimeError):
    """연결 실패·HTTP 오류·응답 형식 오류. 메시지에 요청 본문을 담지 않는다."""


@dataclass(frozen=True)
class LLMResponse:
    content: str
    prompt_eval_count: int | None
    eval_count: int | None
    latency_ms: float | None
    done_reason: str | None


class LLM(Protocol):
    """파이프라인이 기대하는 호출 규약. `max_prompt_tokens`가 있으면 입력 상한이다(num_ctx - 출력 예약)."""

    max_prompt_tokens: int | None

    def __call__(self, messages: Messages) -> LLMResponse: ...


def _count(payload: Mapping, key: str) -> int | None:
    value = payload.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def parse_chat_response(payload: Mapping) -> LLMResponse:
    """`/api/chat` 비스트리밍 응답 딕셔너리를 `LLMResponse`로 바꾼다. 형식이 다르면 LLMError."""
    message = payload.get("message")
    if not isinstance(message, Mapping) or not isinstance(message.get("content"), str):
        raise LLMError("response has no message.content string")
    total = _count(payload, "total_duration")
    load = _count(payload, "load_duration")
    latency_ms = None if total is None else max(total - (load or 0), 0) / 1_000_000
    done_reason = payload.get("done_reason")
    return LLMResponse(
        content=message["content"],
        prompt_eval_count=_count(payload, "prompt_eval_count"),
        eval_count=_count(payload, "eval_count"),
        latency_ms=latency_ms,
        done_reason=done_reason if isinstance(done_reason, str) else None,
    )


def _request_json(url: str, body: Mapping | None, timeout: float) -> dict:
    data = None if body is None else json.dumps(body, ensure_ascii=False).encode("utf-8")
    headers = {"Content-Type": "application/json"} if data is not None else {}
    request = urllib.request.Request(url, data=data, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read()
    except urllib.error.HTTPError as error:
        raise LLMError(f"http {error.code} from {url.rsplit('/', 1)[-1]}") from None
    except (urllib.error.URLError, OSError, TimeoutError) as error:
        raise LLMError(f"cannot reach ollama: {type(error).__name__}") from None
    try:
        parsed = json.loads(raw)
    except ValueError:
        raise LLMError("response is not JSON") from None
    if not isinstance(parsed, dict):
        raise LLMError("response is not a JSON object")
    return parsed


class OllamaLLM:
    """`/api/chat` 호출기. 옵션(온도 0, 고정 시드, num_ctx, num_predict)은 요청마다 같게 고정한다."""

    def __init__(
        self,
        model: str = DEFAULT_MODEL,
        host: str = DEFAULT_HOST,
        options: Mapping | None = None,
        think: bool = False,
        keep_alive: str | int | None = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ):
        self.model = model
        self.host = host.rstrip("/")
        self.options = dict(OPTIONS if options is None else options)
        self.think = think
        self.keep_alive = keep_alive
        self.timeout = timeout
        self.max_prompt_tokens: int | None = self.options["num_ctx"] - self.options["num_predict"]

    def request_body(self, messages: Messages) -> dict:
        body = {
            "model": self.model,
            "messages": [dict(message) for message in messages],
            "stream": False,
            "format": "json",
            "think": self.think,
            "options": dict(self.options),
        }
        if self.keep_alive is not None:
            body["keep_alive"] = self.keep_alive
        return body

    def __call__(self, messages: Messages) -> LLMResponse:
        payload = _request_json(f"{self.host}/api/chat", self.request_body(messages), self.timeout)
        return parse_chat_response(payload)


_LICENSE_NAMES = (
    ("Apache License", "Apache-2.0"),
    ("MIT License", "MIT"),
)


def model_info(model: str = DEFAULT_MODEL, host: str = DEFAULT_HOST, timeout: float = 60.0) -> dict:
    """`/api/show`·`/api/tags`·`/api/version`에서 모델 이름·digest·라이선스·컨텍스트 한도·서버 버전을 읽는다.

    digest = Ollama 모델 manifest digest(`ollama list`의 ID가 앞 12자), weights_sha256 = 가중치 blob의
    sha256(Modelfile `FROM` 경로의 파일명). 로컬 경로는 적지 않는다.
    """
    host = host.rstrip("/")
    show = _request_json(f"{host}/api/show", {"model": model}, timeout)
    tags = _request_json(f"{host}/api/tags", None, timeout)
    version = _request_json(f"{host}/api/version", None, timeout)
    digest = next(
        (item.get("digest") for item in tags.get("models", []) if item.get("name") == model), None
    )
    blob = re.search(
        r"^FROM\s+\S*sha256-([0-9a-f]{64})\s*$", show.get("modelfile", ""), re.MULTILINE
    )
    license_text = show.get("license", "")
    license_name = next((name for key, name in _LICENSE_NAMES if key in license_text[:400]), None)
    details = show.get("details", {})
    info = show.get("model_info", {})
    return {
        "name": model,
        "digest": digest,
        "weights_sha256": blob.group(1) if blob else None,
        "family": details.get("family"),
        "parameter_size": details.get("parameter_size"),
        "quantization": details.get("quantization_level"),
        "license": license_name,
        "license_text_sha256": hashlib.sha256(license_text.encode("utf-8")).hexdigest()
        if license_text
        else None,
        "context_length": next(
            (value for key, value in info.items() if key.endswith(".context_length")), None
        ),
        "capabilities": show.get("capabilities"),
        "ollama_version": version.get("version"),
    }
