"""로깅 인프라. 요청 범위 속성(request_id 등)을 contextvar 로 흘려보내고 로그 시점에 자동으로
부착한다(Go 의 slog ContextHandler 패턴에 대응).

sync 핸들러가 스레드풀에서 돌아도 Starlette/anyio 가 contextvars 를 복사해 실행하므로,
미들웨어에서 심은 request_id 가 핸들러/로깅까지 전파된다.
"""

from __future__ import annotations

import logging
import sys
from contextvars import ContextVar
from typing import Any

# 요청 범위 상관관계 속성. 미들웨어가 요청마다 설정한다. 기본값은 None 으로 두고(공유 가변
# 기본값 회피), 읽을 때 빈 dict 로 취급한다.
_ctx_attrs: ContextVar[dict[str, Any] | None] = ContextVar("log_ctx_attrs", default=None)


def _current_attrs() -> dict[str, Any]:
    """현재 컨텍스트의 상관관계 속성을 돌려준다(없으면 빈 dict)."""

    return _ctx_attrs.get() or {}


def append_ctx(**attrs: Any) -> None:
    """현재 컨텍스트에 로그 상관관계 속성을 더한다(기존 속성 유지). Go AppendCtx 에 대응한다.
    원본 dict 를 공유하지 않도록 매번 새 dict 를 설정한다.
    """

    merged = dict(_current_attrs())
    merged.update(attrs)
    _ctx_attrs.set(merged)


class _ContextFilter(logging.Filter):
    """로그 레코드에 contextvar 의 상관관계 속성을 부착한다. 레코드 속성으로 올려, 포매터가
    key=value 로 렌더링할 수 있게 한다.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        attrs = _current_attrs()
        for k, v in attrs.items():
            setattr(record, k, v)
        record.ctx_attrs = attrs
        return True


class _KeyValueFormatter(logging.Formatter):
    """레코드를 `time level msg key=value ...` 형태로 렌더링한다(Go slog TextHandler 톤)."""

    def format(self, record: logging.LogRecord) -> str:
        base = (
            f"time={self.formatTime(record)} level={record.levelname} msg={record.getMessage()!r}"
        )
        extra = getattr(record, "ctx_attrs", {})
        parts = [f"{k}={v!r}" for k, v in extra.items()]
        # 호출부가 logger.info(msg, extra={...}) 로 넘긴 추가 필드도 렌더링한다.
        for k, v in record.__dict__.items():
            if k in _RESERVED or k == "ctx_attrs" or k in extra:
                continue
            parts.append(f"{k}={v!r}")
        if parts:
            return base + " " + " ".join(parts)
        return base


# logging.LogRecord 의 표준 속성. 이 키들은 추가 필드로 렌더링하지 않는다.
_RESERVED = frozenset(logging.LogRecord("", 0, "", 0, "", (), None).__dict__.keys()) | {
    "message",
    "asctime",
    "taskName",
}


def new(name: str = "samplepython", level: int = logging.INFO) -> logging.Logger:
    """contextvar 상관관계 속성을 자동 부착하는 표준 로거를 만든다."""

    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.handlers.clear()
    logger.propagate = False

    handler = logging.StreamHandler(sys.stdout)
    handler.addFilter(_ContextFilter())
    handler.setFormatter(_KeyValueFormatter())
    logger.addHandler(handler)
    return logger
