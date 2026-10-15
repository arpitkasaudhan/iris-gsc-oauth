"""Scrub OAuth secrets from every log line, whichever library wrote it.

The app itself never logs tokens, but dependencies can (an httpx debug line,
an exception that echoes a request body). Defence in depth: a filter on the
root handlers rewrites anything that looks like a Google token or an OAuth
form field before it reaches the log sink.
"""

import logging
import re

_REDACTED = "[REDACTED]"

_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"ya29\.[0-9A-Za-z_\-.]+"), _REDACTED),  # Google access token
    (re.compile(r"1//[0-9A-Za-z_\-]+"), _REDACTED),  # Google refresh token
    (re.compile(r"(?i)\b(bearer\s+)[^\s\"',]+"), r"\1" + _REDACTED),
    (
        re.compile(
            r"(?i)\b((?:access_token|refresh_token|id_token|client_secret|code_verifier|token)"
            r"[\"']?\s*[=:]\s*[\"']?)[^&\s\"',}]+"
        ),
        r"\1" + _REDACTED,
    ),
    # Authorization code in a callback query string (only "code=", so "status code: 401" survives)
    (re.compile(r"([?&]code=)[^&\s\"']+"), r"\1" + _REDACTED),
]


def redact(text: str) -> str:
    for pattern, repl in _PATTERNS:
        text = pattern.sub(repl, text)
    return text


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:  # malformed format args: leave the record alone
            return True
        cleaned = redact(message)
        if cleaned != message:
            record.msg, record.args = cleaned, None
        if record.exc_info and not record.exc_text:
            record.exc_text = redact(logging.Formatter().formatException(record.exc_info))
        elif record.exc_text:
            record.exc_text = redact(record.exc_text)
        return True


def install(*logger_names: str) -> None:
    """Attach the filter to the handlers of the root logger and of ``logger_names``."""
    flt = RedactingFilter()
    for name in ("", *logger_names):
        for handler in logging.getLogger(name).handlers:
            if not any(isinstance(f, RedactingFilter) for f in handler.filters):
                handler.addFilter(flt)
