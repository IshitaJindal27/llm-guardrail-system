"""Secret / API-key detection — stop credentials leaking into prompts or out of completions."""
from __future__ import annotations

import re

_PATTERNS = {
    "aws_access_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "anthropic_key": re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b"),
    "openai_key": re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
    "github_token": re.compile(r"\bghp_[A-Za-z0-9]{36}\b"),
    "slack_token": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b"),
}


def detect(text: str) -> list[str]:
    return sorted({name for name, rx in _PATTERNS.items() if rx.search(text)})


def redact(text: str) -> str:
    out = text
    for name, rx in _PATTERNS.items():
        out = rx.sub(f"[{name.upper()}]", out)
    return out
