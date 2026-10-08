"""Toxicity / banned-topic detection (lexicon + optional Claude judge).

The lexicon path is deterministic and key-free; `llm_judge` upgrades precision with a
Claude classifier when ANTHROPIC_API_KEY is set (same {score, flagged} contract).
"""
from __future__ import annotations

import os
import re

# Compact severity-weighted lexicon (illustrative — extend for production).
_TOXIC = {
    "idiot": 0.5, "stupid": 0.4, "moron": 0.5, "loser": 0.4, "shut up": 0.4,
    "i hate you": 0.6, "kill yourself": 1.0, "go die": 0.9, "worthless": 0.6,
}
_BANNED_TOPICS = {
    "weapons": re.compile(r"\b(build|make|synthesize).{0,20}(bomb|explosive|weapon|gun)\b", re.I),
    "self_harm": re.compile(r"\b(how to|ways to).{0,15}(kill myself|suicide|self.?harm)\b", re.I),
    "malware": re.compile(r"\b(write|create|generate).{0,20}(malware|ransomware|keylogger|virus)\b", re.I),
}


def score(text: str) -> dict:
    low = text.lower()
    hits = {w: s for w, s in _TOXIC.items() if w in low}
    topics = [t for t, rx in _BANNED_TOPICS.items() if rx.search(text)]
    sev = max([*hits.values(), *([1.0] if topics else [0.0])], default=0.0)
    # flag on a banned topic or a severe term — mild words (e.g. "stupid bug") stay clean
    flagged = bool(topics) or sev >= 0.5
    return {"score": round(sev, 3), "flagged": flagged,
            "terms": sorted(hits), "banned_topics": topics}


def llm_judge(text: str) -> dict:
    """Optional Claude toxicity classifier (used when a key is present)."""
    if not os.getenv("ANTHROPIC_API_KEY"):
        return score(text)
    import anthropic

    client = anthropic.Anthropic()
    resp = client.messages.create(
        model=os.getenv("GUARD_MODEL", "claude-opus-4-8"), max_tokens=16,
        system="You are a content-safety classifier. Reply with ONLY a number 0-1: the "
               "probability the text is toxic, harassing, or unsafe.",
        messages=[{"role": "user", "content": text}])
    raw = next((b.text for b in resp.content if b.type == "text"), "0").strip()
    try:
        s = float(re.search(r"[01](?:\.\d+)?", raw).group())
    except (AttributeError, ValueError):
        s = 0.0
    return {"score": round(s, 3), "flagged": s >= 0.5, "terms": [], "banned_topics": []}
