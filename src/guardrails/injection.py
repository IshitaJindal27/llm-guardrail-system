"""Prompt-injection / jailbreak detection (heuristic signatures + scoring).

Catches the common attack families — instruction override, role/system manipulation,
exfiltration of the system prompt, and known jailbreak personas (DAN etc.). Returns a
score in [0,1] and the matched signals so decisions are explainable.
"""
from __future__ import annotations

import re

# (weight, compiled pattern, label)
_SIGNATURES = [
    (0.7, re.compile(r"ignore (all|any|the|your)?\s*(previous|prior|above|earlier)\s+(instructions|prompts?|rules)", re.I), "instruction_override"),
    (0.7, re.compile(r"disregard (all|the|your)?\s*(previous|prior|above)?\s*(instructions|rules|guidelines)", re.I), "instruction_override"),
    (0.6, re.compile(r"forget (everything|all|what).{0,20}(said|told|instructed)", re.I), "instruction_override"),
    (0.8, re.compile(r"\b(you are now|act as|pretend to be|roleplay as)\b.{0,40}\b(dan|developer mode|jailbroken|unrestricted|no restrictions)\b", re.I), "jailbreak_persona"),
    (0.6, re.compile(r"\bdeveloper mode\b|\bDAN\b|\bdo anything now\b", re.I), "jailbreak_persona"),
    (0.7, re.compile(r"(reveal|print|repeat|show|output).{0,25}(system prompt|your instructions|initial prompt|the prompt above)", re.I), "prompt_exfiltration"),
    (0.6, re.compile(r"(ignore|bypass|override|disable).{0,20}(safety|guardrails?|content policy|filters?|restrictions?)", re.I), "safety_bypass"),
    (0.5, re.compile(r"\bnew instructions?:\b|\bsystem:\s|<\|.*?\|>", re.I), "delimiter_injection"),
    (0.5, re.compile(r"(without|no).{0,15}(ethical|moral|legal).{0,15}(constraints?|limitations?|concerns?)", re.I), "constraint_removal"),
]


def score(text: str) -> dict:
    """Return {score, blocked-ish flag is the caller's job, signals: [labels]}."""
    matched: list[str] = []
    total = 0.0
    for weight, rx, label in _SIGNATURES:
        if rx.search(text):
            matched.append(label)
            total = max(total, weight) + 0.1 * (len(matched) - 1)  # stack a little
    return {"score": round(min(total, 1.0), 3), "signals": sorted(set(matched))}
