"""Guard policy: thresholds + per-category action (block vs redact)."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(os.getenv("GUARD_ROOT", Path(__file__).resolve().parents[2]))
CASES_PATH = ROOT / "data" / "cases.yaml"
MODEL = os.getenv("GUARD_MODEL", "claude-opus-4-8")


@dataclass
class Policy:
    injection_threshold: float = 0.6      # block input at/above this injection score
    toxicity_threshold: float = 0.5       # block at/above this toxicity score
    block_on_input_secret: bool = True    # secrets in a prompt → block (vs redact)
    redact_pii: bool = True               # PII → redact (not block)
    use_llm_toxicity: bool = False        # upgrade toxicity to the Claude judge
    categories: list[str] = field(default_factory=lambda: [
        "injection", "pii", "toxicity", "secrets"])
