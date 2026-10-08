"""FastAPI firewall: scan inputs/outputs directly, or run a fully-guarded chat turn.

  POST /guard/input   scan a prompt   -> verdict (allow/redact/block + reasons + detections)
  POST /guard/output  scan a completion
  POST /chat          guarded turn: scan input -> (LLM) -> scan output
"""
from __future__ import annotations

import os

from fastapi import FastAPI
from pydantic import BaseModel, Field

from guardrails.config import MODEL
from guardrails.guard import Guard

app = FastAPI(title="LLM Guardrails", version="0.1.0")
guard = Guard()


def _llm(prompt: str) -> str:
    if not os.getenv("ANTHROPIC_API_KEY"):
        return f"(mock answer) You asked: {prompt[:80]}"
    import anthropic

    client = anthropic.Anthropic()
    resp = client.messages.create(model=MODEL, max_tokens=512,
                                  messages=[{"role": "user", "content": prompt}])
    return next((b.text for b in resp.content if b.type == "text"), "")


class TextIn(BaseModel):
    text: str = Field(..., min_length=1)


class ChatIn(BaseModel):
    prompt: str = Field(..., min_length=1)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/guard/input")
def guard_input(body: TextIn):
    return guard.scan_input(body.text).to_dict()


@app.post("/guard/output")
def guard_output(body: TextIn):
    return guard.scan_output(body.text).to_dict()


@app.post("/chat")
def chat(body: ChatIn):
    inp = guard.scan_input(body.prompt)
    if not inp.allowed:
        return {"blocked": True, "stage": "input", "reasons": inp.reasons,
                "answer": "Request blocked by input guardrail."}
    answer = _llm(inp.text)  # inp.text is PII-redacted if applicable
    out = guard.scan_output(answer)
    if not out.allowed:
        return {"blocked": True, "stage": "output", "reasons": out.reasons,
                "answer": "Response withheld by output guardrail."}
    return {"blocked": False, "answer": out.text,
            "input_verdict": inp.to_dict(), "output_verdict": out.to_dict()}
