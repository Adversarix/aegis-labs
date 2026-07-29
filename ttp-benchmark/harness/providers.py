"""Provider adapters.

Two adapters cover everything we need:

  AnthropicProvider        -> Claude, via the official `anthropic` SDK.
  OpenAICompatibleProvider -> Kimi K3 (Moonshot) and Qwen (DashScope), both of
                              which speak the OpenAI Chat Completions API.

Each adapter takes a raw report string and returns a normalised
`ExtractionResult`. Failures are captured, not raised, so one dead provider
never sinks the whole benchmark.
"""

from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass, field

from .prompts import SYSTEM, build_user_prompt
from .schema import TTP_JSON_SCHEMA


@dataclass
class ExtractionResult:
    model_key: str
    techniques: list[dict] = field(default_factory=list)  # [{technique_id, name, evidence}]
    raw_text: str = ""
    input_tokens: int = 0
    output_tokens: int = 0
    latency_s: float = 0.0
    error: str | None = None

    @property
    def technique_ids(self) -> list[str]:
        return [normalize_id(t.get("technique_id", "")) for t in self.techniques if t.get("technique_id")]


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

_ID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")


def normalize_id(raw: str) -> str:
    """Uppercase, strip, keep only a well-formed ATT&CK id (else '')."""
    s = (raw or "").strip().upper().replace(" ", "")
    m = re.search(r"T\d{4}(?:\.\d{3})?", s)
    return m.group(0) if m else ""


def _strip_fences(text: str) -> str:
    """Pull JSON out of a ```json ... ``` fence if the model added one."""
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z]*\n", "", text)
        text = re.sub(r"\n```$", "", text)
    # If there's leading/trailing prose, grab the outermost {...}.
    start, end = text.find("{"), text.rfind("}")
    if start != -1 and end != -1 and end > start:
        return text[start : end + 1]
    return text


def _parse_techniques(text: str) -> list[dict]:
    data = json.loads(_strip_fences(text))
    techs = data.get("techniques", []) if isinstance(data, dict) else []
    out = []
    for t in techs:
        if isinstance(t, dict) and t.get("technique_id"):
            out.append(
                {
                    "technique_id": str(t.get("technique_id", "")),
                    "name": str(t.get("name", "")),
                    "evidence": str(t.get("evidence", "")),
                }
            )
    return out


# ---------------------------------------------------------------------------
# Anthropic (Claude)
# ---------------------------------------------------------------------------

class AnthropicProvider:
    def __init__(self, cfg: dict):
        from anthropic import Anthropic  # imported lazily so the dep is optional

        self.cfg = cfg
        self.key = cfg["key"]
        self.model = cfg["model"]
        self.max_tokens = cfg.get("max_tokens", 4096)
        self.client = Anthropic()  # reads ANTHROPIC_API_KEY / ant profile

    def extract(self, report_text: str) -> ExtractionResult:
        t0 = time.perf_counter()
        try:
            resp = self.client.messages.create(
                model=self.model,
                max_tokens=self.max_tokens,
                system=SYSTEM,
                messages=[{"role": "user", "content": build_user_prompt(report_text)}],
                output_config={"format": {"type": "json_schema", "schema": TTP_JSON_SCHEMA}},
            )
            if getattr(resp, "stop_reason", None) == "refusal":
                return ExtractionResult(
                    model_key=self.key,
                    raw_text="",
                    input_tokens=resp.usage.input_tokens,
                    output_tokens=resp.usage.output_tokens,
                    latency_s=time.perf_counter() - t0,
                    error="refusal (model declined to process this report)",
                )
            text = next((b.text for b in resp.content if b.type == "text"), "")
            return ExtractionResult(
                model_key=self.key,
                techniques=_parse_techniques(text),
                raw_text=text,
                input_tokens=resp.usage.input_tokens,
                output_tokens=resp.usage.output_tokens,
                latency_s=time.perf_counter() - t0,
            )
        except Exception as e:  # noqa: BLE001 - record, don't crash the run
            return ExtractionResult(
                model_key=self.key, latency_s=time.perf_counter() - t0, error=f"{type(e).__name__}: {e}"
            )


# ---------------------------------------------------------------------------
# OpenAI-compatible (Kimi K3, Qwen, ...)
# ---------------------------------------------------------------------------

class OpenAICompatibleProvider:
    def __init__(self, cfg: dict):
        from openai import OpenAI  # lazy import

        self.cfg = cfg
        self.key = cfg["key"]
        self.model = cfg["model"]
        self.max_tokens = cfg.get("max_tokens", 4096)
        # Extra request params forwarded verbatim to the API (e.g.
        # reasoning_effort). Sent via extra_body so provider-specific values
        # pass through regardless of the installed OpenAI SDK version.
        self.extra_params = cfg.get("params", {}) or {}

        api_key = os.environ.get(cfg.get("api_key_env", ""), "")
        base_url = os.environ.get(cfg.get("base_url_env", ""), "") or cfg.get("base_url_default")
        if not api_key:
            raise RuntimeError(f"missing API key env {cfg.get('api_key_env')!r} for model {self.key}")
        self.client = OpenAI(api_key=api_key, base_url=base_url)

    def extract(self, report_text: str) -> ExtractionResult:
        t0 = time.perf_counter()
        try:
            resp = self.client.chat.completions.create(
                model=self.model,
                max_tokens=self.max_tokens,
                temperature=0,
                response_format={"type": "json_object"},
                messages=[
                    {"role": "system", "content": SYSTEM},
                    {"role": "user", "content": build_user_prompt(report_text)},
                ],
                extra_body=self.extra_params or None,
            )
            text = resp.choices[0].message.content or ""
            usage = resp.usage
            return ExtractionResult(
                model_key=self.key,
                techniques=_parse_techniques(text),
                raw_text=text,
                input_tokens=getattr(usage, "prompt_tokens", 0) or 0,
                output_tokens=getattr(usage, "completion_tokens", 0) or 0,
                latency_s=time.perf_counter() - t0,
            )
        except Exception as e:  # noqa: BLE001
            return ExtractionResult(
                model_key=self.key, latency_s=time.perf_counter() - t0, error=f"{type(e).__name__}: {e}"
            )


def build_provider(cfg: dict):
    kind = cfg["provider"]
    if kind == "anthropic":
        return AnthropicProvider(cfg)
    if kind == "openai_compatible":
        return OpenAICompatibleProvider(cfg)
    raise ValueError(f"unknown provider {kind!r} for model {cfg.get('key')!r}")
