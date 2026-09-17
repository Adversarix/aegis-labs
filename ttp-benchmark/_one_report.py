#!/usr/bin/env python3
"""Process a single corpus report through one model and write the harness cache
file (results/raw/<model>/<id>.json). Used to finish long-running local-model
reports one at a time, outside the background runner that keeps getting killed.

Usage: python _one_report.py <model_key> <report_id>
"""
import json
import pathlib
import sys

import yaml

from harness.providers import build_provider

ROOT = pathlib.Path(__file__).parent
model_key, report_id = sys.argv[1], sys.argv[2]

cfg = next(m for m in yaml.safe_load((ROOT / "config.yaml").read_text())["models"] if m["key"] == model_key)
report = next(json.loads(l) for l in open(ROOT / "data" / "corpus.jsonl") if json.loads(l)["id"] == report_id)

provider = build_provider(cfg)
result = provider.extract(report["text"])

cp = ROOT / "results" / "raw" / model_key.replace("/", "_") / f"{report_id}.json"
cp.parent.mkdir(parents=True, exist_ok=True)
cp.write_text(json.dumps({
    "technique_ids": result.technique_ids,
    "techniques": result.techniques,
    "raw_text": result.raw_text,
    "input_tokens": result.input_tokens,
    "output_tokens": result.output_tokens,
    "latency_s": result.latency_s,
    "error": result.error,
}, indent=2))
tag = f"ERROR {result.error}" if result.error else f"{len(result.technique_ids)} techniques ({result.latency_s:.1f}s)"
print(f"{report_id}: {tag} -> {cp.relative_to(ROOT)}")
