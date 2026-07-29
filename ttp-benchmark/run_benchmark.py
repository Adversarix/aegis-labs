#!/usr/bin/env python3
"""TTP-extraction benchmark harness.

Runs every model in config.yaml over a corpus of threat-intel reports, scores
each model's extracted MITRE ATT&CK technique ids against gold labels, and
prints a comparison table (accuracy, latency, tokens, cost).

Usage:
    python run_benchmark.py                       # all models, full corpus
    python run_benchmark.py --models claude-opus-4-8 kimi-k3
    python run_benchmark.py --limit 2             # first 2 reports only
    python run_benchmark.py --corpus data/corpus.jsonl

Raw model outputs are cached under results/raw/ so reruns are cheap; pass
--no-cache to force fresh calls.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import sys

import yaml
from tabulate import tabulate

from harness.evaluate import ModelReport, evaluate_model, parent
from harness.providers import build_provider, normalize_id

ROOT = pathlib.Path(__file__).parent
RAW_DIR = ROOT / "results" / "raw"


def load_corpus(path: pathlib.Path, limit: int | None) -> list[dict]:
    rows = []
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows[:limit] if limit else rows


def load_config(path: pathlib.Path, only: list[str] | None) -> list[dict]:
    cfg = yaml.safe_load(path.read_text())
    models = cfg["models"]
    if only:
        models = [m for m in models if m["key"] in only]
        missing = set(only) - {m["key"] for m in models}
        if missing:
            sys.exit(f"unknown model key(s) in --models: {', '.join(sorted(missing))}")
    return models


def cache_path(model_key: str, report_id: str) -> pathlib.Path:
    safe = model_key.replace("/", "_")
    return RAW_DIR / safe / f"{report_id}.json"


def run_model(cfg: dict, corpus: list[dict], use_cache: bool) -> list[dict]:
    """Return per-report scoring rows for one model."""
    print(f"\n=== {cfg['key']} ({cfg['provider']}:{cfg['model']}) ===", flush=True)
    try:
        provider = build_provider(cfg)
    except Exception as e:  # noqa: BLE001 - a misconfigured model shouldn't kill the run
        print(f"  ! skipped: {type(e).__name__}: {e}")
        return [
            {"id": r["id"], "gold": set(r["gold_techniques"]), "pred": set(), "latency": 0.0,
             "in_tok": 0, "out_tok": 0, "error": str(e)}
            for r in corpus
        ]

    rows = []
    for r in corpus:
        cp = cache_path(cfg["key"], r["id"])
        result = None
        if use_cache and cp.exists():
            cached = json.loads(cp.read_text())
            preds = [normalize_id(t) for t in cached["technique_ids"]]
            rows.append({"id": r["id"], "gold": set(r["gold_techniques"]), "pred": {p for p in preds if p},
                         "latency": cached["latency_s"], "in_tok": cached["input_tokens"],
                         "out_tok": cached["output_tokens"], "error": cached.get("error")})
            print(f"  [cache] {r['id']}: {len([p for p in preds if p])} techniques")
            continue

        result = provider.extract(r["text"])
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
        preds = {p for p in result.technique_ids if p}
        tag = f"ERROR {result.error}" if result.error else f"{len(preds)} techniques ({result.latency_s:.1f}s)"
        print(f"  {r['id']}: {tag}")
        rows.append({"id": r["id"], "gold": set(r["gold_techniques"]), "pred": preds, "latency": result.latency_s,
                     "in_tok": result.input_tokens, "out_tok": result.output_tokens, "error": result.error})
    return rows


def print_table(reports: list[ModelReport]) -> None:
    headers = ["model", "F1(strict)", "P", "R", "F1(parent)", "macroF1", "errs", "avg s", "in tok", "out tok", "cost $"]
    table = []
    for r in reports:
        table.append([
            r.model_key,
            f"{r.micro_strict.f1:.3f}",
            f"{r.micro_strict.precision:.3f}",
            f"{r.micro_strict.recall:.3f}",
            f"{r.micro_parent.f1:.3f}",
            f"{r.macro_f1_strict:.3f}",
            f"{r.n_errors}/{r.n_reports}",
            f"{r.avg_latency_s:.1f}",
            r.total_input_tokens,
            r.total_output_tokens,
            f"{r.est_cost_usd:.4f}" if r.est_cost_usd is not None else "-",
        ])
    print("\n" + tabulate(table, headers=headers, tablefmt="github"))
    print("\nstrict = exact ATT&CK id; parent = technique-level (sub-technique collapsed).")
    print("F1/P/R are micro-averaged over the corpus; macroF1 averages per-report F1.")


def categorize(gold: set[str], pred: set[str]):
    """Split a model's prediction for one report into hits / misses / extras.

    A missed gold id is flagged True if its *parent* technique was predicted
    (covered at technique level — the model got the technique, wrong sub-technique).
    An extra id is flagged True if its parent is in gold (a wrong sub-technique of
    a real one) rather than a pure hallucination.
    """
    gold_par = {parent(g) for g in gold}
    pred_par = {parent(p) for p in pred}
    hits = sorted(gold & pred)
    missed = [(m, parent(m) in pred_par) for m in sorted(gold - pred)]
    extra = [(e, parent(e) in gold_par) for e in sorted(pred - gold)]
    return hits, missed, extra


def _fmt(marked: list[tuple[str, bool]]) -> str:
    if not marked:
        return "—"
    return " ".join(("~" + i if flag else i) for i, flag in marked)


def _index_rows(all_rows: dict[str, list[dict]]) -> dict:
    return {(mk, r["id"]): r for mk, rows in all_rows.items() for r in rows}


def print_drilldown(corpus: list[dict], all_rows: dict[str, list[dict]]) -> None:
    idx = _index_rows(all_rows)
    print("\n" + "=" * 78)
    print("PER-REPORT DRILL-DOWN")
    print("  miss   = gold technique the model did NOT predict (false negative)")
    print("  halluc = technique the model predicted that is NOT in gold (false positive)")
    print("  ~ID    = parent technique matched (right technique, wrong sub-technique)")
    for rep in corpus:
        gold = set(rep["gold_techniques"])
        print(f"\n── {rep['id']}  ({len(gold)} gold) " + "─" * 18)
        print(f"   gold: {' '.join(sorted(gold))}")
        for mk in all_rows:
            r = idx[(mk, rep["id"])]
            if r.get("error"):
                print(f"   {mk:16} ERROR {r['error']}")
                continue
            hits, missed, extra = categorize(gold, r["pred"])
            print(f"   {mk:16} hit {len(hits)}/{len(gold):<2}  miss: {_fmt(missed):34}  halluc: {_fmt(extra)}")


def write_drilldown_md(corpus: list[dict], all_rows: dict[str, list[dict]], path: pathlib.Path) -> None:
    idx = _index_rows(all_rows)
    lines = ["# Per-report drill-down", "",
             "`miss` = false negative (gold technique the model missed). "
             "`halluc` = false positive (predicted, not in gold). "
             "`~ID` = right technique, wrong sub-technique.", ""]
    for rep in corpus:
        gold = set(rep["gold_techniques"])
        lines += [f"## {rep['id']} ({len(gold)} gold)", "",
                  f"**gold:** {' '.join(sorted(gold))}", "",
                  "| model | hit | miss | halluc |", "|---|---|---|---|"]
        for mk in all_rows:
            r = idx[(mk, rep["id"])]
            if r.get("error"):
                lines.append(f"| {mk} | — | — | ERROR: {r['error']} |")
                continue
            hits, missed, extra = categorize(gold, r["pred"])
            lines.append(f"| {mk} | {len(hits)}/{len(gold)} | {_fmt(missed)} | {_fmt(extra)} |")
        lines.append("")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", default=str(ROOT / "config.yaml"))
    ap.add_argument("--corpus", default=str(ROOT / "data" / "corpus.jsonl"))
    ap.add_argument("--models", nargs="*", help="subset of model keys to run")
    ap.add_argument("--limit", type=int, help="only the first N reports")
    ap.add_argument("--no-cache", action="store_true", help="ignore cached responses")
    ap.add_argument("--no-drill", action="store_true", help="skip the per-report drill-down")
    ap.add_argument(
        "--reasoning-effort",
        choices=["none", "low", "medium", "high", "xhigh", "max"],
        help="override reasoning_effort for openai_compatible models (e.g. Kimi K3); "
        "not all providers accept every level, and the API coerces unsupported ones",
    )
    args = ap.parse_args()

    corpus = load_corpus(pathlib.Path(args.corpus), args.limit)
    models = load_config(pathlib.Path(args.config), args.models)

    if args.reasoning_effort:
        overridden = []
        for m in models:
            if m.get("provider") == "openai_compatible":
                m.setdefault("params", {})["reasoning_effort"] = args.reasoning_effort
                overridden.append(m["key"])
        if overridden:
            print(f"reasoning_effort={args.reasoning_effort} applied to: {', '.join(overridden)}")
            if not args.no_cache:
                print("  ! note: cache is keyed by model+report, not effort; pass "
                      "--no-cache to avoid reusing responses from another effort level")

    print(f"Corpus: {len(corpus)} reports | Models: {', '.join(m['key'] for m in models)}")

    reports: list[ModelReport] = []
    all_rows: dict[str, list[dict]] = {}
    for cfg in models:
        rows = run_model(cfg, corpus, use_cache=not args.no_cache)
        all_rows[cfg["key"]] = rows
        reports.append(evaluate_model(cfg["key"], rows, cfg.get("price_in"), cfg.get("price_out")))

    print_table(reports)

    if not args.no_drill:
        print_drilldown(corpus, all_rows)
        write_drilldown_md(corpus, all_rows, ROOT / "results" / "drilldown.md")

    out = ROOT / "results" / "summary.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps([{
        "model": r.model_key,
        "f1_strict": r.micro_strict.f1, "precision": r.micro_strict.precision, "recall": r.micro_strict.recall,
        "f1_parent": r.micro_parent.f1, "macro_f1_strict": r.macro_f1_strict,
        "errors": r.n_errors, "n_reports": r.n_reports, "avg_latency_s": r.avg_latency_s,
        "input_tokens": r.total_input_tokens, "output_tokens": r.total_output_tokens, "cost_usd": r.est_cost_usd,
    } for r in reports], indent=2))
    print(f"\nWrote {out.relative_to(ROOT)}, results/drilldown.md, and raw outputs to results/raw/")


if __name__ == "__main__":
    main()
