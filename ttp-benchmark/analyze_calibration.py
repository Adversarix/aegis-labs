#!/usr/bin/env python3
"""Calibration + threshold analysis for the Jev Noul sweep.

Jev's headline claim is calibrated probabilities. The TTP harness scores a
thresholded technique *set*, which hides that. This script goes back to the
raw noul values saved per report and scores them as probabilistic predictions
against ground truth over the full candidate label space.

For every (report, candidate-technique) pair it forms:
    label = 1 if the technique is in that report's gold set else 0
    prob  = the noul value Jev returned (0.0 if the technique wasn't scored)

and reports Brier score, Expected Calibration Error, a reliability table, and
a precision/recall/F1 sweep over decision thresholds.

Usage:
    python analyze_calibration.py                      # both corpora, jev-typesafe
    python analyze_calibration.py --model jev-typesafe --bins 10
"""

from __future__ import annotations

import argparse
import json
import pathlib

from tabulate import tabulate

ROOT = pathlib.Path(__file__).parent
CORPORA = ["data/corpus.jsonl", "data/corpus_cisa.jsonl"]


def load_gold() -> dict[str, set[str]]:
    gold: dict[str, set[str]] = {}
    for c in CORPORA:
        p = ROOT / c
        if not p.exists():
            continue
        for line in p.read_text().splitlines():
            line = line.strip()
            if line:
                r = json.loads(line)
                gold[r["id"]] = set(r["gold_techniques"])
    return gold


def load_pairs(model: str, candidates: list[str], gold: dict[str, set[str]]):
    """Yield (prob, label) over every (report, candidate) pair."""
    raw_dir = ROOT / "results" / "raw" / model
    pairs: list[tuple[float, int]] = []
    n_reports = 0
    for rid, gset in gold.items():
        f = raw_dir / f"{rid}.json"
        if not f.exists():
            continue
        n_reports += 1
        rec = json.loads(f.read_text())
        nouls = json.loads(rec.get("raw_text") or "{}").get("nouls", {})
        for tid in candidates:
            prob = float(nouls.get(tid, 0.0))
            label = 1 if tid in gset else 0
            pairs.append((prob, label))
    return pairs, n_reports


def brier(pairs) -> float:
    return sum((p - y) ** 2 for p, y in pairs) / len(pairs)


def reliability(pairs, bins: int):
    """Equal-width bins; returns rows (lo, hi, n, mean_pred, frac_pos) and ECE."""
    edges = [i / bins for i in range(bins + 1)]
    rows = []
    ece = 0.0
    total = len(pairs)
    for b in range(bins):
        lo, hi = edges[b], edges[b + 1]
        # last bin is closed on the right so prob==1.0 lands somewhere
        sel = [(p, y) for p, y in pairs if (lo <= p < hi or (b == bins - 1 and p == hi))]
        if not sel:
            rows.append((lo, hi, 0, None, None))
            continue
        mean_pred = sum(p for p, _ in sel) / len(sel)
        frac_pos = sum(y for _, y in sel) / len(sel)
        rows.append((lo, hi, len(sel), mean_pred, frac_pos))
        ece += (len(sel) / total) * abs(frac_pos - mean_pred)
    return rows, ece


def threshold_sweep(pairs, thresholds):
    out = []
    for t in thresholds:
        tp = fp = fn = 0
        for p, y in pairs:
            pred = 1 if p >= t else 0
            if pred and y:
                tp += 1
            elif pred and not y:
                fp += 1
            elif not pred and y:
                fn += 1
        prec = tp / (tp + fp) if tp + fp else 0.0
        rec = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
        out.append((t, tp, fp, fn, prec, rec, f1))
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="jev-typesafe")
    ap.add_argument("--candidates", default="data/candidates_corpus.json")
    ap.add_argument("--bins", type=int, default=10)
    args = ap.parse_args()

    candidates = list(json.loads((ROOT / args.candidates).read_text()))
    gold = load_gold()
    pairs, n_reports = load_pairs(args.model, candidates, gold)
    if not pairs:
        raise SystemExit(f"no raw outputs found for model {args.model!r}; run the sweep first")

    n = len(pairs)
    pos = sum(y for _, y in pairs)
    print(f"model={args.model}  reports={n_reports}  candidates={len(candidates)}")
    print(f"pairs={n}  positives={pos}  base_rate={pos / n:.4f}")
    print(f"\nBrier score : {brier(pairs):.4f}   (lower is better; 0 = perfect)")

    rows, ece = reliability(pairs, args.bins)
    print(f"ECE         : {ece:.4f}   (lower is better; gap between confidence and reality)")

    print("\nReliability table (does a stated probability match observed frequency?)")
    table = [[f"{lo:.1f}-{hi:.1f}", n_, f"{mp:.3f}" if mp is not None else "-",
              f"{fp:.3f}" if fp is not None else "-",
              f"{(fp - mp):+.3f}" if mp is not None else "-"]
             for lo, hi, n_, mp, fp in rows]
    print(tabulate(table, headers=["bin", "n", "mean_pred", "frac_pos", "gap(obs-pred)"], tablefmt="github"))

    ths = [round(0.05 * i, 2) for i in range(1, 20)]
    sweep = threshold_sweep(pairs, ths)
    best = max(sweep, key=lambda r: r[6])
    print("\nThreshold sweep (micro over all report x technique pairs)")
    stab = [[f"{t:.2f}", tp, fp, fn, f"{p:.3f}", f"{r:.3f}", f"{f:.3f}" + (" <-best" if (t, tp, fp, fn, p, r, f) == best else "")]
            for (t, tp, fp, fn, p, r, f) in sweep]
    print(tabulate(stab, headers=["thresh", "TP", "FP", "FN", "P", "R", "F1"], tablefmt="github"))
    print(f"\nBest F1 = {best[6]:.3f} at threshold {best[0]:.2f} "
          f"(P={best[4]:.3f} R={best[5]:.3f}). Config currently uses 0.5.")


if __name__ == "__main__":
    main()
