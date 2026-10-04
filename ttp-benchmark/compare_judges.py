#!/usr/bin/env python3
"""Compare two adjudication judges and emit a consensus-gold corpus.

The adjudicated CISA gold was first built with Claude, which is also one of the
scored models. This measures how much a held-out judge (gpt-oss, neither scored
nor Claude) agrees, so the gold does not rest on a scored model's say-so.

Both judges ruled on the identical per-report candidate pool (table gold union
every model's predictions), so their `verdicts` maps are directly comparable.
We report per-candidate agreement and Cohen's kappa, the overlap of the
techniques each judge ADDED, and write a consensus corpus whose gold is the CISA
table plus only the techniques BOTH judges substantiate (the conservative,
defensible ground truth).

Usage:
    python compare_judges.py \
      --a results/cisa_adjudication_audit.json --a-name claude \
      --b results/cisa_adjudication_audit_gptoss.json --b-name gptoss
"""

from __future__ import annotations

import argparse
import json
import pathlib

ROOT = pathlib.Path(__file__).parent


def load_audit(p: str) -> dict:
    return json.loads((ROOT / p).read_text())["reports"]


def verdict_set(rep: dict) -> dict:
    """tid -> bool supported, over the report's judged candidates."""
    return {t: bool(v.get("supported")) for t, v in (rep.get("verdicts") or {}).items()}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--a", default="results/cisa_adjudication_audit.json")
    ap.add_argument("--a-name", default="claude")
    ap.add_argument("--b", default="results/cisa_adjudication_audit_gptoss.json")
    ap.add_argument("--b-name", default="gptoss")
    ap.add_argument("--corpus", default="data/corpus_cisa.jsonl")
    ap.add_argument("--out", default="data/corpus_cisa_consensus.jsonl")
    args = ap.parse_args()

    A, B = load_audit(args.a), load_audit(args.b)
    corpus = {r["id"]: r for r in (json.loads(l) for l in (ROOT / args.corpus).read_text().splitlines() if l.strip())}

    both = both_yes = a_yes = b_yes = disagree = 0  # per-candidate tallies
    a_err = [r for r in A if A[r].get("error")]
    b_err = [r for r in B if B[r].get("error")]
    shared_reports = [r for r in A if r in B and not A[r].get("error") and not B[r].get("error")]

    add_jaccard = []
    rows = []
    for rid in corpus:
        table = set(corpus[rid]["gold_techniques"])
        if rid in shared_reports:
            va, vb = verdict_set(A[rid]), verdict_set(B[rid])
            shared = set(va) & set(vb)
            for t in shared:
                both += 1
                if va[t] and vb[t]:
                    both_yes += 1
                elif va[t]:
                    a_yes += 1; disagree += 1
                elif vb[t]:
                    b_yes += 1; disagree += 1
            add_a = {t for t in va if va[t]}
            add_b = {t for t in vb if vb[t]}
            if add_a or add_b:
                add_jaccard.append(len(add_a & add_b) / len(add_a | add_b))
            consensus = sorted(table | (add_a & add_b))
            src = "consensus"
        else:
            # one judge missing this report: fall back to table only, flagged
            consensus = sorted(table)
            src = "table-only (a judge skipped this report)"
        rows.append({"id": rid, "source": "cisa-consensus", "text": corpus[rid]["text"],
                     "gold_techniques": consensus, "consensus_note": src})

    (ROOT / args.out).write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + "\n")

    # agreement + kappa over the shared candidate pool
    agree = both_yes + (both - both_yes - disagree)  # both-yes + both-no
    po = agree / both if both else 0.0
    pa_yes = (both_yes + a_yes) / both if both else 0.0   # A positive rate
    pb_yes = (both_yes + b_yes) / both if both else 0.0   # B positive rate
    pe = pa_yes * pb_yes + (1 - pa_yes) * (1 - pb_yes)
    kappa = (po - pe) / (1 - pe) if (1 - pe) else 0.0

    print(f"reports: {len(shared_reports)} compared, "
          f"{args.a_name} skipped {len(a_err)}, {args.b_name} skipped {len(b_err)}")
    print(f"candidates jointly judged: {both}")
    print(f"  both YES (agree present) : {both_yes}")
    print(f"  both NO  (agree absent)  : {both - both_yes - disagree}")
    print(f"  {args.a_name}-only YES         : {a_yes}")
    print(f"  {args.b_name}-only YES         : {b_yes}")
    print(f"\nraw agreement: {po:.1%}")
    print(f"Cohen's kappa: {kappa:.3f}  "
          f"({'almost perfect' if kappa>=0.8 else 'substantial' if kappa>=0.6 else 'moderate' if kappa>=0.4 else 'fair/poor'})")
    print(f"{args.a_name} positive rate: {pa_yes:.1%} | {args.b_name} positive rate: {pb_yes:.1%}")
    if add_jaccard:
        print(f"added-technique-set Jaccard (mean over reports): {sum(add_jaccard)/len(add_jaccard):.1%}")
    print(f"\nwrote consensus corpus -> {args.out} "
          f"({len(rows)} reports; gold = table + techniques BOTH judges substantiate)")


if __name__ == "__main__":
    main()
