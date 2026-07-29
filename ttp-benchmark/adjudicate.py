#!/usr/bin/env python3
"""Adjudicate ATT&CK gold labels for a CISA corpus subset.

CISA advisory tables are not exhaustive: the prose usually describes more
techniques than the table tags, so models get penalised (false positives) for
extracting real-but-untabled techniques. This tool produces human-verified gold
that reflects what the prose actually substantiates, so absolute precision/recall
become trustworthy (not just the ranking).

Process (see README "Adjudicating labels"):
  1. Build a candidate pool per report = CISA table gold UNION every technique any
     model predicted. (A technique ALL models missed can't enter this pool, so for
     honest recall the human should also read for misses -- flagged in the summary.)
  2. Adjudicate each candidate against the PROSE, not the table: keep / drop, with
     an optional substantiation tier (explicit vs inferable) and a note.
  3. Emit an adjudicated corpus + a delta report (what adjudication added/removed
     vs the CISA table).

Bias guards: --blind hides which source proposed a candidate (shuffled order).
An optional --llm-prepass <config-key> pre-labels candidates with a judge model
to speed review; the human still decides. Do NOT use a model you are benchmarking
as the sole judge -- it is circular; treat the pre-pass as a suggestion only.

Usage:
    # pick a stratified subset yourself, or sample:
    python adjudicate.py --sample 20 --models claude-opus-4-8 kimi-k3-fireworks deepseek-v4-pro qwen3-max
    python adjudicate.py --ids aa25-071a aa24-109a --models claude-opus-4-8
    python adjudicate.py --resume            # continue a saved session
    python adjudicate.py --emit              # write the adjudicated corpus from saved decisions

Interactive keys per candidate: [k]eep  [d]rop  e=keep(explicit)  i=keep(inferable)
    n=add note   b=back   s=skip   ?=show prose   q=save & quit
"""

from __future__ import annotations

import argparse
import glob
import json
import pathlib
import random
import re
import sys

ROOT = pathlib.Path(__file__).parent
RAW = ROOT / "results" / "raw"
STATE = ROOT / "results" / "adjudication.json"   # resumable decisions + notes

_ID_RE = re.compile(r"T\d{4}(?:\.\d{3})?")


def norm(s: str) -> str:
    m = _ID_RE.search((s or "").upper())
    return m.group(0) if m else ""


def attack_url(tid: str) -> str:
    return "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"


def load_corpus(path: pathlib.Path) -> dict:
    return {r["id"]: r for r in (json.loads(l) for l in path.read_text().splitlines() if l.strip())}


def load_predictions(model: str, rid: str) -> list[dict]:
    p = RAW / model / f"{rid}.json"
    if not p.exists():
        return []
    d = json.loads(p.read_text())
    if d.get("error"):
        return []
    return d.get("techniques", []) or []


def build_candidates(report: dict, models: list[str]) -> dict:
    """id -> {sources:set[str], names:set[str], evidence:list[str]}."""
    cands: dict[str, dict] = {}

    def add(tid, source, name="", evidence=""):
        tid = norm(tid)
        if not tid:
            return
        c = cands.setdefault(tid, {"sources": set(), "names": set(), "evidence": []})
        c["sources"].add(source)
        if name:
            c["names"].add(name.strip())
        if evidence:
            c["evidence"].append(evidence.strip())

    for tid in report.get("gold_techniques", []):
        add(tid, "cisa-table")
    for m in models:
        for t in load_predictions(m, report["id"]):
            add(t.get("technique_id", ""), m, t.get("name", ""), t.get("evidence", ""))
    return cands


def _sentences(text: str) -> list[str]:
    return [s.strip() for s in re.split(r"(?<=[.!?])\s+", text) if s.strip()]


def supporting_sentences(text: str, names: set[str], evidence: list[str], k: int = 2) -> list[str]:
    """Surface the prose sentences most likely to support a candidate, by word
    overlap with the technique name(s) and any model-supplied evidence."""
    terms: set[str] = set()
    for src in list(names) + evidence:
        terms |= {w for w in re.findall(r"[a-zA-Z][a-zA-Z0-9-]{3,}", src.lower())}
    terms -= {"this", "that", "which", "actor", "actors", "used", "using", "have", "with", "technique"}
    if not terms:
        return []
    scored = []
    for s in _sentences(text):
        sw = set(re.findall(r"[a-zA-Z][a-zA-Z0-9-]{3,}", s.lower()))
        overlap = len(terms & sw)
        if overlap:
            scored.append((overlap, s))
    scored.sort(key=lambda x: -x[0])
    return [s for _, s in scored[:k]]


# ---------------------------------------------------------------------------
# optional LLM pre-pass
# ---------------------------------------------------------------------------

def llm_prepass(report: dict, cands: dict, cfg_key: str) -> dict:
    """Return {tid: {'suggested': 'keep'|'drop', 'quote': str}} using a judge model
    from config.yaml. Suggestion only -- the human still decides."""
    import yaml
    cfgs = {m["key"]: m for m in yaml.safe_load((ROOT / "config.yaml").read_text())["models"]}
    if cfg_key not in cfgs:
        sys.exit(f"--llm-prepass: unknown model key {cfg_key!r}")
    cfg = cfgs[cfg_key]
    out: dict[str, dict] = {}
    sys_prompt = (
        "You are an ATT&CK adjudicator. Given an advisory excerpt and a candidate "
        "MITRE ATT&CK technique, decide whether the TEXT substantiates that technique "
        "per its ATT&CK definition. Respond as JSON: "
        '{"supported": true|false, "quote": "<shortest supporting sentence, or empty>"}.'
    )
    text = report["text"][:12000]
    if cfg["provider"] == "anthropic":
        from anthropic import Anthropic
        client = Anthropic()
        def ask(u):
            r = client.messages.create(model=cfg["model"], max_tokens=400, system=sys_prompt,
                                       messages=[{"role": "user", "content": u}])
            return next((b.text for b in r.content if b.type == "text"), "")
    else:
        import os
        from openai import OpenAI
        client = OpenAI(api_key=os.environ.get(cfg.get("api_key_env", ""), ""),
                        base_url=os.environ.get(cfg.get("base_url_env", ""), "") or cfg.get("base_url_default"))
        def ask(u):
            r = client.chat.completions.create(model=cfg["model"], max_tokens=400, temperature=0,
                                               response_format={"type": "json_object"},
                                               messages=[{"role": "system", "content": sys_prompt},
                                                         {"role": "user", "content": u}])
            return r.choices[0].message.content or ""
    for tid, c in cands.items():
        name = next(iter(c["names"]), "")
        u = f"Advisory excerpt:\n{text}\n\nCandidate technique: {tid} {name}\nSubstantiated by the text?"
        try:
            m = re.search(r"\{.*\}", ask(u), re.S)
            j = json.loads(m.group(0)) if m else {}
            out[tid] = {"suggested": "keep" if j.get("supported") else "drop", "quote": j.get("quote", "")}
        except Exception as e:  # noqa: BLE001
            out[tid] = {"suggested": "", "quote": f"(judge error: {type(e).__name__})"}
    return out


# ---------------------------------------------------------------------------
# state
# ---------------------------------------------------------------------------

def load_state() -> dict:
    return json.loads(STATE.read_text()) if STATE.exists() else {"decisions": {}, "prepass": {}}


def save_state(state: dict) -> None:
    STATE.parent.mkdir(parents=True, exist_ok=True)
    STATE.write_text(json.dumps(state, indent=2))


# ---------------------------------------------------------------------------
# interactive review
# ---------------------------------------------------------------------------

def review(corpus: dict, ids: list[str], models: list[str], blind: bool, prepass_key: str | None) -> None:
    state = load_state()
    dec = state["decisions"]
    for rid in ids:
        report = corpus[rid]
        cands = build_candidates(report, models)
        if prepass_key and rid not in state["prepass"]:
            print(f"[{rid}] running LLM pre-pass ({prepass_key}) over {len(cands)} candidates...", flush=True)
            state["prepass"][rid] = llm_prepass(report, cands, prepass_key)
            save_state(state)
        prepass = state["prepass"].get(rid, {})

        order = list(cands)
        if blind:
            random.shuffle(order)
        print("\n" + "=" * 78)
        print(f"REPORT {rid}: {report.get('title', '')[:70]}")
        print(f"  {len(cands)} candidates | CISA table had {len(report.get('gold_techniques', []))}")
        for tid in order:
            key = f"{rid}:{tid}"
            if key in dec:
                continue
            c = cands[tid]
            name = next(iter(c["names"]), "")
            print(f"\n  {tid}  {name}")
            print(f"     {attack_url(tid)}")
            if not blind:
                print(f"     proposed by: {', '.join(sorted(c['sources']))}")
            for s in supporting_sentences(report["text"], c["names"], c["evidence"]):
                print(f"     prose: \"{s[:200]}\"")
            if tid in prepass:
                pp = prepass[tid]
                print(f"     LLM suggests: {pp['suggested'] or '?'}  {('| '+pp['quote'][:120]) if pp.get('quote') else ''}")
            ans = input("     [k]eep [d]rop e=explicit i=inferable n=note b=back ?=prose q=quit > ").strip().lower()
            if ans == "q":
                save_state(state); print("saved."); return
            if ans == "?":
                print("\n" + report["text"][:4000] + "\n")
                ans = input("     [k]eep [d]rop e i n b > ").strip().lower()
            note = ""
            if ans == "n":
                note = input("     note: ").strip()
                ans = input("     [k]eep [d]rop e i > ").strip().lower()
            mapping = {"k": ("keep", ""), "e": ("keep", "explicit"), "i": ("keep", "inferable"), "d": ("drop", "")}
            if ans in mapping:
                verdict, tier = mapping[ans]
                dec[key] = {"verdict": verdict, "tier": tier, "note": note, "sources": sorted(c["sources"])}
                save_state(state)
            # anything else (incl. 's'/'b') = skip for now
    save_state(state)
    print("\nreview pass complete for the requested reports.")


# ---------------------------------------------------------------------------
# emit adjudicated corpus + delta
# ---------------------------------------------------------------------------

def emit(corpus: dict, ids: list[str], out_path: pathlib.Path) -> None:
    state = load_state()
    dec = state["decisions"]
    rows, added_tot, removed_tot, undecided = [], 0, 0, 0
    for rid in ids:
        report = corpus[rid]
        table = set(report.get("gold_techniques", []))
        kept, decided = set(), set()
        for key, d in dec.items():
            r, tid = key.split(":", 1)
            if r != rid:
                continue
            decided.add(tid)
            if d["verdict"] == "keep":
                kept.add(tid)
        # candidates with no decision yet
        cands = set(build_candidates(report, MODELS_FOR_EMIT))
        undecided += len(cands - decided)
        added = kept - table
        removed = table - kept  # table techniques the human dropped
        added_tot += len(added); removed_tot += len(removed)
        rows.append({
            "id": rid, "source": "cisa-adjudicated", "url": report.get("url", ""),
            "title": report.get("title", ""), "text": report["text"],
            "gold_techniques": sorted(kept),
            "adjudication": {"table_gold": sorted(table), "added": sorted(added), "removed": sorted(removed)},
        })
    out_path.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + "\n")
    print(f"wrote {len(rows)} adjudicated reports -> {out_path}")
    print(f"table-incompleteness delta: +{added_tot} added, -{removed_tot} removed vs CISA tables")
    if undecided:
        print(f"WARNING: {undecided} candidates still undecided; run review to finish before trusting scores")


MODELS_FOR_EMIT: list[str] = []


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--corpus", default=str(ROOT / "data" / "corpus_cisa.jsonl"))
    ap.add_argument("--ids", nargs="*", help="explicit report ids to adjudicate")
    ap.add_argument("--sample", type=int, help="random N reports (stratify yourself via --ids for real use)")
    ap.add_argument("--models", nargs="*", default=[], help="models whose predictions seed the candidate pool")
    ap.add_argument("--blind", action="store_true", help="hide which source proposed each candidate")
    ap.add_argument("--llm-prepass", metavar="CONFIG_KEY", help="judge model key from config.yaml (suggestion only)")
    ap.add_argument("--resume", action="store_true", help="continue the saved session over its reports")
    ap.add_argument("--emit", action="store_true", help="write adjudicated corpus from saved decisions")
    ap.add_argument("-o", "--out", default=str(ROOT / "data" / "corpus_cisa_adjudicated.jsonl"))
    args = ap.parse_args()

    corpus = load_corpus(pathlib.Path(args.corpus))
    global MODELS_FOR_EMIT
    MODELS_FOR_EMIT = args.models or _infer_models()

    if args.resume or args.emit:
        ids = sorted({k.split(":", 1)[0] for k in load_state()["decisions"]}) or list(corpus)
    elif args.ids:
        ids = args.ids
    elif args.sample:
        pool = list(corpus)
        random.shuffle(pool)
        ids = pool[: args.sample]
    else:
        ap.error("give --ids, --sample N, --resume, or --emit")

    missing = [i for i in ids if i not in corpus]
    if missing:
        sys.exit(f"ids not in corpus: {', '.join(missing)}")

    if args.emit:
        emit(corpus, ids, pathlib.Path(args.out))
    else:
        review(corpus, ids, MODELS_FOR_EMIT, args.blind, args.llm_prepass)


def _infer_models() -> list[str]:
    return sorted(p.name for p in RAW.iterdir() if p.is_dir()) if RAW.exists() else []


if __name__ == "__main__":
    main()
