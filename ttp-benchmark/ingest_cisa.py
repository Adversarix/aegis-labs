#!/usr/bin/env python3
"""Ingest CISA cybersecurity advisories into the benchmark corpus format.

CISA's AA-series advisories ship a per-tactic "MITRE ATT&CK Techniques" table
(columns: Technique Title | ID | Use). That table is document-level, multi-label
ground truth for free. This script:

  1. fetches each advisory's HTML,
  2. reads gold technique ids out of the ATT&CK tables,
  3. strips ALL tables from the prose (so the model can't read the answer key),
  4. emits one corpus row per advisory: {id, source, url, title, text, gold_techniques}.

ATT&CK tables are detected by their header (a "Technique"+"ID" row), NOT by
caption text, because advisories rename tactics (e.g. "Stealth" for Defense
Evasion). D3FEND tables use D3-* ids and are naturally excluded by the T#### filter.

Usage:
    python ingest_cisa.py aa26-204a aa25-266a            # by slug
    python ingest_cisa.py https://www.cisa.gov/.../aa26-204a
    python ingest_cisa.py --from-listing 20              # 20 most recent AA-series
    python ingest_cisa.py --from-listing 20 -o data/corpus_cisa.jsonl

Rows with zero ATT&CK techniques are skipped (no usable gold) and reported.
"""

from __future__ import annotations

import argparse
import html as _html
import json
import re
import sys
import urllib.request

BASE = "https://www.cisa.gov"
LISTING = BASE + "/news-events/cybersecurity-advisories?f%5B0%5D=advisory_type%3A94"
UA = "Mozilla/5.0 (compatible; aegis-labs-ttp-benchmark/1.0; +https://github.com/Adversarix/aegis-labs)"

_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def fetch(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=45) as r:  # noqa: S310 - fixed cisa.gov host
        return r.read().decode("utf-8", "replace")


def _text(fragment: str) -> str:
    """HTML fragment -> collapsed plain text."""
    fragment = re.sub(r"<[^>]+>", " ", fragment)
    return _html.unescape(re.sub(r"\s+", " ", fragment)).strip()


def _cells(row_html: str) -> list[str]:
    return [_text(c) for c in re.findall(r"<t[dh][^>]*>(.*?)</t[dh]>", row_html, re.S)]


def _rows(table_html: str) -> list[list[str]]:
    return [_cells(r) for r in re.findall(r"<tr[^>]*>(.*?)</tr>", table_html, re.S)]


_START_MARKERS = ("executive summary", "summary", "overview")
_END_MARKERS = ("references", "disclaimer", "version history", "acknowledgement",
                "contact information", "rewards for justice", "revisions")


def _trim_boilerplate(text: str) -> str:
    """Trim page chrome: cut leading banner/metadata before the first summary
    heading, and trailing References/Disclaimer/Contact sections. Operates on
    flattened text with lowercase marker search; falls back to keeping the ends
    if a marker is absent."""
    low = text.lower()
    start = min((low.find(m) for m in _START_MARKERS if low.find(m) != -1), default=0)
    if start == -1:
        start = 0
    # Only cut trailing boilerplate in the latter half of the doc — these marker
    # words (references, disclaimer, ...) also occur in normal prose, and real
    # end sections always sit near the end. This avoids truncating mid-body.
    floor = start + (len(text) - start) // 2
    end_candidates = [low.find(m, floor) for m in _END_MARKERS]
    end_candidates = [i for i in end_candidates if i != -1]
    end = min(end_candidates) if end_candidates else len(text)
    trimmed = text[start:end].strip()
    return trimmed or text  # never return empty


def _strip_inline_ids(text: str) -> str:
    """Remove inline ATT&CK id citations from prose so the model must infer the
    technique from the described behavior, not copy the label. CISA advisories
    tag behaviors inline, e.g. "...exfiltration in bulk [T1114.002]." — that hands
    the model the answer. We drop the id (and any now-empty bracket) but leave the
    surrounding behavior description intact. Matches enterprise (T1###) and ICS
    (T0###) ids. gold_techniques is already collected from the tables, so this is safe.
    """
    # bracketed/parenthesized citations, incl. a leading comma-separated list
    text = re.sub(r"[\[(]\s*T\d{4}(?:\.\d{3})?(?:\s*,\s*T\d{4}(?:\.\d{3})?)*\s*[\])]", " ", text)
    # any remaining bare ids
    text = re.sub(r"\bT\d{4}(?:\.\d{3})?\b", " ", text)
    # tidy leftovers: empty brackets, orphaned separators, doubled spaces
    text = re.sub(r"[\[(]\s*[\])]", " ", text)
    return re.sub(r"\s+([.,;:])", r"\1", re.sub(r"\s+", " ", text)).strip()


def _is_attack_table(rows: list[list[str]]) -> bool:
    """True if the header row looks like Technique Title | ID | Use."""
    if not rows:
        return False
    header = " ".join(rows[0]).lower()
    return "technique" in header and "id" in header


def slug_to_url(s: str) -> str:
    s = s.strip()
    if s.startswith("http"):
        return s
    return f"{BASE}/news-events/cybersecurity-advisories/{s}"


def main_region(page_html: str) -> str:
    """Return the <main> region (drops site chrome) or the whole page as fallback."""
    m = re.search(r"<main\b.*?</main>", page_html, re.S)
    return m.group(0) if m else page_html


def parse_advisory(url: str, enterprise_only: bool = False) -> dict | None:
    page = fetch(url)
    slug = url.rstrip("/").split("/")[-1]

    h1 = re.search(r"<h1[^>]*>(.*?)</h1>", page, re.S)
    title = _text(h1.group(1)) if h1 else slug

    content = main_region(page)
    tables = re.findall(r"<table\b.*?</table>", content, re.S)

    gold: set[str] = set()
    for t in tables:
        rows = _rows(t)
        if not _is_attack_table(rows):
            continue
        # collect technique ids from the ID column of each data row
        for row in rows[1:]:
            for cell in row:
                for m in _ID_RE.findall(cell):
                    gold.add(m.upper())

    if enterprise_only:
        # drop ATT&CK-for-ICS ids (T0###); keep enterprise T1### only
        gold = {g for g in gold if not g.startswith("T0")}

    if not gold:
        return {"id": slug, "url": url, "title": title, "gold_techniques": [], "text": "", "_skip": True}

    # strip EVERY table from the prose so the answer key never reaches the model
    prose_html = re.sub(r"<table\b.*?</table>", " ", content, flags=re.S)
    prose_html = re.sub(r"<(script|style)\b.*?</\1>", " ", prose_html, flags=re.S)
    text = _text(prose_html)
    text = _trim_boilerplate(text)
    text = _strip_inline_ids(text)

    return {
        "id": slug,
        "source": "cisa",
        "url": url,
        "title": title,
        "text": text,
        "gold_techniques": sorted(gold),
    }


def discover(n: int) -> list[str]:
    """Collect up to n advisory URLs, paginating the listing (10 per page)."""
    seen, out = set(), []
    page = 0
    while len(out) < n and page < 50:  # 50-page backstop
        html_page = fetch(f"{LISTING}&page={page}")
        slugs = re.findall(r"/news-events/cybersecurity-advisories/(aa\d{2}-[0-9a-z]+)", html_page)
        new = [s for s in dict.fromkeys(slugs) if s not in seen]
        if not new:
            break  # no more results
        for s in new:
            seen.add(s)
            out.append(slug_to_url(s))
        page += 1
    return out[:n]


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("advisories", nargs="*", help="advisory slugs or URLs (e.g. aa26-204a)")
    ap.add_argument("--from-listing", type=int, metavar="N", help="pull N most recent AA-series advisories")
    ap.add_argument("--enterprise-only", action="store_true",
                    help="drop ATT&CK-for-ICS ids (T0###); skip reports left with no enterprise gold")
    ap.add_argument("-o", "--out", help="append rows to this JSONL file (else stdout)")
    args = ap.parse_args()

    urls = [slug_to_url(a) for a in args.advisories]
    if args.from_listing:
        urls += discover(args.from_listing)
    if not urls:
        ap.error("give advisory slugs/URLs or --from-listing N")

    rows, skipped = [], []
    for url in urls:
        try:
            row = parse_advisory(url, enterprise_only=args.enterprise_only)
        except Exception as e:  # noqa: BLE001 - one bad advisory shouldn't sink the batch
            print(f"  ! {url}: {type(e).__name__}: {e}", file=sys.stderr)
            continue
        if row.get("_skip"):
            skipped.append(row["id"])
            print(f"  - {row['id']}: no ATT&CK table, skipped", file=sys.stderr)
            continue
        rows.append(row)
        print(f"  + {row['id']}: {len(row['gold_techniques'])} techniques, {len(row['text'])} chars", file=sys.stderr)

    out = sys.stdout if not args.out else open(args.out, "a", encoding="utf-8")
    for r in rows:
        out.write(json.dumps(r, ensure_ascii=False) + "\n")
    if args.out:
        out.close()

    print(f"\ningested {len(rows)} advisories, skipped {len(skipped)}"
          + (f" ({', '.join(skipped)})" if skipped else ""), file=sys.stderr)


if __name__ == "__main__":
    main()
