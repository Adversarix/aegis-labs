#!/usr/bin/env python3
"""Dependency license gate — fail if any installed distribution is copyleft.

AEGIS Labs code is released permissively (Apache-2.0 / MIT) and some capabilities
are absorbed into the commercial Adversarix product. A copyleft dependency (GPL,
LGPL, AGPL, MPL, ...) imposes obligations on anything that links it, which would
contaminate that absorption path. This gate scans the *installed* environment and
fails on any non-allowlisted copyleft license.

Run it in an environment where the project requirements are installed:

    pip install -r exploitgym-eval/requirements.txt -r ttp-benchmark/requirements.txt
    python scripts/check_licenses.py

Exit codes:
    0  no copyleft found (unknown/unclassified licenses are reported as warnings)
    1  at least one non-allowlisted copyleft dependency

To accept a specific package deliberately (e.g. it is dual-licensed and we use
the permissive option), add it to ALLOWLIST with a reason.

Self-test the classifier without any environment:  python scripts/check_licenses.py --selftest
"""

from __future__ import annotations

import argparse
import re
import sys
from importlib import metadata

# Normalized package name -> reason it is allowed despite matching a copyleft
# pattern. Keep this small and justified; every entry is a deliberate exception.
ALLOWLIST: dict[str, str] = {
    # "example-pkg": "dual-licensed MIT OR GPL-2.0; we use it under MIT",
}

# Ordered (family, tier, pattern). First match wins, so more specific families
# (AGPL/LGPL) are tested before plain GPL.
#
# tier "block" = strong or network copyleft that can impose obligations on a
#   whole linked/derived work — dangerous for the Apache-2.0/MIT absorption path.
#   These fail the gate.
# tier "warn"  = weak / file-level copyleft (obligations attach only to
#   modifications of the licensed files themselves). Using these unmodified as
#   dependencies is standard practice even in proprietary products, so they are
#   reported for review but do not fail the gate.
PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
    ("AGPL", "block", re.compile(r"affero|\bAGPL", re.I)),
    ("LGPL", "warn", re.compile(r"lesser general public|\bLGPL", re.I)),
    ("GPL", "block", re.compile(r"general public license|\bGPL", re.I)),
    ("SSPL", "block", re.compile(r"server side public|\bSSPL\b", re.I)),
    ("OSL", "block", re.compile(r"open software license|\bOSL-", re.I)),
    ("EUPL", "block", re.compile(r"european union public|\bEUPL\b", re.I)),
    ("CeCILL", "block", re.compile(r"cecill", re.I)),
    ("CC-BY-SA", "block", re.compile(r"share.?alike|\bCC.?BY.?SA", re.I)),
    ("MPL", "warn", re.compile(r"mozilla public|\bMPL\b", re.I)),
    ("EPL", "warn", re.compile(r"eclipse public|\bEPL\b", re.I)),
    ("CDDL", "warn", re.compile(r"common development and distribution|\bCDDL\b", re.I)),
]


def normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name or "").lower()


def license_signals(md) -> list[str]:
    """Collect the license identifiers worth classifying for one distribution.

    Prefers SPDX ``License-Expression`` and trove ``License ::`` classifiers,
    which are short and reliable. The free-text ``License`` field is included
    only when it looks like an identifier (short, single line) rather than an
    embedded full license text, which would produce false positives.
    """
    signals: list[str] = []
    expr = md.get("License-Expression")
    if expr:
        signals.append(expr)
    for c in md.get_all("Classifier") or []:
        if c.startswith("License ::"):
            signals.append(c)
    lic = (md.get("License") or "").strip()
    if lic and len(lic) <= 80 and "\n" not in lic:
        signals.append(lic)
    return signals


def classify(signals: list[str]) -> tuple[str, str] | None:
    """Return ``(family, tier)`` if any signal matches copyleft, else None."""
    blob = " ; ".join(signals)
    for family, tier, pattern in PATTERNS:
        if pattern.search(blob):
            return family, tier
    return None


def scan() -> int:
    blocked: list[tuple[str, str, str, str]] = []  # name, version, family, signal
    weak: list[tuple[str, str, str, str]] = []
    unknown: list[tuple[str, str]] = []  # name, version
    total = 0

    for dist in sorted(metadata.distributions(), key=lambda d: normalize(d.metadata.get("Name", ""))):
        md = dist.metadata
        name = md.get("Name") or "?"
        version = md.get("Version") or "?"
        total += 1
        signals = license_signals(md)
        if not signals:
            unknown.append((name, version))
            continue
        hit = classify(signals)
        if hit is None:
            continue
        family, tier = hit
        row = (name, version, family, " | ".join(signals))
        if tier == "block" and normalize(name) not in ALLOWLIST:
            blocked.append(row)
        elif tier == "warn":
            weak.append(row)

    print(f"Scanned {total} installed distributions.\n")

    if blocked:
        print("STRONG COPYLEFT DEPENDENCIES FOUND (gate FAILED):")
        for name, version, family, signal in blocked:
            print(f"  ✗ {name} {version}  [{family}]  <- {signal}")
        print(
            "\nStrong/network copyleft (GPL, AGPL, SSPL, ...) can impose license "
            "obligations on everything that links it, which breaks the "
            "Apache-2.0/MIT absorption path.\n"
            "Remove the dependency, replace it with a permissive equivalent, or — "
            "if it is dual-licensed and we use the permissive option — add it to "
            "ALLOWLIST in scripts/check_licenses.py with a reason."
        )

    if weak:
        print(f"\nWEAK / FILE-LEVEL COPYLEFT ({len(weak)}) — review, does not fail the gate:")
        for name, version, family, signal in weak:
            print(f"  ~ {name} {version}  [{family}]  <- {signal}")
        print("  (obligations attach only to modifications of the licensed files; "
              "using these unmodified as dependencies is generally fine.)")

    if unknown:
        print(f"\nNO DETECTABLE LICENSE METADATA ({len(unknown)}) — review manually, "
              "does not fail the gate:")
        for name, version in unknown:
            print(f"  ? {name} {version}")

    print(f"\n{'FAILED: strong copyleft present.' if blocked else 'OK: no strong copyleft dependencies detected.'}")
    return 1 if blocked else 0


def selftest() -> int:
    cases = [
        (["MIT"], None),
        (["Apache-2.0"], None),
        (["BSD-3-Clause"], None),
        (["ISC"], None),
        (["License :: OSI Approved :: MIT License"], None),
        (["License :: OSI Approved :: Apache Software License"], None),
        (["MIT OR Apache-2.0"], None),
        (["GPL-3.0-or-later"], ("GPL", "block")),
        (["License :: OSI Approved :: GNU General Public License v3 (GPLv3)"], ("GPL", "block")),
        (["License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)"], ("LGPL", "warn")),
        (["AGPL-3.0"], ("AGPL", "block")),
        (["License :: OSI Approved :: GNU Affero General Public License v3"], ("AGPL", "block")),
        (["MPL-2.0"], ("MPL", "warn")),
        (["MPL-2.0 AND MIT"], ("MPL", "warn")),
        (["License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)"], ("MPL", "warn")),
        (["EPL-2.0"], ("EPL", "warn")),
        (["SSPL-1.0"], ("SSPL", "block")),
        (["CC-BY-SA-4.0"], ("CC-BY-SA", "block")),
        (["License :: OSI Approved :: Common Development and Distribution License 1.0 (CDDL-1.0)"], ("CDDL", "warn")),
    ]
    failures = 0
    for signals, expected in cases:
        got = classify(signals)
        ok = got == expected
        if not ok:
            failures += 1
        print(f"  {'ok ' if ok else 'FAIL'}  {signals} -> {got!r} (expected {expected!r})")
    print(f"\n{'ALL PASS' if not failures else f'{failures} FAILURE(S)'}")
    return 1 if failures else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--selftest", action="store_true", help="test the classifier on synthetic inputs and exit")
    args = ap.parse_args()
    return selftest() if args.selftest else scan()


if __name__ == "__main__":
    sys.exit(main())
