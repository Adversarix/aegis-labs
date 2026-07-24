# Security Policy

AEGIS Labs publishes security research tooling. This policy covers two things:
how to **report a vulnerability in AEGIS Labs' own code**, and the **intended
use** of these dual-use tools.

## Reporting a vulnerability in this code

If you discover a security vulnerability in code published in this repository
(for example, a way the harness could be made to execute untrusted input outside
its sandbox, a credential-handling flaw, or a supply-chain issue), please report
it **privately** — do not open a public issue or pull request.

Preferred channel:

- **GitHub private vulnerability reporting** — use the repository's
  *Security → Report a vulnerability* button (GitHub Security Advisories). This
  keeps the report private until a fix is ready.

Alternative channel:

- Email **`aegis-labs-security@proton.me`** with the details below.

Please include:

- a description of the issue and its impact,
- the affected project/path and version or commit,
- steps to reproduce (a minimal proof of concept if possible),
- any suggested remediation.

### What to expect

- **Acknowledgement** within 3 business days.
- An initial **assessment** within 10 business days.
- Coordinated disclosure: we will work with you on a fix and a disclosure
  timeline (target 90 days, sooner where practical), and credit you unless you
  prefer to remain anonymous.

Please give us a reasonable opportunity to remediate before any public
disclosure.

## Supported versions

This is actively developed research code. Security fixes are applied to the
latest `main`. There is no long-term support for older commits or tags; update
to the latest `main` to receive fixes.

## Intended use and scope (dual-use notice)

Several projects here are offensive-security research tools — exploit-development
evaluation harnesses, TTP extraction, and attack-chain analysis. They are
published to advance measurement and defense, and are intended solely for
**lawful, authorized** use: security testing you are permitted to perform, CTF
and benchmark environments, defensive research, and education.

They are **not** intended for, and must not be used for, unauthorized access to
systems you do not own or have explicit permission to test, or any other
unlawful activity. You are responsible for complying with all applicable laws
and for obtaining authorization before testing any system.

### Out of scope for vulnerability reports

The following are working as intended and are **not** vulnerabilities in this
code:

- a tool executing exploit or attack logic against its **own sandboxed targets,
  fixtures, or benchmark environments** — that is its designed function;
- capabilities that require the operator to supply their own targets,
  credentials, or authorization to do anything;
- findings in **third-party dependencies or benchmark datasets** (report those
  upstream), though we welcome a heads-up.

If you are unsure whether something is in scope, report it privately and we will
help triage.
