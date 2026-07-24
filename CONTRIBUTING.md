# Contributing to AEGIS Labs

Thanks for your interest. AEGIS Labs is the open home for security research
released by the Adversarix project — benchmarks, evaluation harnesses, and
research tooling. Capabilities are developed here as research products first;
some learnings are later absorbed into the commercial Adversarix product. The
permissive licensing below is what makes that flow work in both directions.

## Licensing of contributions

Code in this repository is dual-licensed under either the
[Apache License 2.0](./LICENSE-APACHE) or the [MIT License](./LICENSE-MIT), at
the user's option.

**Unless you explicitly state otherwise, any contribution you intentionally
submit for inclusion in this repository shall be dual-licensed as above (Apache
2.0 OR MIT), with no additional terms or conditions.** This "inbound = outbound"
model means a contribution carries the same permissive license as the project,
including the right to use it commercially — so contributions may be
incorporated into Adversarix or other products consistent with those licenses.

We do **not** require a separate Contributor License Agreement (CLA). Instead we
use the Developer Certificate of Origin (see below).

## Sign your work — Developer Certificate of Origin (DCO)

Every commit must be signed off, certifying that you wrote the code or otherwise
have the right to submit it under the project's license. The full text is in the
[`DCO`](./DCO) file (Developer Certificate of Origin 1.1).

Sign off by adding a `Signed-off-by` trailer to each commit — `git` does this
for you with `-s`:

```bash
git commit -s -m "Your commit message"
```

This appends a line using your real name and the email in your `git` config:

```
Signed-off-by: Jane Developer <jane@example.com>
```

Use a real identity (pseudonyms and anonymous contributions can't certify
origin). To fix commits that are missing a sign-off:

```bash
git commit --amend -s            # the most recent commit
git rebase --signoff main        # a range of commits on your branch
```

## How to contribute

1. **Open an issue first** for anything non-trivial, so we can align on approach
   before you invest effort.
2. **Fork and branch** from `main`.
3. **Make focused changes** with signed-off commits (`-s`).
4. **Add or update tests** and make sure existing ones pass (see below).
5. **Open a pull request** against `main`.

`main` is protected: PRs require a passing CI run, one approving review,
resolved conversations, and an up-to-date branch before merge. Direct pushes and
force-pushes to `main` are blocked.

## Development and tests

Each project is self-contained under its own directory. Prefer the standard
library and permissively licensed dependencies. Run a project's tests before
opening a PR — for example:

```bash
cd exploitgym-eval && pip install -r requirements.txt && python tests/test_aggregate.py
```

CI (`.github/workflows/ci.yml`) syntax-checks all tracked Python and runs the
project unit tests on every PR. Match the style, naming, and comment density of
the surrounding code.

## Dependency licensing

To keep this code cleanly reusable — including absorption into downstream
products — **only add dependencies under permissive licenses** (MIT, Apache-2.0,
BSD, ISC, and similar). Do **not** introduce copyleft dependencies (GPL, LGPL,
AGPL, MPL, or similar) without prior discussion in an issue; a copyleft
dependency can impose obligations on everything that links against it.

## Keep the boundary clean

This repository is public and permissively licensed. Do not commit:

- proprietary or confidential code (including internal Adversarix code),
- secrets, API keys, credentials, or customer/production data,
- material you do not have the right to release under Apache-2.0 / MIT.

## Responsible research

Several projects here are offensive-security research tools (exploit-development
harnesses, TTP extraction, attack-chain analysis) intended for **authorized**
testing, CTF, defensive research, and education. When contributing:

- exercise capabilities only against sandboxed or self-owned targets and the
  benchmarks' own fixtures — never against third-party systems without
  authorization;
- do not add working exploits, payloads, or targeting data aimed at real,
  non-consenting systems;
- report security issues in this code responsibly per [SECURITY.md](./SECURITY.md)
  rather than in a public issue or PR.

## Questions

Open a GitHub issue for anything that isn't a security report. Thanks for
contributing to AEGIS Labs.
