#!/usr/bin/env bash
# Day-1 acceptance gate (week-one-spike.md Day 1): the SAME tool schema must
# round-trip on BOTH a local and a hosted backend. Neutrality is a day-one
# property — one backend passing is not enough; both must pass.

set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "############## Day 1 — round-trip: LOCAL ##############"
bash "$HERE/roundtrip.sh" local;  local_rc=$?
echo
echo "############## Day 1 — round-trip: HOSTED #############"
bash "$HERE/roundtrip.sh" hosted; hosted_rc=$?

echo
echo "===================== VERDICT ========================"
echo "local  : $([ $local_rc  -eq 0 ] && echo PASS || echo FAIL)"
echo "hosted : $([ $hosted_rc -eq 0 ] && echo PASS || echo FAIL)"
if [ $local_rc -eq 0 ] && [ $hosted_rc -eq 0 ]; then
  echo "ACCEPTANCE 1 (neutrality: both backends): PASS — proceed to Day 2 (fork bake-off)."
  exit 0
fi
echo "ACCEPTANCE 1: FAIL — format/neutrality risk surfaced on day one."
echo "Fix path (week-one-spike.md Day 1): adjust the failing backend's tool-call"
echo "flags/template or the abstraction's normalization, or drop to a smaller"
echo "known-good tool-calling model. Do not proceed until BOTH pass."
exit 1
