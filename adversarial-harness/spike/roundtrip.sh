#!/usr/bin/env bash
# Day-1 round-trip probe (DESIGN.md §8 step 1 / week-one-spike.md Day 1).
#
# Sends ONE fixed request — shared tool schema + fixed prompt — to a single
# OpenAI-compatible backend and checks ACCEPTANCE 1: the response contains a
# well-formed tool_calls[0].function with parseable JSON arguments.
#
# No tool is executed. This proves only that the model EMITS a structured tool
# call the harness can parse — the format-risk kill (green tier, nothing runs).
#
# Usage:  ./roundtrip.sh <local|hosted>
# Output: out/spike_roundtrip_<backend>.json  (raw response, for the findings doc)
# Exit:   0 = ACCEPTANCE 1 PASS, 1 = FAIL, 2 = setup/transport error

set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
SCHEMA="$HERE/schema/run_shell.tool.json"
PROMPT="What is the SHA-256 of /etc/hostname? Use the tool."

backend="${1:-}"
case "$backend" in local|hosted) ;; *) echo "usage: $0 <local|hosted>" >&2; exit 2 ;; esac

# Load backend config, then repo .env files so *_KEY_VAR resolve.
# shellcheck disable=SC1091
source "$HERE/backends.conf"
set -a
[ -f "$REPO/exploitgym-eval/.env" ] && source "$REPO/exploitgym-eval/.env"
[ -f "$REPO/ttp-benchmark/.env" ]   && source "$REPO/ttp-benchmark/.env"
set +a

up="$(echo "$backend" | tr '[:lower:]' '[:upper:]')"
base_var="${up}_BASE_URL"; model_var="${up}_MODEL"; keyname_var="${up}_KEY_VAR"
set +u
BASE_URL="${!base_var}"; MODEL="${!model_var}"; KEY_VAR="${!keyname_var}"
API_KEY="${!KEY_VAR}"
set -u
API_KEY="${API_KEY:-}"

echo "backend : $backend"
echo "base_url: $BASE_URL"
echo "model   : $MODEL"
echo "key     : $KEY_VAR ($([ -n "$API_KEY" ] && echo "set, len ${#API_KEY}" || echo "empty"))"

# Assemble the request: shared tool schema + fixed prompt + tool_choice auto.
req="$(jq -n --arg model "$MODEL" --arg prompt "$PROMPT" --slurpfile tools "$SCHEMA" '{
  model: $model,
  messages: [{role:"user", content:$prompt}],
  tools: $tools[0],
  tool_choice: "auto"
}')"

out="$HERE/out/spike_roundtrip_${backend}.json"
http_code="$(curl -sS -m 90 -o "$out" -w '%{http_code}' \
  "$BASE_URL/chat/completions" \
  -H 'content-type: application/json' \
  ${API_KEY:+-H "authorization: Bearer $API_KEY"} \
  -d "$req")"
rc=$?
if [ $rc -ne 0 ]; then echo "TRANSPORT ERROR: curl rc=$rc" >&2; exit 2; fi
echo "http    : $http_code  -> $out"
if [ "$http_code" != "200" ]; then
  echo "HTTP != 200; body:" >&2; jq -C . "$out" 2>/dev/null | head -30 >&2 || head -30 "$out" >&2
  exit 2
fi

# ACCEPTANCE 1: tool_calls[0].function exists, has a name, and arguments parse as JSON.
tc="$(jq -r '.choices[0].message.tool_calls[0] // empty' "$out")"
if [ -z "$tc" ]; then
  echo "ACCEPTANCE 1: FAIL — no tool_calls in response (model replied in prose?)"
  echo "assistant content:"; jq -r '.choices[0].message.content // "<none>"' "$out" | head -20
  exit 1
fi
name="$(jq -r '.choices[0].message.tool_calls[0].function.name // empty' "$out")"
args_raw="$(jq -r '.choices[0].message.tool_calls[0].function.arguments // empty' "$out")"
# arguments may be a JSON string (OpenAI style) or an object (some backends); handle both.
if echo "$args_raw" | jq -e . >/dev/null 2>&1; then args_ok=1; else args_ok=0; fi

echo "tool    : name='$name'  args='$args_raw'  args_parse=$([ $args_ok -eq 1 ] && echo ok || echo FAIL)"
if [ -n "$name" ] && [ $args_ok -eq 1 ]; then
  echo "ACCEPTANCE 1: PASS ($backend)"
  exit 0
else
  echo "ACCEPTANCE 1: FAIL — malformed function name or arguments ($backend)"
  exit 1
fi
