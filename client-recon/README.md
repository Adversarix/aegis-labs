# client-recon

Derive confidence-scored **claims** about a web client — spoofed self-report,
headless/automation, hardened-privacy browser, datacenter origin — from a bundle
of browser-side and edge-observed signals. Built for **detection measurement**:
run it over logged client telemetry to cluster and triage who is misrepresenting
themselves, and how confidently you can say so.

It is the defensive inverse of a fingerprinting recon page. The same signals an
attacker's landing page collects to profile and target a visitor are the signals
a defender uses to catch a bot, a spoofed User-Agent, or a headless crawler. This
module keeps the collection contract but points it at detection.

## Model

Three concepts, one contract (`lib/signals.js`):

- **Signal** — a raw measurement. Client-supplied signals are attacker-
  controllable; edge-observed signals are merely harder to forge. Detectors
  encode that asymmetry.
- **Claim** — a plain-English assertion derived from signals, carrying a
  `confidence` (`certain` / `likely` / `guess`), a `weight` (0–10), the
  `evidence` it rests on, and a one-line `how`. Findings are auditable.
- **Score / verdict** — `analyze()` folds claims into a 0–100 anomaly score and
  a coarse verdict (`clean` → `anomalous` → `suspect` → `adversarial`). A single
  *certain*, high-weight claim (e.g. `navigator.webdriver`) hard-sets
  `adversarial` regardless of the sum.

The strongest detectors are **cross-checks** between the client's story and the
edge's observation — a spoofed UA is cheap, but making the TLS stack, header
order, geo-IP, and timezone all agree with the lie is not.

## Detector families

| File | Catches | Examples |
|------|---------|----------|
| `lib/lies.js` | Self-report inconsistency | UA OS vs `navigator.platform`, JS-UA vs wire-UA, browser timezone vs geo-IP, `navigator.language` vs `Accept-Language`, impossible screen geometry, patched natives |
| `lib/headless.js` | Automation / headless | `navigator.webdriver`, `HeadlessChrome` token, missing `window.chrome`, empty `languages`, SwiftShader/llvmpipe WebGL, permissions desync, zero outer viewport |
| `lib/edge.js` | Passive, server-side | Datacenter/hosting ASN, TLS < 1.2, protocol downgrade, missing browser headers, missing Client Hints, plus a JA4-adjacent transport fingerprint |

`edgeFingerprint()` hashes the stable shape of a connection (TLS version + cipher
+ ClientHello length + header order) into a short cluster key. It is a clustering
aid over what an edge Worker readily exposes, **not** a substitute for a JA4
computed from the raw ClientHello bytes.

## Bundle shape

`analyze()` takes `{ client, edge }`. Every field is optional — a detector that
lacks its inputs simply stays silent. `client.*` is whatever a browser snippet
reports (`navigator`, `screen`, WebGL, timezone, permissions); `edge.*` matches
the request context a proxy/CDN sees (geo, ASN/org, TLS parameters, HTTP
protocol, header order). See `fixtures/` for complete, synthetic examples.

## Collecting the bundle

You don't have to build the bundle by hand — `collect/` ships both halves:

- `collect/client.js` → `collectClient()` runs in the browser and returns the
  `client` object (best-effort, never throws, async for Client Hints).
- `collect/edge.js` → `edgeContext({ headers, cf })` runs on your server/edge and
  returns the `edge` object from the request headers plus a Cloudflare-style
  connection context. Accepts a WHATWG `Headers` instance or a plain object.

The browser POSTs its half; the server builds the edge half from the same request
and runs `analyze()` — the client never sees the verdict. See
[`collect/README.md`](./collect/) for the end-to-end wiring.

## Usage

```js
import { analyze } from "./lib/index.js";

const result = analyze(bundle);
// -> { verdict, score, hard, fingerprint, categories, claims[] }
if (result.verdict === "adversarial") gate(result.claims);
```

Or from the shell, for offline analysis of a captured bundle — the exit code
doubles as a gate (`1` when anything scores adversarial):

```bash
node bin/client-recon.js fixtures/headless-puppeteer.json
cat captured.json | node bin/client-recon.js --json
```

## Tests

```bash
node client-recon.test.mjs
```

Pure functions, three synthetic fixtures (honest Chrome, headless Puppeteer,
spoofed UA), and a CLI subprocess check. No dependencies, no network, no real
user data.

## Provenance & scope

This is an original, clean-room implementation. The *techniques* it encodes
(UA/platform cross-checks, headless tells, TLS/header fingerprinting) are
standard, publicly documented browser-fingerprinting methods; the code here was
written from that shared knowledge, not copied from any specific project. It
carries the repository's inbound=outbound license (Apache-2.0 OR MIT).

Intended for **authorized** defensive use — analyzing your own traffic, bot and
fraud triage, and detection research. Fingerprinting client telemetry has privacy
implications; apply it to data you are authorized to collect and analyze.
