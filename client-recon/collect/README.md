# collect — bundle collectors

Two small, dependency-free collectors that produce the halves `analyze()` consumes.
Neither trusts the other: the client half is the browser's freely-spoofable
self-report, the edge half is what the transport actually observed. Detection
comes from checking one against the other.

- **`client.js`** — runs in the browser, returns the `client` object.
- **`edge.js`** — runs on your server/edge, returns the `edge` object.

## End-to-end wiring

The browser collects its half and POSTs it; the server builds the edge half from
the same request and runs `analyze()`. The client never sees the verdict.

### 1. Browser

```html
<script type="module">
  import { collectClient } from "/client-recon/collect/client.js";

  const client = await collectClient();
  await fetch("/api/attest", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ client }),
  });
</script>
```

`collectClient()` is best-effort and never throws: unsupported probes are simply
omitted. It is async because UA Client Hints and `permissions.query` are
promise-based.

### 2. Server / edge (Cloudflare Pages/Workers shown; any runtime works)

```js
import { edgeContext } from "../client-recon/collect/edge.js";
import { analyze } from "../client-recon/lib/index.js";

export const onRequestPost = async ({ request }) => {
  const { client } = await request.json();
  const edge = edgeContext({ headers: request.headers, cf: request.cf });

  const result = analyze({ client, edge });
  // result: { verdict, score, hard, fingerprint, categories, claims[] }

  if (result.verdict === "adversarial") {
    // log, challenge, or block — your policy. Keep the reasons server-side.
    console.warn("client-recon", result.fingerprint, result.claims.map((c) => c.id));
  }
  return Response.json({ ok: true });
};
```

On Express/Fastify/Hono, pass `{ headers: req.headers, cf }` instead — `edge.js`
accepts a WHATWG `Headers` instance or a plain header object, and any
`cf`-shaped connection context your proxy injects (TLS parameters, ASN/org, geo,
HTTP protocol). Fields it doesn't find are omitted, and their detectors stay
silent.

## Notes

- **Header order** reflects the runtime's header iteration order; some runtimes
  normalize or sort header names, so treat it as a clustering aid, not guaranteed
  wire order. For true JA4 you need the raw ClientHello bytes, which live below
  this layer.
- **`toStringNative`** is derived by sampling live runtime functions for a
  patched `toString`. It is only meaningful against real browser globals; under a
  mock/test environment ordinary JS functions read as non-native.
- Both collectors are exported from the package root too:
  `import { collectClient, edgeContext } from "../lib/index.js"`.
