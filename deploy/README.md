# Deployment configuration

## One deployment, not two

`vercel.json` **always overrides dashboard settings**, and a repository can
only have one. Two Vercel projects reading the same repository therefore read
the same config and build the same site — configuring the second through its
dashboard silently does nothing.

We hit this in both directions: first both projects served the docs, then both
served the wallet. Neither was a misconfiguration; it is simply what happens
when two projects share one config file.

**So there is one project, serving both:**

```
/                    the wallet
/veyra-sign.html     the offline signer
/veyra-watch.html    the watch-only page
/SHA256SUMS          verification hashes
/docs/               the documentation site
```

Built by `npm run build:public`, which assembles `public/` and then **verifies
it** — that the root is the wallet rather than a redirect, that its CSP carries
a script hash, and that every expected docs page exists. Both deployment
failures we hit would have been caught by checking the output instead of
trusting the config that produced it.

Delete the second Vercel project; it has nothing to build.

## Historical: why `vercel.json` belonged to the WALLET

Vercel **always prefers `vercel.json` over dashboard settings**, and a
repository can only have one. Both Vercel projects read the same file, so
configuring a second project through the dashboard has no effect — it silently
builds whatever `vercel.json` says.

That is why a wallet project can deploy successfully and serve the docs.

The file belongs to the wallet because that is the deployment which needs the
security headers. The docs project is configured through its dashboard.

| Project | Configured by | Build command | Output |
| --- | --- | --- | --- |
| Wallet | `vercel.json` (root) | `npm run standalone && …` | `public` |
| Docs | Dashboard | `npm run docs:build && npm run site:build` | `app/dist-site` |

If one project ever serves the other's content, check whether `vercel.json` is
quietly winning.

## ⚠️ `vercel.json` rejects unknown keys

Vercel validates the file against a strict schema. A `"//"` key — the usual
JSON-comment convention — fails the build with:

```
should NOT have additional property `//`
```

So there are no comments in that file, and the explanation lives here instead.
`npm run check:vercel` validates the top-level keys before you push.

## Files here

| File | Purpose |
| --- | --- |
| `vercel-docs.json` | The docs project's settings, for reference. Not read by Vercel |
| `vercel-standalone.json` | Alternative wallet config, if you deploy it as its own repo |
| `fly.toml` | Fly.io — the watch-only API |
| `render.yaml` | Render — the watch-only API |
| `docker-compose.yml` | Local watch-only API |
