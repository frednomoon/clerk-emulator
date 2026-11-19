<p align="center">
  <img src="https://raw.githubusercontent.com/pjsny/clerk-emulator/main/assets/banner.png" alt="clerk-emulator — local, offline, in-memory" width="820" />
</p>

<p align="center">
  <a href="https://github.com/pjsny/clerk-emulator/actions/workflows/ci.yml"><img src="https://github.com/pjsny/clerk-emulator/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
  <a href="https://www.npmjs.com/package/clerk-emulator"><img src="https://img.shields.io/npm/v/clerk-emulator" alt="npm" /></a>
  <a href="./LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue.svg" alt="License: Apache-2.0" /></a>
  <a href="https://socket.dev/npm/package/clerk-emulator"><img src="https://socket.dev/api/badge/npm/package/clerk-emulator" alt="Socket" /></a>
</p>

# clerk-emulator

A local, offline emulator for [Clerk](https://clerk.com)'s Backend API (BAPI) and Frontend API (FAPI). Develop and test Clerk auth with no network, no cloud instance, and no rate limits — it signs real JWTs, so `@clerk/backend` and `clerk-js` work against it unmodified. Built on [Hono](https://hono.dev); state is in-memory and resets every run.

## Install

```bash
npm install --save-dev clerk-emulator
```

## Quick start

Run the server:

```bash
npx clerk-emulator
# Backend API:  http://localhost:4000
# Secret key:   sk_test_emulate
```

Configure via env: `PORT`, `HOST`, `CLERK_SECRET_KEY`, `CLERK_MACHINE_KEY`, `CLERK_PUBLISHABLE_KEY`, `CLERK_USERNAME_REQUIRED`. Add `--persist <file>` (or `CLERK_PERSIST`) to keep state across restarts, and `--seed <file>` (or `CLERK_SEED`) to seed from a JSON [`ClerkSeedConfig`](./src/index.ts) instead of the default fixtures:

```json
{
  "users": [
    {
      "clerk_id": "user_2f6K9jIXfKxKKJGpSlfHqpm5x95",
      "username": "dev",
      "email_addresses": ["dev@example.com"],
      "password": "supersecret123",
      "public_metadata": { "role": "admin" }
    }
  ],
  "webhooks": [{ "url": "http://localhost:3000/api/webhooks/clerk", "secret": "whsec_..." }]
}
```

`CLERK_PUBLISHABLE_KEY` should be the key your app uses (default `pk_test_ZW11bGF0ZS5leGFtcGxlLmNvbSQ`): Clerk names cookies with a suffix derived from it, so the cookies the emulator sets only line up when it matches. Webhooks with a `whsec_` secret are signed with Svix headers like Clerk's, so `verifyWebhook` and `svix` accept them; `CLERK_WEBHOOK_URL` + `CLERK_WEBHOOK_SECRET` register one from the environment.

Point the backend SDK at it:

```ts
import { createClerkClient } from "@clerk/backend";

const clerk = createClerkClient({ secretKey: "sk_test_emulate", apiUrl: "http://localhost:4000" });
await clerk.users.createUser({ emailAddress: ["dev@example.com"], password: "supersecret123" });
```

Or run it in-process for tests (no separate server):

```ts
import { createServer, clerkPlugin } from "clerk-emulator";

const { app } = createServer(clerkPlugin, {
  tokens: { sk_test_emulate: { login: "admin", id: 1, scopes: [] } },
});
const res = await app.request("/v1/users", { headers: { Authorization: "Bearer sk_test_emulate" } });
```

`app` is a [Hono](https://hono.dev) app — call `app.request(...)` in-memory, or `serve({ fetch: app.fetch, port })` (`@hono/node-server`) to bind a port.

Point the frontend (clerk-js) at it: set a **relative** `proxyUrl` so clerk-js sends Frontend API calls to a path your dev server forwards to the emulator (clerk-js forces `https` on _absolute_ proxy URLs, so it must be relative). Pin `clerkJSVersion` to skip the floating `@<major>` CDN redirect.

```tsx
// React entry
<ClerkProvider publishableKey="pk_test_..." proxyUrl="/__clerk" clerkJSVersion="6.17.0">
```

```ts
// vite.config.ts — forward the proxy path to the emulator
server: {
  proxy: {
    "/__clerk": { target: "http://localhost:4000", changeOrigin: true, rewrite: (p) => p.replace(/^\/__clerk/, "") },
  },
}
```

Vanilla clerk-js is the same idea: `new Clerk(pk, { proxyUrl: "/__clerk" })`. See [`e2e/`](./e2e) for complete React, `@clerk/clerk-react`, and vanilla setups.

### Next.js (`@clerk/nextjs`)

`clerkMiddleware` and `auth()` work against the emulator, including the handshake the middleware uses to refresh missing or stale cookies. Two differences from the client-only setup:

- The proxy URL must be **absolute**: the server resolves a relative one against `window`. As clerk-js upgrades absolute proxy URLs to `https`, run the dev server over https (`next dev --experimental-https`).
- Point the server SDK at the emulator and set your own sign-in page, since the default is Clerk's hosted one.

```bash
# .env.local
CLERK_SECRET_KEY=sk_test_emulate
CLERK_API_URL=http://localhost:4000
NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY=pk_test_ZW11bGF0ZS5leGFtcGxlLmNvbSQ
NEXT_PUBLIC_CLERK_PROXY_URL=https://localhost:3000/__clerk
NEXT_PUBLIC_CLERK_SIGN_IN_URL=/sign-in
```

```js
// next.config.mjs
async rewrites() {
  return [{ source: "/__clerk/:path*", destination: "http://localhost:4000/:path*" }];
},
```

### Clients and sessions

Each browser or app install gets its own client, as with real Clerk, so two browsers can be signed in as different users. The emulator identifies a client the way Clerk does: by the dev browser token clerk-js sends (`__clerk_db_jwt`), the `__client` cookie it sets on its own responses, or, for native apps, the `Authorization` header. Behind a same-origin proxy it also sets `__client_uat` and, for a development key, `__clerk_db_jwt`, so the backend SDKs see a consistent signed-in state.

### Social sign-in (Google, Apple, GitHub)

`signIn.authenticateWithRedirect()` on the web and `useSSO()` in Expo work without real provider credentials. Instead of Google's consent screen, the browser opens the emulator's account picker at `/v1/oauth_emulate/authorize`:

- **An existing account** signs in, and the browser goes to `redirectUrlComplete`, or `redirectUrl` when there is none.
- **A new email** goes back to `redirectUrl` with the sign-in `transferable`, and `signUp.create({ transfer: true })` makes the account. `AuthenticateWithRedirectCallback` does that for you.
- **Cancel** goes back to `redirectUrl` with the sign-in still unverified.

Native redirects carry a `rotating_token_nonce`, as from Clerk. Set `CLERK_USERNAME_REQUIRED=1` to require a username at sign-up, as some instances do: a new OAuth account then stops at `missing_requirements` until `signUp.update({ username })`.

## What's supported

| Capability | Details |
|---|---|
| Users & email addresses | full CRUD, ban / lock, metadata, verify password |
| Organizations | CRUD, memberships, invitations, domains |
| Sessions & tokens | session CRUD, JWT minting, v1/v2 negotiation (`clerk-api-version` / `__clerk_api_version`) |
| M2M tokens | create, verify, revoke |
| OAuth 2.0 / OIDC | authorize, token, userinfo, JWKS |
| Frontend API (FAPI) | sign-in (email or username), MFA (TOTP), sign-up, per-browser and native clients |
| Social sign-in | `oauth_google`, `oauth_apple`, `oauth_github` through an emulated provider page; sign-up transfer |
| Handshake | `GET /v1/client/handshake` (nonce and token formats), `GET /v1/clients/handshake_payload` |
| Webhooks | Clerk-shaped resource events, Svix-signed for `whsec_` secrets |
| Testing tokens | `@clerk/testing` compatible — `POST /v1/testing_tokens`, `__clerk_testing_token` |
| _Out of scope_ | real social providers, linking a provider to a signed-in user, passkeys, SAML / enterprise SSO, multi-session, billing, profile management |

## Compatibility

Verified in CI against:

| Surface | SDK | Versions | Clerk core |
|---|---|---|---|
| Frontend (React) | `@clerk/react` | latest 6.x | Core 3 (Active) |
| Frontend (React) | `@clerk/clerk-react` | latest 5.x | Core 2 (LTS) |
| Frontend (vanilla) | `@clerk/clerk-js` | latest 5.x, 6.x | Core 2 (LTS), Core 3 |
| Backend | `@clerk/backend` | latest 2.x, 3.x | Core 3 |
| Full stack | `@clerk/nextjs` | 6.x (manually, sign-in through `clerkMiddleware` and `auth()`) | Core 2 |
| Runtime | Node.js | 20, 22, 24 | — |

Not yet tested: `@clerk/backend` 0.x (Core 2 LTS, pre-Core-3 API). `@clerk/nextjs` has no CI cell yet.

## Tests

```bash
npm test             # unit + integration (Node, against a real server)
cd e2e && npm test   # browser e2e (Playwright, real clerk-js)
```

| Layer | Covers |
|---|---|
| Browser e2e — Playwright + clerk-js | sign-in (password / email-code / MFA-TOTP), sign-up, org listing |
| SDK e2e — `@clerk/backend` over HTTP | admin lifecycle: users, organizations, memberships, invitations, domains, M2M |
| HTTP integration — raw requests | OAuth / OIDC, webhooks, session-token v1/v2 negotiation |

Browser e2e and the backend SDK run across the version matrix in [Compatibility](#compatibility). See [`docs/testing.md`](./docs/testing.md) for Playwright/Cypress (`@clerk/testing`), backend-SDK, and in-process setups.

## License & attribution

[Apache-2.0](./LICENSE). The framework under `src/framework/` is adapted from [`vercel-labs/emulate`](https://github.com/vercel-labs/emulate) (Apache-2.0) with its HTTP layer swapped for Hono — see [`NOTICE`](./NOTICE).

"Clerk" is a trademark of Clerk, Inc. This is an independent, unofficial tool — not affiliated with, endorsed by, or sponsored by Clerk, Inc.
