---
"clerk-emulator": minor
---

Make the emulator work behind `@clerk/nextjs`'s `clerkMiddleware`:

- Each browser or native app gets its own FAPI client, identified by its dev browser token, a `__client` cookie or the `Authorization` header, instead of one global client holding every session.
- Implement the handshake (`GET /v1/client/handshake`, nonce and token formats, and `GET /v1/clients/handshake_payload`), with Clerk's suffixed cookie names.
- Set `__client_uat` (and `__clerk_db_jwt` for development keys) on FAPI responses.
- Derive the signing key's `kid` from the key, so SDKs refetch JWKS after the emulator restarts instead of rejecting tokens.
- Sign webhooks with Svix headers for `whsec_` secrets, and wrap events in Clerk's envelope.
- CLI: `--seed <file>` / `CLERK_SEED`, `CLERK_PUBLISHABLE_KEY`, `CLERK_WEBHOOK_URL` / `CLERK_WEBHOOK_SECRET`.
- Sign in with a username as well as an email address; add the `end` and `remove` session actions.
