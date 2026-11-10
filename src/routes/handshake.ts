import { randomBytes } from "node:crypto";
import { SignJWT } from "jose";
import type { RouteContext, Store } from "../framework/index.js";
import { clerkApiTokenVersion, clerkError, isAuthResponse, requireSecretKey, resolvePrimaryOrgClaims } from "../route-helpers.js";
import { getClerkStore } from "../store.js";
import { createSessionToken, keyPairPromise } from "./oauth.js";
import {
  CLIENT_UAT_COOKIE,
  DEV_BROWSER_PARAM,
  SESSION_COOKIE,
  TEN_YEARS,
  activeSessionsForClient,
  clientUat,
  cookieWithSuffix,
  resolveClient,
  writeClientCredentials,
  type ResolvedClient,
} from "./fapi-client.js";

// The handshake is how the backend SDKs (clerkMiddleware, authenticateRequest)
// get fresh auth cookies when the ones on the app's domain are missing or
// stale. The SDK redirects the browser here; FAPI works out the browser's
// client, then redirects back with the cookies to set, either as a nonce the
// SDK swaps for them via the Backend API (`format=nonce`) or as a signed JWT
// (`__clerk_handshake`).

const NONCE_TTL_MS = 5 * 60 * 1000;

type PendingHandshake = { directives: string[]; expiresAt: number };

function getNonces(store: Store): Map<string, PendingHandshake> {
  let map = store.getData<Map<string, PendingHandshake>>("clerk.handshake.nonces");
  if (!map) {
    map = new Map();
    store.setData("clerk.handshake.nonces", map);
  }
  return map;
}

export function handshakeRoutes({ app, store, baseUrl, tokenMap }: RouteContext): void {
  const cs = getClerkStore(store);

  app.get("/v1/client/handshake", async (c) => {
    const redirectParam = c.req.query("redirect_url");
    let redirectUrl: URL;
    try {
      redirectUrl = new URL(redirectParam ?? "");
    } catch {
      return clerkError(c, 400, "form_param_format_invalid", "redirect_url must be an absolute URL");
    }

    // The backend SDK needs a dev browser token for development keys. A
    // browser without one still has a client: clerk-js only runs a dev browser
    // when the key's Frontend API is a Clerk dev domain (*.accounts.dev), and
    // otherwise keeps the `__client` cookie like a production browser. So find
    // the client by whatever the browser carries and hand its token back as
    // the dev browser token.
    const reason = c.req.query("__clerk_hs_reason") ?? "";
    const isDevelopment = !!c.req.query(DEV_BROWSER_PARAM) || reason.startsWith("dev-browser");
    const resolved: ResolvedClient = resolveClient(c, store);
    const client = resolved.client;

    const suffixed = c.req.query("suffixed_cookies") === "true";
    const secure = redirectUrl.protocol === "https:";
    const cookie = (name: string, value: string, maxAge?: number) =>
      cookieWithSuffix(store, name, value, { secure, maxAge }, suffixed);

    const directives: string[] = [];
    const sessions = activeSessionsForClient(store, client);
    const session = sessions.find((s) => s.clerk_id === client.last_active_session_id) ?? sessions[0];
    const user = session ? cs.users.findOneBy("clerk_id", session.user_id) : undefined;
    if (session && user) {
      const jwt = await createSessionToken(
        store,
        user,
        session.clerk_id,
        baseUrl,
        resolvePrimaryOrgClaims(cs, user),
        clerkApiTokenVersion(c),
      );
      directives.push(...cookie(SESSION_COOKIE, jwt));
    } else {
      directives.push(...cookie(SESSION_COOKIE, "", 0));
    }
    directives.push(...cookie(CLIENT_UAT_COOKIE, String(clientUat(store, client)), TEN_YEARS));
    if (isDevelopment) directives.push(...cookie(DEV_BROWSER_PARAM, client.token, TEN_YEARS));

    if (c.req.query("format") === "nonce") {
      const nonce = randomBytes(18).toString("base64url");
      getNonces(store).set(nonce, { directives, expiresAt: Date.now() + NONCE_TTL_MS });
      redirectUrl.searchParams.set("__clerk_handshake_nonce", nonce);
    } else {
      const { privateKey, kid } = await keyPairPromise;
      const token = await new SignJWT({ handshake: directives })
        .setProtectedHeader({ alg: "RS256", kid, typ: "JWT" })
        .setIssuedAt()
        .setExpirationTime("5m")
        .sign(privateKey);
      redirectUrl.searchParams.set("__clerk_handshake", token);
    }

    // A production browser's own client cookie lives on FAPI's origin, which
    // behind a same-origin proxy is the app's, so it rides on this redirect.
    if (resolved.transport === "cookie") writeClientCredentials(c, store, resolved);
    c.header("Cache-Control", "no-store");
    return c.redirect(redirectUrl.toString(), 307);
  });

  // Backend API: swap a handshake nonce for the cookie directives.
  app.get("/v1/clients/handshake_payload", (c) => {
    const auth = requireSecretKey(c, tokenMap);
    if (isAuthResponse(auth)) return auth;

    const nonces = getNonces(store);
    const now = Date.now();
    for (const [key, pending] of nonces) if (pending.expiresAt < now) nonces.delete(key);

    const pending = nonces.get(c.req.query("nonce") ?? "");
    if (!pending) return clerkError(c, 404, "resource_not_found", "Handshake nonce not found or expired");
    return c.json({ object: "handshake_payload", directives: pending.directives });
  });
}
