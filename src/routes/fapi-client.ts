import { createHash, randomBytes } from "node:crypto";
import { getCookie } from "hono/cookie";
import type { Context, AppEnv, Store } from "../framework/index.js";
import { generateClerkId, nowUnix } from "../helpers.js";
import { getClerkStore } from "../store.js";
import type { ClerkClient } from "../entities.js";

// How clerk-js identifies its FAPI client, one per browser or app install:
// - development instances send a dev browser token as `?__clerk_db_jwt=`
// - production instances rely on the HttpOnly `__client` cookie FAPI sets
// - native apps (`?_is_native=1`) send it in `Authorization` and read it back
//   from the response's `Authorization` header
export const DEV_BROWSER_PARAM = "__clerk_db_jwt";
export const CLIENT_COOKIE = "__client";
export const CLIENT_UAT_COOKIE = "__client_uat";
export const SESSION_COOKIE = "__session";

export type ClientTransport = "dev_browser" | "native" | "cookie";

export interface ResolvedClient {
  client: ClerkClient;
  transport: ClientTransport;
  /** The request carried no credentials, so this client was made for it. */
  created: boolean;
}

// The publishable key the emulated instance answers to. Clerk names its cookies
// with a suffix derived from it (`__session_<suffix>`), so FAPI-set cookies only
// line up with the SDKs when this matches the key the app is configured with.
export const DEFAULT_PUBLISHABLE_KEY = "pk_test_ZW11bGF0ZS5leGFtcGxlLmNvbSQ";

export interface ClerkEmulatorConfig {
  publishableKey: string;
}

const CONFIG_KEY = "clerk.config";

export function setEmulatorConfig(store: Store, config: Partial<ClerkEmulatorConfig>): void {
  store.setData(CONFIG_KEY, { ...getEmulatorConfig(store), ...config });
}

export function getEmulatorConfig(store: Store): ClerkEmulatorConfig {
  return store.getData<ClerkEmulatorConfig>(CONFIG_KEY) ?? { publishableKey: DEFAULT_PUBLISHABLE_KEY };
}

/** Mirrors `getCookieSuffix` in @clerk/shared: first 8 chars of base64(sha1(pk)), URL-safe. */
export function cookieSuffix(publishableKey: string): string {
  return createHash("sha1")
    .update(publishableKey)
    .digest("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .substring(0, 8);
}

export function createClient(store: Store, token?: string): ClerkClient {
  const cs = getClerkStore(store);
  const now = nowUnix();
  return cs.clients.insert({
    client_id: generateClerkId("client_"),
    token: token ?? `dvb_${randomBytes(24).toString("base64url")}`,
    last_active_session_id: null,
    created_at_unix: now,
    updated_at_unix: now,
  });
}

function findOrCreateClient(store: Store, token: string | undefined): { client: ClerkClient; created: boolean } {
  if (!token) return { client: createClient(store), created: true };
  // An unknown token (e.g. after the emulator restarted) adopts the token rather
  // than failing, so the browser keeps working without clearing cookies.
  const existing = getClerkStore(store).clients.findOneBy("token", token);
  return { client: existing ?? createClient(store, token), created: false };
}

/** Works out which client a FAPI request belongs to, creating one if it has none. */
export function resolveClient(c: Context<AppEnv>, store: Store): ResolvedClient {
  if (c.req.query("_is_native")) {
    const header = c.req.header("Authorization")?.replace(/^Bearer\s+/i, "").trim();
    return { ...findOrCreateClient(store, header || undefined), transport: "native" };
  }

  const devBrowser = c.req.query(DEV_BROWSER_PARAM);
  if (devBrowser) {
    return { ...findOrCreateClient(store, devBrowser), transport: "dev_browser" };
  }

  return { ...findOrCreateClient(store, getCookie(c, CLIENT_COOKIE)), transport: "cookie" };
}

/**
 * Resolves the client for a request that continues a sign-in or sign-up. A
 * request with no credentials (curl, server-side tests) carries on as the
 * client that started the flow instead of becoming a new, empty one.
 */
export function resolveFlowClient(c: Context<AppEnv>, store: Store, flowClient: ClerkClient): ResolvedClient {
  const resolved = resolveClient(c, store);
  if (!resolved.created) return resolved;
  getClerkStore(store).clients.delete(resolved.client.id);
  return { client: flowClient, transport: resolved.transport, created: false };
}

/** Current state of a client, re-read so callers see writes made since resolving it. */
export function reloadClient(store: Store, client: ClerkClient): ClerkClient {
  return getClerkStore(store).clients.findOneBy("client_id", client.client_id) ?? client;
}

/**
 * Records a change to the client. `updated_at` feeds `__client_uat`, which the
 * backend SDKs compare to the session token's `iat`, so it must only move when
 * the client's sign-in state actually changes.
 */
export function touchClient(store: Store, client: ClerkClient, patch: Partial<ClerkClient> = {}): ClerkClient {
  const cs = getClerkStore(store);
  return cs.clients.update(client.id, { ...patch, updated_at_unix: nowUnix() }) ?? client;
}

export function activeSessionsForClient(store: Store, client: ClerkClient) {
  return getClerkStore(store)
    .sessions.findBy("client_id", client.client_id)
    .filter((s) => s.status === "active");
}

/** Value of `__client_uat`: when the client last changed, or 0 when signed out. */
export function clientUat(store: Store, client: ClerkClient): number {
  return activeSessionsForClient(store, client).length > 0 ? client.updated_at_unix : 0;
}

export interface CookieOptions {
  secure: boolean;
  maxAge?: number;
  httpOnly?: boolean;
}

export function serializeCookie(name: string, value: string, opts: CookieOptions): string {
  const parts = [`${name}=${value}`, "Path=/", "SameSite=Lax"];
  if (opts.maxAge !== undefined) parts.push(`Max-Age=${opts.maxAge}`);
  if (opts.httpOnly) parts.push("HttpOnly");
  if (opts.secure) parts.push("Secure");
  return parts.join("; ");
}

/** A cookie under its plain name and, when the SDK uses them, its suffixed name. */
export function cookieWithSuffix(
  store: Store,
  name: string,
  value: string,
  opts: CookieOptions,
  suffixed: boolean,
): string[] {
  const cookies = [serializeCookie(name, value, opts)];
  if (suffixed) {
    const suffix = cookieSuffix(getEmulatorConfig(store).publishableKey);
    cookies.push(serializeCookie(`${name}_${suffix}`, value, opts));
  }
  return cookies;
}

const TEN_YEARS = 315360000;

// The emulator usually sits behind the app's dev server (a relative or
// same-origin proxyUrl), so trust the forwarded protocol for the Secure flag.
export function requestIsSecure(c: Context<AppEnv>): boolean {
  const forwarded = c.req.header("x-forwarded-proto");
  if (forwarded) return forwarded.split(",")[0]!.trim() === "https";
  return new URL(c.req.url).protocol === "https:";
}

/**
 * Hands the client's credentials back the way its transport expects. Native
 * apps read `Authorization`; browsers identified by cookie get `__client` and
 * `__client_uat` (plus `__clerk_db_jwt` for a development key). Dev browsers
 * get nothing: clerk-js keeps their token and `__client_uat` cookies itself.
 */
export function writeClientCredentials(c: Context<AppEnv>, store: Store, resolved: ResolvedClient): void {
  const client = reloadClient(store, resolved.client);
  if (resolved.transport === "native") {
    c.header("Authorization", client.token);
    c.header("Access-Control-Expose-Headers", "Authorization");
    return;
  }
  if (resolved.transport !== "cookie") return;

  const secure = requestIsSecure(c);
  const cookies = [
    serializeCookie(CLIENT_COOKIE, client.token, { secure, maxAge: TEN_YEARS, httpOnly: true }),
    ...cookieWithSuffix(store, CLIENT_UAT_COOKIE, String(clientUat(store, client)), { secure, maxAge: TEN_YEARS }, true),
  ];
  // With a development key the backend SDKs treat any request without a dev
  // browser token as signed out, and only document requests can recover via a
  // handshake. clerk-js runs no dev browser unless the key's Frontend API is a
  // Clerk dev domain, so give the browser its token here, as a dev browser would.
  if (getEmulatorConfig(store).publishableKey.startsWith("pk_test_")) {
    cookies.push(...cookieWithSuffix(store, DEV_BROWSER_PARAM, client.token, { secure, maxAge: TEN_YEARS }, true));
  }
  for (const cookie of cookies) c.header("Set-Cookie", cookie, { append: true });
}

export { TEN_YEARS };
