import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createClerkClient } from "@clerk/backend";
import { verifyWebhook } from "@clerk/backend/webhooks";
import { decodeJwt } from "jose";
import { cookieSuffix, setEmulatorConfig, DEFAULT_PUBLISHABLE_KEY } from "../index.js";
import { svixSignature } from "../framework/index.js";
import { clerkTestSecretKey, startClerkTestEmulator, type ClerkTestEmulator } from "./helpers.js";

const APP_URL = "https://app.example.test/dashboard";
// pk_live_ + base64("clerk.app.example.test$")
const LIVE_PUBLISHABLE_KEY = `pk_live_${Buffer.from("clerk.app.example.test$").toString("base64").replace(/=+$/, "")}`;

/** Minimal cookie jar: what a browser would hold for one origin. */
class Jar {
  cookies = new Map<string, string>();

  store(res: Response | string[]): void {
    const setCookies = Array.isArray(res) ? res : res.headers.getSetCookie();
    for (const raw of setCookies) {
      const [pair, ...attrs] = raw.split(";").map((p) => p.trim());
      const eq = pair!.indexOf("=");
      const name = pair!.slice(0, eq);
      const value = pair!.slice(eq + 1);
      const expired = attrs.some((a) => a.toLowerCase() === "max-age=0");
      if (expired || value === "") this.cookies.delete(name);
      else this.cookies.set(name, value);
    }
  }

  header(): string {
    return [...this.cookies].map(([k, v]) => `${k}=${v}`).join("; ");
  }
}

async function fapi(
  emulator: ClerkTestEmulator,
  path: string,
  opts: { jar?: Jar; query?: Record<string, string>; body?: Record<string, string>; headers?: Record<string, string> } = {},
) {
  const url = new URL(path, emulator.url);
  for (const [k, v] of Object.entries(opts.query ?? {})) url.searchParams.set(k, v);
  const res = await fetch(url, {
    method: opts.body ? "POST" : "GET",
    redirect: "manual",
    headers: {
      ...(opts.body ? { "Content-Type": "application/x-www-form-urlencoded" } : {}),
      ...(opts.jar?.cookies.size ? { Cookie: opts.jar.header() } : {}),
      ...opts.headers,
    },
    body: opts.body ? new URLSearchParams(opts.body).toString() : undefined,
  });
  opts.jar?.store(res);
  return res;
}

async function signInWithPassword(
  emulator: ClerkTestEmulator,
  opts: { jar?: Jar; query?: Record<string, string>; headers?: Record<string, string> },
) {
  const res = await fapi(emulator, "/v1/client/sign_ins", {
    ...opts,
    body: { identifier: "alice@example.com", password: "alice123" },
  });
  expect(res.ok).toBe(true);
  return (await res.json()) as {
    response: { created_session_id: string };
    client: { id: string; sessions: Array<{ id: string }>; updated_at: number };
  };
}

function documentRequest(url: string, jar?: Jar) {
  return new Request(url, {
    headers: {
      "Sec-Fetch-Dest": "document",
      Accept: "text/html",
      ...(jar?.cookies.size ? { Cookie: jar.header() } : {}),
    },
  });
}

describe("Clerk plugin - per-client FAPI state", () => {
  let emulator: ClerkTestEmulator;

  beforeAll(async () => {
    emulator = await startClerkTestEmulator();
  });

  afterAll(async () => {
    await emulator?.close();
  });

  it("keeps each browser's sessions to itself", async () => {
    const alice = new Jar();
    const other = new Jar();
    const signedIn = await signInWithPassword(emulator, { jar: alice });
    expect(signedIn.client.sessions).toHaveLength(1);

    const res = await fapi(emulator, "/v1/client", { jar: other });
    const { response: otherClient } = (await res.json()) as { response: { id: string; sessions: unknown[] } };
    expect(otherClient.sessions).toHaveLength(0);
    expect(otherClient.id).not.toBe(signedIn.client.id);
  });

  it("sets __client and __client_uat for production browsers", async () => {
    const jar = new Jar();
    await fapi(emulator, "/v1/environment", { jar });
    const suffix = cookieSuffix(DEFAULT_PUBLISHABLE_KEY);
    expect(jar.cookies.get("__client")).toBeTruthy();
    expect(jar.cookies.get("__client_uat")).toBe("0");
    expect(jar.cookies.get(`__client_uat_${suffix}`)).toBe("0");

    const signedIn = await signInWithPassword(emulator, { jar });
    const uat = Number(jar.cookies.get("__client_uat"));
    expect(uat).toBe(Math.floor(signedIn.client.updated_at / 1000));
    expect(uat).toBeGreaterThan(0);

    // Signing out ends this client's sessions and resets __client_uat.
    await fapi(emulator, "/v1/client/sessions", { jar, body: { _method: "DELETE" } });
    expect(jar.cookies.get("__client_uat")).toBe("0");
  });

  it("gives cookie clients a dev browser cookie when the key is a development key", async () => {
    const jar = new Jar();
    await fapi(emulator, "/v1/environment", { jar });
    expect(jar.cookies.get("__clerk_db_jwt")).toBe(jar.cookies.get("__client"));

    setEmulatorConfig(emulator.store, { publishableKey: LIVE_PUBLISHABLE_KEY });
    try {
      const live = new Jar();
      await fapi(emulator, "/v1/environment", { jar: live });
      expect(live.cookies.has("__clerk_db_jwt")).toBe(false);
    } finally {
      setEmulatorConfig(emulator.store, { publishableKey: DEFAULT_PUBLISHABLE_KEY });
    }
  });

  it("scopes development browsers by their dev browser token, without cookies", async () => {
    const first = (await (await fapi(emulator, "/v1/dev_browser", { body: {} })).json()) as { id: string };
    const second = (await (await fapi(emulator, "/v1/dev_browser", { body: {} })).json()) as { id: string };
    expect(first.id).not.toBe(second.id);

    const signedIn = await fetch(`${emulator.url}/v1/client/sign_ins?__clerk_db_jwt=${first.id}`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: "identifier=alice%40example.com&password=alice123",
    });
    expect(signedIn.headers.getSetCookie()).toHaveLength(0);

    const firstClient = await fapi(emulator, "/v1/client", { query: { __clerk_db_jwt: first.id } });
    const secondClient = await fapi(emulator, "/v1/client", { query: { __clerk_db_jwt: second.id } });
    expect(((await firstClient.json()) as any).response.sessions).toHaveLength(1);
    expect(((await secondClient.json()) as any).response.sessions).toHaveLength(0);
  });

  it("hands native clients their token in the Authorization header", async () => {
    const first = await fapi(emulator, "/v1/environment", { query: { _is_native: "1" } });
    const token = first.headers.get("authorization");
    expect(token).toBeTruthy();

    await signInWithPassword(emulator, { query: { _is_native: "1" }, headers: { Authorization: token! } });
    const again = await fapi(emulator, "/v1/client", { query: { _is_native: "1" }, headers: { Authorization: token! } });
    expect(again.headers.get("authorization")).toBe(token);
    expect(((await again.json()) as any).response.sessions).toHaveLength(1);
  });

  it("lets a request with no credentials finish the sign-in it started", async () => {
    const created = await fapi(emulator, "/v1/client/sign_ins", { body: { identifier: "alice@example.com" } });
    const { response: signIn } = (await created.json()) as { response: { id: string } };
    const attempt = await fapi(emulator, `/v1/client/sign_ins/${signIn.id}/attempt_first_factor`, {
      body: { strategy: "password", password: "alice123" },
    });
    const body = (await attempt.json()) as { client: { sessions: unknown[] } };
    expect(body.client.sessions).toHaveLength(1);
  });
});

describe("Clerk plugin - handshake with the real @clerk/backend SDK", () => {
  let emulator: ClerkTestEmulator;

  beforeAll(async () => {
    emulator = await startClerkTestEmulator();
  });

  afterAll(async () => {
    await emulator?.close();
  });

  // Follow the SDK's handshake redirect to the emulator and back to the app.
  async function runHandshake(location: string, jar: Jar): Promise<string> {
    const res = await fapi(emulator, location.replace(/^https?:\/\/[^/]+/, ""), { jar });
    expect(res.status).toBe(307);
    return res.headers.get("location")!;
  }

  it("development: issues a dev browser, then restores a missing session token", async () => {
    const clerk = createClerkClient({ secretKey: clerkTestSecretKey, apiUrl: emulator.url });
    const opts = { publishableKey: DEFAULT_PUBLISHABLE_KEY, secretKey: clerkTestSecretKey, proxyUrl: emulator.url };
    const browser = new Jar();

    // First visit: no dev browser yet, so the SDK hands off to FAPI.
    const first = await clerk.authenticateRequest(documentRequest(APP_URL), opts);
    expect(first.status).toBe("handshake");
    expect(first.reason).toBe("dev-browser-missing");
    const back = await runHandshake(first.headers.get("location")!, browser);
    expect(new URL(back).searchParams.get("__clerk_handshake_nonce")).toBeTruthy();

    const resolved = await clerk.authenticateRequest(documentRequest(back), opts);
    expect(resolved.status).toBe("signed-out");
    browser.store(resolved.headers.getSetCookie());
    const devBrowser = browser.cookies.get("__clerk_db_jwt");
    expect(devBrowser).toBeTruthy();

    // clerk-js signs in on that dev browser and records __client_uat, but the
    // app's __session cookie is missing, as after it expires.
    const signedIn = await signInWithPassword(emulator, { query: { __clerk_db_jwt: devBrowser! } });
    browser.cookies.set("__client_uat", String(Math.floor(signedIn.client.updated_at / 1000)));

    const stale = await clerk.authenticateRequest(documentRequest(APP_URL, browser), opts);
    expect(stale.status).toBe("handshake");
    expect(stale.reason).toBe("client-uat-but-no-session-token");
    const backAgain = await runHandshake(stale.headers.get("location")!, browser);

    const final = await clerk.authenticateRequest(documentRequest(backAgain, browser), opts);
    expect(final.status).toBe("signed-in");
    expect(final.toAuth()?.sessionId).toBe(signedIn.response.created_session_id);
  });

  it("production: restores the session from the __client cookie, with suffixed cookies", async () => {
    setEmulatorConfig(emulator.store, { publishableKey: LIVE_PUBLISHABLE_KEY });
    try {
      const clerk = createClerkClient({ secretKey: clerkTestSecretKey, apiUrl: emulator.url });
      const opts = { publishableKey: LIVE_PUBLISHABLE_KEY, secretKey: clerkTestSecretKey, proxyUrl: emulator.url };
      // With a same-origin proxy, FAPI's cookies and the app's share one jar.
      const browser = new Jar();
      const signedIn = await signInWithPassword(emulator, { jar: browser });
      const suffix = cookieSuffix(LIVE_PUBLISHABLE_KEY);
      expect(browser.cookies.get(`__client_uat_${suffix}`)).toBe(browser.cookies.get("__client_uat"));

      const stale = await clerk.authenticateRequest(documentRequest(APP_URL, browser), opts);
      expect(stale.status).toBe("handshake");
      const back = await runHandshake(stale.headers.get("location")!, browser);

      const final = await clerk.authenticateRequest(documentRequest(back, browser), opts);
      expect(final.status).toBe("signed-in");
      expect(final.toAuth()?.sessionId).toBe(signedIn.response.created_session_id);
      const setCookies = final.headers.getSetCookie().join("\n");
      expect(setCookies).toContain(`__session_${suffix}=`);
      expect(setCookies).toContain("Secure");
    } finally {
      setEmulatorConfig(emulator.store, { publishableKey: DEFAULT_PUBLISHABLE_KEY });
    }
  });

  it("signs the token format with the instance key", async () => {
    const jar = new Jar();
    await signInWithPassword(emulator, { jar });
    const res = await fapi(emulator, "/v1/client/handshake", {
      jar,
      query: { redirect_url: APP_URL, suffixed_cookies: "false" },
    });
    const token = new URL(res.headers.get("location")!).searchParams.get("__clerk_handshake")!;
    const { handshake } = decodeJwt(token) as { handshake: string[] };
    expect(handshake.some((c) => c.startsWith("__session=ey"))).toBe(true);
  });

  it("only gives handshake payloads to callers with the secret key", async () => {
    const res = await fetch(`${emulator.url}/v1/clients/handshake_payload?nonce=whatever`);
    expect(res.status).toBe(401);
  });
});

describe("Clerk plugin - Svix-signed webhooks", () => {
  it("produces signatures @clerk/backend's verifyWebhook accepts", async () => {
    const secret = `whsec_${Buffer.from("emulator-webhook-secret").toString("base64")}`;
    const body = JSON.stringify({ object: "event", type: "user.created", data: { id: "user_123" } });
    const id = "msg_test";
    const timestamp = Math.floor(Date.now() / 1000);

    const request = new Request("https://app.example.test/api/webhooks/clerk", {
      method: "POST",
      headers: {
        "svix-id": id,
        "svix-timestamp": String(timestamp),
        "svix-signature": svixSignature(secret, id, timestamp, body),
      },
      body,
    });
    const event = await verifyWebhook(request, { signingSecret: secret });
    expect(event.type).toBe("user.created");
  });
});
