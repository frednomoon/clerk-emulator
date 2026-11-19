import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { getClerkStore, setEmulatorConfig } from "../index.js";
import { startClerkTestEmulator, type ClerkTestEmulator } from "./helpers.js";

type Json = Record<string, any>;

/** A FAPI client: native (token in Authorization) or a dev browser (token in the query). */
async function newClient(emulator: ClerkTestEmulator, transport: "native" | "dev_browser") {
  let token = "";
  if (transport === "dev_browser") {
    token = ((await (await fetch(`${emulator.url}/v1/dev_browser`, { method: "POST" })).json()) as Json).id;
  }

  return async (path: string, opts: { method?: string; body?: Record<string, string> } = {}) => {
    const url = new URL(path, emulator.url);
    if (transport === "native") url.searchParams.set("_is_native", "1");
    else url.searchParams.set("__clerk_db_jwt", token);
    const res = await fetch(url, {
      method: opts.method ?? (opts.body ? "POST" : "GET"),
      headers: {
        ...(opts.body ? { "Content-Type": "application/x-www-form-urlencoded" } : {}),
        ...(transport === "native" && token ? { Authorization: token } : {}),
      },
      body: opts.body ? new URLSearchParams(opts.body).toString() : undefined,
    });
    if (transport === "native") token = res.headers.get("Authorization") ?? token;
    return { status: res.status, ...((await res.json()) as { response: Json; client: Json; errors?: Json[] }) };
  };
}

/** Submits the emulated provider page, as the person picking an account would. */
async function chooseAccount(emulator: ClerkTestEmulator, signIn: Json, fields: Record<string, string>) {
  const pageUrl = signIn.first_factor_verification.external_verification_redirect_url as string;
  const page = await fetch(pageUrl);
  expect(page.status).toBe(200);

  const res = await fetch(`${emulator.url}/v1/oauth_emulate/authorize`, {
    method: "POST",
    redirect: "manual",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ sign_in_id: signIn.id, ...fields }).toString(),
  });
  expect(res.status).toBe(303);
  return new URL(res.headers.get("Location")!);
}

describe("Clerk plugin - OAuth sign-in (emulated provider)", () => {
  let emulator: ClerkTestEmulator;

  beforeAll(async () => {
    emulator = await startClerkTestEmulator(({ store }) => setEmulatorConfig(store, { usernameRequired: true }));
  });

  afterAll(async () => {
    await emulator?.close();
  });

  it("lists Google and Apple as social connections", async () => {
    const fapi = await newClient(emulator, "dev_browser");
    const { response } = await fapi("/v1/environment");
    expect(response.user_settings.social.oauth_google.enabled).toBe(true);
    expect(response.user_settings.social.oauth_apple.enabled).toBe(true);
    expect(response.user_settings.attributes.username.required).toBe(true);
  });

  it("native: a new account transfers to a sign-up that completes once it has a username", async () => {
    const fapi = await newClient(emulator, "native");
    const created = await fapi("/v1/client/sign_ins", {
      body: { strategy: "oauth_google", redirect_url: "myapp://sso-callback" },
    });
    expect(created.response.status).toBe("needs_identifier");
    expect(created.response.first_factor_verification.status).toBe("unverified");

    const redirect = await chooseAccount(emulator, created.response, { email: "new@example.com", first_name: "New" });
    expect(`${redirect.protocol}//${redirect.host}`).toBe("myapp://sso-callback");
    expect(redirect.searchParams.get("rotating_token_nonce")).toBeTruthy();

    // What useSSO does with the redirect.
    const reloaded = await fapi(
      `/v1/client/sign_ins/${created.response.id}?rotating_token_nonce=${redirect.searchParams.get("rotating_token_nonce")}`,
    );
    expect(reloaded.response.first_factor_verification.status).toBe("transferable");

    const signUp = await fapi("/v1/client/sign_ups", { body: { transfer: "true" } });
    expect(signUp.response.status).toBe("missing_requirements");
    expect(signUp.response.missing_fields).toEqual(["username"]);
    expect(signUp.response.email_address).toBe("new@example.com");
    expect(signUp.response.verifications.external_account.status).toBe("verified");

    const updated = await fapi(`/v1/client/sign_ups/${signUp.response.id}`, {
      method: "PATCH",
      body: { username: "newbie" },
    });
    expect(updated.response.status).toBe("complete");
    expect(updated.client.last_active_session_id).toBe(updated.response.created_session_id);

    const cs = getClerkStore(emulator.store);
    const user = cs.users.findOneBy("username", "newbie")!;
    expect(user.first_name).toBe("New");
    expect(cs.emailAddresses.findOneBy("user_id", user.clerk_id)?.verification_strategy).toBe("from_oauth_google");
  });

  it("rejects a username that is already taken", async () => {
    const fapi = await newClient(emulator, "native");
    const created = await fapi("/v1/client/sign_ins", {
      body: { strategy: "oauth_apple", redirect_url: "myapp://sso-callback" },
    });
    await chooseAccount(emulator, created.response, { email: "second@example.com" });
    const signUp = await fapi("/v1/client/sign_ups", { body: { transfer: "true" } });

    const taken = await fapi(`/v1/client/sign_ups/${signUp.response.id}`, {
      method: "PATCH",
      body: { username: "newbie" },
    });
    expect(taken.status).toBe(422);
    expect(taken.errors?.[0]?.code).toBe("form_identifier_exists");
  });

  it("web: an existing account signs in and goes straight to the complete URL", async () => {
    const fapi = await newClient(emulator, "dev_browser");
    const created = await fapi("/v1/client/sign_ins", {
      body: {
        strategy: "oauth_google",
        redirect_url: "https://app.example.test/sso-callback",
        // clerk-js passes redirectUrlComplete through as given.
        action_complete_redirect_url: "/web",
      },
    });

    const redirect = await chooseAccount(emulator, created.response, { email: "alice@example.com" });
    expect(redirect.toString()).toBe("https://app.example.test/web");

    const { response: client } = await fapi("/v1/client");
    expect(client.sessions).toHaveLength(1);
    expect(client.last_active_session_id).toBe(client.sessions[0].id);
    expect(client.sign_in).toBeNull();
  });

  it("web: the callback page finds the transferable sign-in on the client", async () => {
    const fapi = await newClient(emulator, "dev_browser");
    const created = await fapi("/v1/client/sign_ins", {
      body: {
        strategy: "oauth_google",
        redirect_url: "https://app.example.test/sso-callback",
        action_complete_redirect_url: "https://app.example.test/web",
      },
    });

    const redirect = await chooseAccount(emulator, created.response, { email: "web-new@example.com" });
    expect(redirect.toString()).toBe("https://app.example.test/sso-callback");

    // AuthenticateWithRedirectCallback reads client.sign_in after the reload.
    const { response: client } = await fapi("/v1/client");
    expect(client.sign_in.id).toBe(created.response.id);
    expect(client.sign_in.first_factor_verification.status).toBe("transferable");
  });

  it("cancelling returns to the app with the sign-in unverified", async () => {
    const fapi = await newClient(emulator, "dev_browser");
    const created = await fapi("/v1/client/sign_ins", {
      body: { strategy: "oauth_google", redirect_url: "https://app.example.test/sso-callback" },
    });

    const redirect = await chooseAccount(emulator, created.response, { cancel: "true" });
    expect(redirect.toString()).toBe("https://app.example.test/sso-callback");

    const { response: client } = await fapi("/v1/client");
    expect(client.sign_in.first_factor_verification.status).toBe("unverified");
  });
});
