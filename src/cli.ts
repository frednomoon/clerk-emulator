#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import { serve } from "@hono/node-server";
import { createServer, filePersistence } from "./framework/index.js";
import { DEFAULT_PUBLISHABLE_KEY, clerkPlugin, seedFromConfig, setEmulatorConfig, type ClerkSeedConfig } from "./index.js";

const port = Number(process.env.PORT ?? 4000);
const host = process.env.HOST ?? "0.0.0.0";
const secretKey = process.env.CLERK_SECRET_KEY ?? "sk_test_emulate";
const machineKey = process.env.CLERK_MACHINE_KEY ?? "ak_test_emulate";

// --persist <file> (or CLERK_PERSIST=<file>): keep the in-memory store on disk
// so it survives restarts.
const persistArgIdx = process.argv.indexOf("--persist");
const persistPath = persistArgIdx !== -1 ? process.argv[persistArgIdx + 1] : process.env.CLERK_PERSIST;

// --seed <file> (or CLERK_SEED=<file>): a JSON ClerkSeedConfig to seed instead
// of the default fixtures (users with fixed ids, metadata, orgs, webhooks).
const seedArgIdx = process.argv.indexOf("--seed");
const seedPath = seedArgIdx !== -1 ? process.argv[seedArgIdx + 1] : process.env.CLERK_SEED;

// The publishable key your app is configured with. Clerk derives its cookie
// names from it, so cookies the emulator sets only match when this does.
const publishableKey = process.env.CLERK_PUBLISHABLE_KEY ?? DEFAULT_PUBLISHABLE_KEY;

// CLERK_USERNAME_REQUIRED=1: sign-up needs a username, as on instances that
// require one. An OAuth sign-up then stops at missing_requirements for it.
const usernameRequired = ["1", "true"].includes(process.env.CLERK_USERNAME_REQUIRED ?? "");

// CLERK_WEBHOOK_URL (+ CLERK_WEBHOOK_SECRET, a whsec_ secret): deliver every
// event there, signed with Svix like Clerk's webhooks.
const webhookUrl = process.env.CLERK_WEBHOOK_URL;
const webhookSecret = process.env.CLERK_WEBHOOK_SECRET;

const { app, store, webhooks, baseUrl } = createServer(clerkPlugin, {
  port,
  tokens: {
    [secretKey]: { login: "admin", id: 1, scopes: [] },
    [machineKey]: { login: "machine", id: 2, scopes: [] },
  },
});

const persistence = persistPath ? filePersistence(persistPath) : null;

// Restore a persisted store if present; otherwise seed default fixtures so the
// emulator is usable the moment it boots.
let restored = false;
if (persistence) {
  const raw = await persistence.load();
  if (raw) {
    try {
      store.restore(JSON.parse(raw));
      restored = true;
    } catch {
      // Corrupt/empty file — fall through to seeding.
    }
  }
}

if (!restored) {
  if (seedPath) {
    const config = JSON.parse(await readFile(seedPath, "utf8")) as ClerkSeedConfig;
    seedFromConfig(store, baseUrl, config, webhooks);
  } else {
    clerkPlugin.seed?.(store, baseUrl);
    seedFromConfig(store, baseUrl, {
      users: [
        { email_addresses: ["alice@example.com"], first_name: "Alice", last_name: "Smith", password: "alice123" },
        { email_addresses: ["bob@example.com"], first_name: "Bob", last_name: "Jones" },
        {
          email_addresses: ["mfa@example.com"],
          first_name: "Mfa",
          last_name: "User",
          password: "mfa12345",
          totp_enabled: true,
        },
      ],
      organizations: [
        {
          name: "Acme Corp",
          slug: "acme",
          members: [
            { email: "alice@example.com", role: "admin" },
            { email: "bob@example.com", role: "member" },
          ],
        },
      ],
    });
  }
}

setEmulatorConfig(store, { publishableKey, usernameRequired });

if (webhookUrl) {
  webhooks.register({
    url: webhookUrl,
    events: ["*"],
    active: true,
    owner: "clerk",
    secret: webhookSecret,
    signing: "svix",
  });
}

if (persistence) {
  const save = () => persistence.save(JSON.stringify(store.snapshot())).catch(() => {});
  setInterval(save, 2000).unref();
  for (const signal of ["SIGINT", "SIGTERM"] as const) {
    process.on(signal, () => void save().then(() => process.exit(0)));
  }
}

serve({ fetch: app.fetch, port, hostname: host }, () => {
  process.stdout.write(
    [
      "",
      "  clerk-emulator is running",
      `  Backend API:  ${baseUrl}`,
      `  Secret key:   ${secretKey}`,
      `  Machine key:  ${machineKey}`,
      `  Publishable:  ${publishableKey}`,
      ...(seedPath ? [`  Seeded from:  ${seedPath}`] : []),
      ...(persistPath ? [`  Persisting:   ${persistPath}`] : []),
      ...(webhookUrl ? [`  Webhooks to:  ${webhookUrl}`] : []),
      "",
      "  Point the Clerk SDK at it with:",
      `    CLERK_SECRET_KEY=${secretKey}`,
      `    CLERK_API_URL=${baseUrl}`,
      `    CLERK_PUBLISHABLE_KEY=${publishableKey}  (same key in the browser)`,
      "",
    ].join("\n") + "\n",
  );
});
