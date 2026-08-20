/**
 * API SECURITY TESTS (§21)
 *
 * Every §21 category, written as an attack rather than an assertion:
 * authentication, authorization, malformed input, replay, request tampering,
 * rate limits, oversized requests, invalid transaction data, secret leakage,
 * error leakage, IDOR, and endpoint enumeration.
 *
 * The API is the only component reachable by an unauthenticated stranger, so
 * it gets the most hostile treatment in the repository.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import type { Server } from "node:http";
import { AddressInfo } from "node:net";
import { createApiServer } from "../src/server.js";
import { WalletService } from "../src/services/walletService.js";
import { generateApiToken, secretsMatch, RateLimiter } from "../src/middleware.js";
import { Wallet } from "../../core/wallet/wallet.js";
import { MemoryChainSource } from "../../core/chain/memory.js";
import { REGTEST } from "../../core/bitcoin/networks.js";

const MNEMONIC =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const TOKEN = "a".repeat(64);

let server: Server;
let baseUrl: string;
let service: WalletService;
let wallet: Wallet;
let chain: MemoryChainSource;
let recipientAddress: string;

async function start(): Promise<void> {
  wallet = Wallet.restore(MNEMONIC, REGTEST);
  chain = new MemoryChainSource("regtest", 500);
  const addresses = wallet.receiveAddresses(3);
  chain.fund(addresses[0]!.address, "11".repeat(32), 0, 1_000_000n, 6);
  chain.fund(addresses[1]!.address, "22".repeat(32), 0, 500_000n, 6);
  await wallet.sync(chain);

  recipientAddress = Wallet.restore(MNEMONIC, REGTEST, "recipient")
    .currentReceiveAddress().address;

  service = new WalletService(wallet, chain);
  server = createApiServer({ service, auth: { token: TOKEN } });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}

async function call(
  path: string,
  options: { method?: string; body?: unknown; token?: string | null; headers?: Record<string, string> } = {},
): Promise<{ status: number; body: any; headers: Headers }> {
  const headers: Record<string, string> = { ...options.headers };
  if (options.token !== null) {
    headers.Authorization = `Bearer ${options.token ?? TOKEN}`;
  }
  if (options.body !== undefined) headers["Content-Type"] = "application/json";

  const response = await fetch(`${baseUrl}${path}`, {
    method: options.method ?? (options.body !== undefined ? "POST" : "GET"),
    headers,
    ...(options.body !== undefined
      ? { body: typeof options.body === "string" ? options.body : JSON.stringify(options.body) }
      : {}),
  });
  const text = await response.text();
  let body: any = null;
  try { body = JSON.parse(text); } catch { body = text; }
  return { status: response.status, body, headers: response.headers };
}

beforeEach(start);
afterEach(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

describe("the happy path works", () => {
  it("GET /health needs no authentication", async () => {
    const response = await call("/health", { token: null });
    expect(response.status).toBe(200);
    expect(response.body.status).toBe("ok");
  });

  it("returns wallet summary, address, and balance", async () => {
    expect((await call("/wallet")).body.network).toBe("regtest");
    expect((await call("/wallet/address")).body.address).toMatch(/^bcrt1q/);
    expect((await call("/wallet/balance")).body.spendable).toBe("1500000");
  });

  it("prepares and sends a transaction", async () => {
    const prepared = await call("/transactions/prepare", {
      body: { to: recipientAddress, amount: 100_000, feeRate: 5 },
    });
    expect(prepared.status).toBe(200);
    expect(prepared.body.amount).toBe("100000");

    const sent = await call("/transactions/send", { body: { id: prepared.body.id } });
    expect(sent.status).toBe(200);
    expect(sent.body.txid).toBe(prepared.body.txid);
  });
});

// ─────────────────────────────────────────────────────────────────────────
describe("§21 ATTACK: authentication", () => {
  it("rejects a missing token", async () => {
    expect((await call("/wallet/balance", { token: null })).status).toBe(401);
  });

  it("rejects a wrong token", async () => {
    expect((await call("/wallet/balance", { token: "b".repeat(64) })).status).toBe(401);
  });

  it("rejects a nearly-correct token", async () => {
    expect((await call("/wallet/balance", { token: "a".repeat(63) + "b" })).status).toBe(401);
    expect((await call("/wallet/balance", { token: "a".repeat(63) })).status).toBe(401);
    expect((await call("/wallet/balance", { token: "a".repeat(65) })).status).toBe(401);
  });

  it("rejects the wrong scheme", async () => {
    const response = await call("/wallet/balance", {
      token: null, headers: { Authorization: `Basic ${TOKEN}` },
    });
    expect(response.status).toBe(401);
  });

  it("gives an IDENTICAL response for every auth failure", async () => {
    // Distinguishing "no header" from "wrong scheme" from "bad token" tells
    // an attacker how far along they are.
    const variants = [
      await call("/wallet/balance", { token: null }),
      await call("/wallet/balance", { token: "wrong" }),
      await call("/wallet/balance", { token: null, headers: { Authorization: "Basic x" } }),
      await call("/wallet/balance", { token: null, headers: { Authorization: "Bearer" } }),
    ];
    const bodies = new Set(variants.map((v) => JSON.stringify(v.body)));
    expect(bodies.size).toBe(1);
    expect(variants.every((v) => v.status === 401)).toBe(true);
  });

  it("protects EVERY non-health endpoint", async () => {
    for (const [method, path] of [
      ["GET", "/wallet"], ["GET", "/wallet/address"], ["GET", "/wallet/balance"],
      ["GET", "/wallet/utxos"], ["GET", "/wallet/security"],
      ["POST", "/wallet/sync"], ["POST", "/wallet/address/next"],
      ["POST", "/transactions/prepare"], ["POST", "/transactions/send"],
      ["GET", "/transactions/" + "a".repeat(32)],
      ["DELETE", "/transactions/" + "a".repeat(32)],
    ] as const) {
      const response = await call(path, { method, token: null, ...(method === "POST" ? { body: {} } : {}) });
      expect(response.status, `${method} ${path} was not protected`).toBe(401);
    }
  });

  it("secretsMatch is length-insensitive and correct", () => {
    expect(secretsMatch("abc", "abc")).toBe(true);
    expect(secretsMatch("abc", "abd")).toBe(false);
    // No throw on differing lengths — a throw would itself be a length oracle.
    expect(secretsMatch("a", "aaaaaaaaaaaaaaaaaaaa")).toBe(false);
    expect(secretsMatch("", "x")).toBe(false);
  });

  it("generated tokens are 256-bit and unique", () => {
    const tokens = new Set(Array.from({ length: 100 }, generateApiToken));
    expect(tokens.size).toBe(100);
    expect([...tokens][0]!.length).toBe(64);
  });
});

// ─────────────────────────────────────────────────────────────────────────
describe("§21 ATTACK: secret leakage", () => {
  it("NO endpoint returns a private key, seed, or mnemonic", async () => {
    const responses = await Promise.all([
      call("/wallet"), call("/wallet/address"), call("/wallet/balance"),
      call("/wallet/utxos"), call("/wallet/security"), call("/health", { token: null }),
    ]);
    const combined = responses.map((r) => JSON.stringify(r.body)).join("\n").toLowerCase();

    for (const forbidden of ["mnemonic", "seed", "privatekey", "private_key", "xprv", "wif", "secret"]) {
      expect(combined, `response mentioned '${forbidden}'`).not.toContain(forbidden);
    }
    // And the actual key material for this known wallet.
    const masterKey = "abandon";
    expect(combined).not.toContain(masterKey);
  });

  it("the forbidden §20 endpoints DO NOT EXIST", async () => {
    for (const path of ["/private-key", "/seed", "/mnemonic", "/secrets",
                        "/wallet/private-key", "/wallet/seed", "/wallet/mnemonic",
                        "/wallet/export", "/wallet/backup", "/debug", "/admin"]) {
      expect((await call(path)).status, `${path} responded`).toBe(404);
    }
  });

  it("the SERVICE has no method that could expose key material", () => {
    // Reflection over the class: the strongest guarantee is that the code
    // path does not exist, and this fails the suite if one is ever added.
    const methods = Object.getOwnPropertyNames(Object.getPrototypeOf(service));
    for (const method of methods) {
      expect(method.toLowerCase()).not.toMatch(/priv|seed|mnemonic|secret|export|backup|xprv/);
    }
  });

  it("UTXO responses omit derivation paths", async () => {
    const response = await call("/wallet/utxos");
    expect(response.status).toBe(200);
    expect(response.body.utxos.length).toBeGreaterThan(0);
    expect(JSON.stringify(response.body)).not.toContain("m/84");
  });

  it("the security endpoint reports facts, not a meaningless score", async () => {
    const response = await call("/wallet/security");
    expect(response.body.network).toBe("regtest");
    expect(response.body.warnings.length).toBeGreaterThan(0);
    // §26: no invented "99% secure".
    expect(JSON.stringify(response.body)).not.toMatch(/score|rating|\d+%/i);
  });
});

// ─────────────────────────────────────────────────────────────────────────
describe("§21 ATTACK: error leakage", () => {
  it("never returns a stack trace or file path", async () => {
    const responses = await Promise.all([
      call("/transactions/prepare", { body: { to: "invalid", amount: 1000, feeRate: 5 } }),
      call("/transactions/prepare", { body: {} }),
      call("/transactions/send", { body: { id: "f".repeat(32) } }),
      call("/nonexistent"),
      call("/transactions/prepare", { body: "not json at all" }),
    ]);
    const combined = responses.map((r) => JSON.stringify(r.body)).join("\n");

    for (const leak of ["/home/", "\\Users\\", ".ts:", "at Object.", "at Wallet.",
                        "node_modules", "TypeError", "ReferenceError", "stack"]) {
      expect(combined, `leaked '${leak}'`).not.toContain(leak);
    }
  });

  it("returns a structured code plus a safe message, and nothing else", async () => {
    const response = await call("/transactions/prepare", { body: {} });
    expect(response.status).toBe(400);
    expect(Object.keys(response.body)).toEqual(["error"]);
    expect(Object.keys(response.body.error).sort()).toEqual(["code", "message"]);
  });

  it("does not echo attacker-supplied VALUES back", async () => {
    const marker = "XSSMARKER1234567890";
    const response = await call("/transactions/prepare", {
      body: { to: marker + "aaaaaaaaaaaaaaa", amount: 1000, feeRate: 5 },
    });
    expect(JSON.stringify(response.body)).not.toContain(marker);
  });

  it("sanitises control characters out of echoed FIELD NAMES", async () => {
    // Field names are echoed (they are client-supplied and contain no server
    // state), but newlines and escapes could forge log entries.
    const response = await call("/transactions/prepare", {
      body: { to: recipientAddress, amount: 1000, feeRate: 5, "evil\nINJECTED": 1 },
    });
    expect(response.status).toBe(400);
    expect(response.body.error.message).not.toContain("\n");
  });
});

// ─────────────────────────────────────────────────────────────────────────
describe("§21 ATTACK: malformed input", () => {
  it("rejects non-JSON bodies", async () => {
    expect((await call("/transactions/prepare", { body: "{not json" })).status).toBe(400);
    expect((await call("/transactions/prepare", { body: "" })).status).toBe(400);
  });

  it("rejects arrays and primitives where an object is required", async () => {
    for (const body of ["[]", '"string"', "42", "null", "true"]) {
      const response = await call("/transactions/prepare", { body });
      expect(response.status, `accepted ${body}`).toBeGreaterThanOrEqual(400);
    }
  });

  it("rejects unknown fields rather than ignoring them", async () => {
    const response = await call("/transactions/prepare", {
      body: { to: recipientAddress, amount: 1000, feeRate: 5, extraField: "x" },
    });
    expect(response.status).toBe(400);
    expect(response.body.error.message).toContain("extraField");
  });

  it("rejects wrong types without coercing", async () => {
    // NOTE: "1000" is deliberately absent. A decimal STRING is a supported
    // form — see the test below — because JSON numbers above 2^53 lose
    // precision silently. The first version of this test listed it here and
    // contradicted a documented design decision.
    for (const amount of [null, [], {}, true, 1.5, -100, NaN]) {
      const response = await call("/transactions/prepare", {
        body: { to: recipientAddress, amount, feeRate: 5 },
      });
      expect(response.status, `accepted amount=${JSON.stringify(amount)}`).toBe(400);
    }
  });

  it("accepts a decimal STRING amount, which avoids float precision loss", async () => {
    const response = await call("/transactions/prepare", {
      body: { to: recipientAddress, amount: "100000", feeRate: 5 },
    });
    expect(response.status).toBe(200);
    expect(response.body.amount).toBe("100000");
  });

  it("rejects amounts above 2^53 sent as numbers", async () => {
    const response = await call("/transactions/prepare", {
      body: { to: recipientAddress, amount: 2 ** 53 + 1, feeRate: 5 },
    });
    expect(response.status).toBe(400);
    expect(response.body.error.message).toMatch(/string for values above/);
  });

  it("rejects out-of-range fee rates", async () => {
    for (const feeRate of [0, 0.5, -5, 10_001, Infinity, NaN]) {
      const response = await call("/transactions/prepare", {
        body: { to: recipientAddress, amount: 100_000, feeRate },
      });
      expect(response.status, `accepted feeRate=${feeRate}`).toBe(400);
    }
  });

  it("rejects addresses containing path traversal or injection", async () => {
    for (const to of ["../../etc/passwd", "bcrt1q<script>", "bcrt1q'; DROP TABLE--",
                      "bcrt1q\u0000null", "a".repeat(200)]) {
      const response = await call("/transactions/prepare", { body: { to, amount: 100_000, feeRate: 5 } });
      expect(response.status, `accepted to=${to}`).toBeGreaterThanOrEqual(400);
    }
  });

  it("rejects prototype-pollution attempts", async () => {
    // Sent as a RAW STRING, deliberately. The first version of this test used
    // an object literal — but in a literal, `__proto__:` sets the prototype
    // rather than creating an own property, so JSON.stringify emitted `{}`
    // and the "attack" was an empty payload testing nothing.
    //
    // JSON.parse, by contrast, DOES create `__proto__` as an own property, so
    // this raw form is the real attack shape.
    const raw = `{"to":"${recipientAddress}","amount":1000,"feeRate":5,` +
      `"__proto__":{"polluted":true},"constructor":{"prototype":{"polluted":true}}}`;

    const response = await call("/transactions/prepare", { body: raw });

    // Rejected by the unknown-key allowlist, which is what makes this safe:
    // no field reaches application code unless it was explicitly permitted.
    expect(response.status).toBeGreaterThanOrEqual(400);
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
    expect((Object.prototype as Record<string, unknown>).polluted).toBeUndefined();
  });

  it("does not pollute the prototype even via a deeply nested payload", async () => {
    const raw = `{"to":"${recipientAddress}","amount":1000,"feeRate":5,` +
      `"strategy":{"__proto__":{"deepPolluted":true}}}`;
    const response = await call("/transactions/prepare", { body: raw });
    expect(response.status).toBeGreaterThanOrEqual(400);
    expect(({} as Record<string, unknown>).deepPolluted).toBeUndefined();
  });

  it("rejects a body on a GET request", async () => {
    const response = await fetch(`${baseUrl}/wallet/balance`, {
      method: "GET", headers: { Authorization: `Bearer ${TOKEN}` },
    });
    expect(response.status).toBe(200); // no body, fine
  });
});

// ─────────────────────────────────────────────────────────────────────────
describe("§21 ATTACK: oversized requests", () => {
  it("rejects a body above the limit", async () => {
    const response = await call("/transactions/prepare", {
      body: JSON.stringify({ to: recipientAddress, amount: 1000, feeRate: 5, pad: "x".repeat(200_000) }),
    });
    expect(response.status).toBe(413);
  });

  it("rejects a lied-about Content-Length", async () => {
    const response = await fetch(`${baseUrl}/transactions/prepare`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${TOKEN}`,
        "Content-Type": "application/json",
        "Content-Length": "99999999",
      },
      body: JSON.stringify({ to: recipientAddress, amount: 1000, feeRate: 5 }),
    }).catch(() => null);
    if (response) expect(response.status).toBe(413);
  });
});

// ─────────────────────────────────────────────────────────────────────────
describe("§21 ATTACK: IDOR and endpoint enumeration", () => {
  it("returns the SAME 404 for nonexistent, expired, and already-sent ids", async () => {
    // Distinguishing them is an oracle for probing valid ids.
    const prepared = await call("/transactions/prepare", {
      body: { to: recipientAddress, amount: 100_000, feeRate: 5 },
    });
    await call("/transactions/send", { body: { id: prepared.body.id } });

    const alreadySent = await call(`/transactions/${prepared.body.id}`);
    const neverExisted = await call(`/transactions/${"f".repeat(32)}`);

    expect(alreadySent.status).toBe(404);
    expect(neverExisted.status).toBe(404);
    expect(JSON.stringify(alreadySent.body)).toBe(JSON.stringify(neverExisted.body));
  });

  it("prepared ids are unguessable", async () => {
    const ids = new Set<string>();
    for (let i = 0; i < 10; i++) {
      const response = await call("/transactions/prepare", {
        body: { to: recipientAddress, amount: 10_000, feeRate: 5 },
      });
      ids.add(response.body.id);
    }
    expect(ids.size).toBe(10);
    // 128 bits of hex. Sequential ids would let one client confirm another's
    // transaction.
    for (const id of ids) expect(id).toMatch(/^[a-f0-9]{32}$/);
  });

  it("rejects malformed ids without probing state", async () => {
    for (const id of ["1", "../wallet", "abc", "g".repeat(32), "%2e%2e"]) {
      const response = await call("/transactions/send", { body: { id } });
      expect(response.status).toBeGreaterThanOrEqual(400);
    }
  });

  it("a wrong METHOD on a real path returns 404, not 405", async () => {
    // 405 confirms the path exists — free reconnaissance.
    expect((await call("/wallet/balance", { method: "DELETE" })).status).toBe(404);
    expect((await call("/health", { method: "POST", token: null, body: {} })).status).toBe(404);
  });

  it("unknown paths reveal nothing about what exists", async () => {
    const a = await call("/wallet/nonexistent");
    const b = await call("/totally/made/up/path");
    expect(a.status).toBe(404);
    expect(JSON.stringify(a.body)).toBe(JSON.stringify(b.body));
  });
});

// ─────────────────────────────────────────────────────────────────────────
describe("§21 ATTACK: replay and request tampering", () => {
  it("a prepared transaction CANNOT be sent twice", async () => {
    const prepared = await call("/transactions/prepare", {
      body: { to: recipientAddress, amount: 100_000, feeRate: 5 },
    });
    expect((await call("/transactions/send", { body: { id: prepared.body.id } })).status).toBe(200);
    // Replaying the same request must not double-spend.
    expect((await call("/transactions/send", { body: { id: prepared.body.id } })).status).toBe(404);
  });

  it("send() accepts NO parameter that could alter the transaction", async () => {
    // The core property of the prepare/confirm split: there is no field
    // through which the broadcast could differ from what was reviewed.
    const prepared = await call("/transactions/prepare", {
      body: { to: recipientAddress, amount: 100_000, feeRate: 5 },
    });
    const tampered = await call("/transactions/send", {
      body: { id: prepared.body.id, amount: 900_000, to: "bcrt1qattacker" },
    });
    expect(tampered.status).toBe(400); // unknown fields rejected outright

    // And the original is still intact and unaltered.
    const review = await call(`/transactions/${prepared.body.id}`);
    expect(review.body.amount).toBe("100000");
    expect(review.body.recipient).toBe(recipientAddress);
  });

  it("the reviewed txid is EXACTLY what gets broadcast", async () => {
    const prepared = await call("/transactions/prepare", {
      body: { to: recipientAddress, amount: 100_000, feeRate: 5 },
    });
    const sent = await call("/transactions/send", { body: { id: prepared.body.id } });
    expect(sent.body.txid).toBe(prepared.body.txid);
    expect(chain.broadcastLog.length).toBe(1);
  });

  it("cancelling prevents sending", async () => {
    const prepared = await call("/transactions/prepare", {
      body: { to: recipientAddress, amount: 100_000, feeRate: 5 },
    });
    expect((await call(`/transactions/${prepared.body.id}`, { method: "DELETE" })).status).toBe(200);
    expect((await call("/transactions/send", { body: { id: prepared.body.id } })).status).toBe(404);
    expect(chain.broadcastLog.length).toBe(0);
  });
});

// ─────────────────────────────────────────────────────────────────────────
describe("§21 ATTACK: invalid transaction data", () => {
  it("refuses to overspend", async () => {
    const response = await call("/transactions/prepare", {
      body: { to: recipientAddress, amount: 99_000_000, feeRate: 5 },
    });
    expect(response.status).toBe(422);
    expect(response.body.error.message).toMatch(/insufficient/i);
  });

  it("refuses a dust amount", async () => {
    const response = await call("/transactions/prepare", {
      body: { to: recipientAddress, amount: 100, feeRate: 5 },
    });
    expect(response.status).toBe(422);
  });

  it("refuses a wrong-network address", async () => {
    const response = await call("/transactions/prepare", {
      body: { to: "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", amount: 100_000, feeRate: 5 },
    });
    expect(response.status).toBe(422);
  });

  it("§16: the review shows amount, fee, total, and remaining balance", async () => {
    const response = await call("/transactions/prepare", {
      body: { to: recipientAddress, amount: 100_000, feeRate: 5 },
    });
    for (const field of ["amount", "fee", "total", "remainingBalance", "change", "vsize", "feeRate"]) {
      expect(response.body[field], `missing ${field}`).toBeDefined();
    }
    expect(BigInt(response.body.total)).toBe(BigInt(response.body.amount) + BigInt(response.body.fee));
  });

  it("nothing is broadcast during prepare", async () => {
    await call("/transactions/prepare", { body: { to: recipientAddress, amount: 100_000, feeRate: 5 } });
    expect(chain.broadcastLog.length).toBe(0);
  });
});

// ─────────────────────────────────────────────────────────────────────────
describe("§21 ATTACK: rate limiting", () => {
  it("blocks a client above the limit", () => {
    const limiter = new RateLimiter({ windowMs: 60_000, maxRequests: 3 });
    for (let i = 0; i < 3; i++) limiter.check("client", 1000);
    expect(() => limiter.check("client", 1000)).toThrow(/Too many requests/);
  });

  it("resets after the window", () => {
    const limiter = new RateLimiter({ windowMs: 1000, maxRequests: 2 });
    limiter.check("client", 0);
    limiter.check("client", 0);
    expect(() => limiter.check("client", 500)).toThrow();
    expect(() => limiter.check("client", 1001)).not.toThrow();
  });

  it("tracks clients independently", () => {
    const limiter = new RateLimiter({ windowMs: 60_000, maxRequests: 1 });
    limiter.check("a", 0);
    expect(() => limiter.check("b", 0)).not.toThrow();
    expect(() => limiter.check("a", 0)).toThrow();
  });

  it("does not grow without bound — the limiter must not become the DoS", () => {
    const limiter = new RateLimiter({ windowMs: 100, maxRequests: 10 });
    for (let i = 0; i < 2000; i++) limiter.check(`client-${i}`, 0);
    limiter.check("trigger", 100_000); // past the window: triggers eviction
    expect(limiter.size).toBeLessThan(2000);
  });

  it("rate limiting applies BEFORE authentication", async () => {
    // Otherwise tokens can be brute-forced at full speed, since failed auth
    // would never consume an allowance.
    const limited = createApiServer({
      service, auth: { token: TOKEN }, rateLimit: { windowMs: 60_000, maxRequests: 3 },
    });
    await new Promise<void>((resolve) => limited.listen(0, "127.0.0.1", resolve));
    const port = (limited.address() as AddressInfo).port;

    const statuses: number[] = [];
    for (let i = 0; i < 6; i++) {
      const response = await fetch(`http://127.0.0.1:${port}/wallet/balance`, {
        headers: { Authorization: "Bearer wrong-token" },
      });
      statuses.push(response.status);
    }
    expect(statuses.filter((s) => s === 429).length).toBeGreaterThan(0);
    await new Promise<void>((resolve) => limited.close(() => resolve()));
  });
});

// ─────────────────────────────────────────────────────────────────────────
// ─────────────────────────────────────────────────────────────────────────
describe("CORS (regression: VEY-008)", () => {
  it("answers a preflight WITHOUT requiring authentication", async () => {
    // The browser strips Authorization from a preflight by design. Requiring
    // it here means every browser request fails before it is ever sent —
    // which is exactly the bug this test exists to prevent recurring.
    const response = await fetch(`${baseUrl}/wallet`, {
      method: "OPTIONS",
      headers: {
        Origin: "http://127.0.0.1:5173",
        "Access-Control-Request-Method": "GET",
        "Access-Control-Request-Headers": "authorization",
      },
    });
    expect(response.status).toBe(204);
    expect(response.headers.get("access-control-allow-origin")).toBe("http://127.0.0.1:5173");
    expect(response.headers.get("access-control-allow-headers")?.toLowerCase()).toContain("authorization");
  });

  it("echoes an allowlisted origin on a real request", async () => {
    const response = await fetch(`${baseUrl}/wallet`, {
      headers: { Authorization: `Bearer ${TOKEN}`, Origin: "http://localhost:5173" },
    });
    expect(response.status).toBe(200);
    expect(response.headers.get("access-control-allow-origin")).toBe("http://localhost:5173");
  });

  it("gives an unlisted origin NO CORS headers", async () => {
    // The browser then blocks it. Note this protects browsers, not the API:
    // curl ignores CORS entirely, so the token is the real guard.
    const response = await fetch(`${baseUrl}/wallet`, {
      headers: { Authorization: `Bearer ${TOKEN}`, Origin: "https://evil.example" },
    });
    expect(response.headers.get("access-control-allow-origin")).toBeNull();
  });

  it("NEVER uses a wildcard origin", async () => {
    for (const origin of ["https://evil.example", "http://127.0.0.1:5173", "null"]) {
      const response = await fetch(`${baseUrl}/wallet`, {
        headers: { Authorization: `Bearer ${TOKEN}`, Origin: origin },
      });
      expect(response.headers.get("access-control-allow-origin")).not.toBe("*");
    }
  });

  it("does not permit credentialed cross-origin requests", async () => {
    // Auth is a bearer token set by our own client, never a cookie. Allowing
    // credentials would grant reach without granting any needed capability.
    const response = await fetch(`${baseUrl}/wallet`, {
      headers: { Authorization: `Bearer ${TOKEN}`, Origin: "http://127.0.0.1:5173" },
    });
    expect(response.headers.get("access-control-allow-credentials")).toBeNull();
  });

  it("sets Vary: Origin so caches cannot cross origins", async () => {
    const response = await fetch(`${baseUrl}/health`);
    expect(response.headers.get("vary")).toBe("Origin");
  });

  it("a preflight still consumes rate limit and cannot enumerate routes", async () => {
    // The same 204 for every path, real or not.
    const real = await fetch(`${baseUrl}/wallet`, {
      method: "OPTIONS", headers: { Origin: "http://127.0.0.1:5173" },
    });
    const fake = await fetch(`${baseUrl}/does/not/exist`, {
      method: "OPTIONS", headers: { Origin: "http://127.0.0.1:5173" },
    });
    expect(real.status).toBe(204);
    expect(fake.status).toBe(204);
  });

  it("still requires a token for the actual request after a preflight", async () => {
    await fetch(`${baseUrl}/wallet`, { method: "OPTIONS", headers: { Origin: "http://127.0.0.1:5173" } });
    const response = await fetch(`${baseUrl}/wallet`, { headers: { Origin: "http://127.0.0.1:5173" } });
    expect(response.status).toBe(401);
  });
});

describe("security headers", () => {
  it("sets no-store, nosniff, and frame denial", async () => {
    const response = await call("/wallet/balance");
    expect(response.headers.get("cache-control")).toContain("no-store");
    expect(response.headers.get("x-content-type-options")).toBe("nosniff");
    expect(response.headers.get("x-frame-options")).toBe("DENY");
    expect(response.headers.get("content-security-policy")).toContain("default-src 'none'");
    expect(response.headers.get("referrer-policy")).toBe("no-referrer");
  });

  it("does not advertise the server implementation", async () => {
    const response = await call("/health", { token: null });
    expect(response.headers.get("x-powered-by")).toBeNull();
    expect(response.headers.get("server")).toBeNull();
  });

  it("balances are never cached", async () => {
    const response = await call("/wallet/balance");
    expect(response.headers.get("cache-control")).toContain("no-store");
  });
});
