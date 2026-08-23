/**
 * HTTP SERVER AND ROUTING
 *
 * Built on `node:http` with no framework. §46 requires a reason for every
 * dependency, and here the reason runs the other way: a framework would hide
 * the parts that matter most. Body limits, header handling, error
 * serialisation, and route matching are all security-relevant, and this file
 * is short enough to read end to end.
 *
 * The trade-off is real. Express is far better tested than this router, and a
 * production deployment facing the internet should sit behind a reverse proxy
 * that handles TLS, timeouts, and connection limits regardless.
 */

import { createServer, type IncomingMessage, type ServerResponse, type Server } from "node:http";
import { ApiError, toApiError, notFound, badRequest } from "./errors.js";
import {
  authenticate, RateLimiter, callerKey, readJsonBody,
  type AuthConfig, type RateLimitConfig,
} from "./middleware.js";
import {
  asObject, rejectUnknownKeys, requireAddress, requireSatoshis,
  requireNumber, optionalEnum, requireId, requireString,
} from "./validation.js";
import { WalletService } from "./services/walletService.js";

export interface ServerConfig {
  readonly service: WalletService;
  readonly auth: AuthConfig;
  /**
   * Origins permitted to call this API from a browser.
   *
   * An explicit allowlist, never `*`. The token is the real defence — a page
   * without it can do nothing — but `*` would let any site on the internet
   * probe this API from a victim's browser and read the replies, turning a
   * stolen token into a usable one from anywhere. An allowlist costs nothing
   * and removes that.
   */
  readonly allowedOrigins?: readonly string[];
  readonly rateLimit?: RateLimitConfig;
  readonly maxBodyBytes?: number;
  /** Server-side logger. Receives internal detail that clients never see. */
  readonly log?: (level: "info" | "warn" | "error", message: string) => void;
}

/**
 * 64 KB. Every legitimate request here is a few hundred bytes; the margin is
 * for comfort, not need. A smaller cap means less to absorb from a hostile
 * client before rejection.
 */
const DEFAULT_MAX_BODY = 64 * 1024;

const DEFAULT_RATE_LIMIT: RateLimitConfig = { windowMs: 60_000, maxRequests: 120 };

/** The Vite dev server, on both spellings of localhost. */
const DEFAULT_ALLOWED_ORIGINS = [
  "http://localhost:5173",
  "http://127.0.0.1:5173",
];

type Handler = (
  request: IncomingMessage,
  body: Record<string, unknown>,
  params: Record<string, string>,
) => unknown | Promise<unknown>;

interface Route {
  readonly method: string;
  /** Path segments; ':name' captures. */
  readonly segments: readonly string[];
  readonly handler: Handler;
  /** Health is the only unauthenticated route. */
  readonly public?: boolean;
}

export function createApiServer(config: ServerConfig): Server {
  const { service, auth } = config;
  const maxBodyBytes = config.maxBodyBytes ?? DEFAULT_MAX_BODY;
  const limiter = new RateLimiter(config.rateLimit ?? DEFAULT_RATE_LIMIT);
  const log = config.log ?? (() => {});
  const allowedOrigins = new Set(config.allowedOrigins ?? DEFAULT_ALLOWED_ORIGINS);

  const routes: Route[] = [
    // ── Public ──────────────────────────────────────────────────────────
    {
      method: "GET", segments: ["health"], public: true,
      // Deliberately minimal. A health endpoint is reachable without
      // authentication, so it must not report version numbers, network,
      // balance, or anything else useful for reconnaissance.
      handler: () => ({ status: "ok" }),
    },

    // ── Wallet ──────────────────────────────────────────────────────────
    { method: "GET", segments: ["wallet"], handler: () => service.summary() },
    { method: "GET", segments: ["wallet", "address"], handler: () => service.receiveAddress() },
    { method: "POST", segments: ["wallet", "address", "next"], handler: () => service.nextReceiveAddress() },
    { method: "GET", segments: ["wallet", "balance"], handler: () => service.balance() },
    { method: "GET", segments: ["wallet", "utxos"], handler: () => ({ utxos: service.utxos() }) },
    { method: "GET", segments: ["wallet", "security"], handler: () => service.securityStatus() },
    { method: "POST", segments: ["wallet", "sync"], handler: () => service.sync() },
    { method: "GET", segments: ["wallet", "fees"], handler: () => service.feeEstimates() },
    { method: "GET", segments: ["transactions", "replaceable"], handler: () => ({ transactions: service.replaceable() }) },
    {
      method: "POST", segments: ["transactions", "bump"],
      handler: (_request, body) => {
        rejectUnknownKeys(body, ["txid", "feeRate"]);
        return service.bumpFee(
          requireString(body, "txid", { maxLength: 64, pattern: /^[a-f0-9]{64}$/ }),
          requireNumber(body, "feeRate", { min: 1, max: 10_000 }),
        );
      },
    },
    {
      method: "GET", segments: ["transactions"],
      handler: async () => ({ transactions: await service.history() }),
    },

    // ── Transactions ────────────────────────────────────────────────────
    {
      method: "POST", segments: ["transactions", "prepare"],
      handler: (_request, body) => {
        rejectUnknownKeys(body, ["to", "amount", "feeRate", "strategy"]);
        const strategy = optionalEnum(body, "strategy", [
          "branch-and-bound", "single-random-draw", "largest-first",
        ] as const);
        return service.prepare({
          to: requireAddress(body, "to"),
          amount: requireSatoshis(body, "amount"),
          // Upper bound is a guard against a fat-finger: 10,000 sat/vB on a
          // 141-vbyte transaction is 1.4 million satoshis of fee.
          feeRate: requireNumber(body, "feeRate", { min: 1, max: 10_000 }),
          ...(strategy ? { strategy } : {}),
        });
      },
    },
    {
      method: "POST", segments: ["transactions", "send"],
      handler: async (_request, body) => {
        // ONLY an id. No amount, no recipient, no fee — there is no parameter
        // through which the broadcast could differ from what was reviewed.
        rejectUnknownKeys(body, ["id"]);
        return service.send(requireId(body, "id"));
      },
    },
    {
      method: "GET", segments: ["transactions", ":id"],
      handler: (_request, _body, params) => service.pendingTransaction(params.id!),
    },
    {
      method: "DELETE", segments: ["transactions", ":id"],
      handler: (_request, _body, params) => {
        service.cancel(params.id!);
        return { cancelled: true };
      },
    },
  ];

  function match(method: string, path: string): { route: Route; params: Record<string, string> } | null {
    const parts = path.split("/").filter((part) => part.length > 0);
    let methodMismatch = false;

    for (const route of routes) {
      if (route.segments.length !== parts.length) continue;

      const params: Record<string, string> = {};
      let matched = true;
      for (let i = 0; i < route.segments.length; i++) {
        const segment = route.segments[i]!;
        if (segment.startsWith(":")) {
          params[segment.slice(1)] = parts[i]!;
        } else if (segment !== parts[i]) {
          matched = false;
          break;
        }
      }
      if (!matched) continue;
      if (route.method !== method) { methodMismatch = true; continue; }
      return { route, params };
    }
    // A known path with the wrong method still yields 404, not 405.
    // 405 confirms the path exists — free reconnaissance for an attacker
    // mapping the surface (§21, endpoint enumeration).
    void methodMismatch;
    return null;
  }

  return createServer((request: IncomingMessage, response: ServerResponse) => {
    void handle(request, response).catch((error: unknown) => {
      log("error", `unhandled: ${(error as Error)?.message}`);
      if (!response.headersSent) {
        writeJson(response, 500, { error: { code: "INTERNAL", message: "Internal error" } });
      }
    });
  });

  async function handle(request: IncomingMessage, response: ServerResponse): Promise<void> {
    setSecurityHeaders(response);
    applyCors(request, response);

    try {
      // Rate limiting runs FIRST, before auth. Otherwise an attacker can
      // brute-force tokens at full speed, since failed auth would never
      // consume an allowance. Preflights are counted too, so they cannot be
      // used as a free channel.
      limiter.check(callerKey(request));

      // A CORS preflight carries no Authorization header — the browser
      // deliberately strips it — so it MUST be answered before the auth check
      // or every browser request fails. It reveals nothing: the same 204 is
      // returned for every path, so it cannot be used to enumerate routes.
      if (request.method === "OPTIONS") {
        response.writeHead(204).end();
        return;
      }

      const url = new URL(request.url ?? "/", "http://localhost");
      const method = request.method ?? "GET";

      const matched = match(method, url.pathname);
      if (!matched) throw notFound(`${method} ${url.pathname}`);

      if (!matched.route.public) {
        authenticate(request, auth);
      }

      let body: Record<string, unknown> = {};
      if (method === "POST" || method === "PUT" || method === "PATCH") {
        const parsed = await readJsonBody(request, maxBodyBytes);
        body = asObject(parsed);
      } else if (request.headers["content-length"] &&
                 Number(request.headers["content-length"]) > 0) {
        // A body on a GET is a sign of a confused or hostile client.
        throw badRequest("Request body not permitted on this method");
      }

      const result = await matched.route.handler(request, body, matched.params);
      writeJson(response, 200, result);
    } catch (error) {
      const apiError = toApiError(error);

      // Internal detail is logged here and ONLY here. It never reaches the
      // response body.
      if (apiError.internalDetail) {
        log(apiError.status >= 500 ? "error" : "warn",
            `${apiError.code}: ${apiError.internalDetail}`);
      }
      writeJson(response, apiError.status, apiError.toResponse());
    }
  }

  function writeJson(response: ServerResponse, status: number, payload: unknown): void {
    // BigInt is not JSON-serialisable and throws. Every amount is converted to
    // a string before this point; the replacer is a backstop that converts
    // rather than crashing, because a 500 on a balance query would be a
    // confusing failure for a purely presentational reason.
    const body = JSON.stringify(payload, (_key, value) =>
      typeof value === "bigint" ? value.toString() : value,
    );
    response.writeHead(status, {
      "Content-Type": "application/json; charset=utf-8",
      "Content-Length": Buffer.byteLength(body),
    });
    response.end(body);
  }

  /**
   * CORS headers, for allowlisted origins only.
   *
   * A request from an unlisted origin gets NO CORS headers, which the browser
   * then blocks — the correct outcome. Note that this protects browsers, not
   * the API: curl and any non-browser client ignore CORS entirely. The token
   * is what actually guards the endpoints.
   */
  function applyCors(request: IncomingMessage, response: ServerResponse): void {
    const origin = request.headers.origin;

    // Responses differ by Origin, so any cache must key on it. Without this a
    // shared cache could serve an allowed origin's response to a disallowed
    // one.
    response.setHeader("Vary", "Origin");

    if (typeof origin !== "string" || !allowedOrigins.has(origin)) return;

    response.setHeader("Access-Control-Allow-Origin", origin);
    response.setHeader("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
    response.setHeader("Access-Control-Allow-Headers", "Authorization, Content-Type");
    response.setHeader("Access-Control-Max-Age", "600");
    // NOT set: Access-Control-Allow-Credentials. Authentication is a bearer
    // token set explicitly by our own client, never a cookie, so permitting
    // credentialed cross-origin requests would grant reach without granting
    // any capability we need.
  }

  function setSecurityHeaders(response: ServerResponse): void {
    // No caching: responses contain balances and addresses. A cached balance
    // in a shared proxy is both stale and a disclosure.
    response.setHeader("Cache-Control", "no-store, max-age=0");
    response.setHeader("Pragma", "no-cache");
    // This API returns JSON only; these prevent a browser being tricked into
    // interpreting a response as something executable.
    response.setHeader("X-Content-Type-Options", "nosniff");
    response.setHeader("X-Frame-Options", "DENY");
    response.setHeader("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'");
    response.setHeader("Referrer-Policy", "no-referrer");
    // Node advertises itself by default; version numbers aid targeting.
    response.removeHeader("X-Powered-By");
  }
}

export { ApiError };
