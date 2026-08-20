/**
 * API CLIENT
 *
 * The UI holds no keys and performs no cryptography. It asks the API for
 * values and displays them. That separation is the point: a browser is a
 * hostile environment for key material, and a UI that cannot sign cannot leak
 * a signing key.
 *
 * Amounts cross this boundary as STRINGS and become BigInt here. A JSON number
 * would be an IEEE double, and `JSON.parse` would silently round anything
 * above 2^53 before this code ever saw it.
 */

export interface WalletSummary {
  network: string;
  derivationPath: string;
  fingerprint: string;
  addressType: string;
  gapLimit: number;
}

export interface Balance {
  total: bigint;
  spendable: bigint;
  unconfirmed: bigint;
  unavailable: bigint;
  utxoCount: number;
}

export interface Utxo {
  txid: string;
  vout: number;
  value: bigint;
  address: string;
  confirmations: number;
  frozen: boolean;
}

export interface AddressInfo {
  address: string;
  path: string;
  network: string;
}

export interface TransactionReview {
  id: string;
  expiresAt: string;
  recipient: string;
  amount: bigint;
  fee: bigint;
  total: bigint;
  change: bigint;
  remainingBalance: bigint;
  feeRate: number;
  vsize: number;
  inputCount: number;
  txid: string;
}

export interface SecurityStatus {
  network: string;
  isMainnet: boolean;
  walletType: string;
  keysHeldBy: string;
  chainSource: string | null;
  chainSourceIsThirdParty: boolean | null;
  privacyWarning: string | null;
  pendingTransactions: number;
  warnings: string[];
}

/**
 * An error carrying the API's structured code.
 *
 * The UI branches on the code, never the message. Branching on message text
 * means a copy edit silently changes behaviour.
 */
export class ApiClientError extends Error {
  constructor(
    readonly code: string,
    message: string,
    readonly status: number,
  ) {
    super(message);
    this.name = "ApiClientError";
  }
}

export class VeyraApi {
  constructor(
    private readonly baseUrl: string,
    private readonly token: string,
  ) {}

  private async request<T>(path: string, init?: RequestInit): Promise<T> {
    let response: Response;
    try {
      response = await fetch(`${this.baseUrl}${path}`, {
        ...init,
        headers: {
          Authorization: `Bearer ${this.token}`,
          ...(init?.body ? { "Content-Type": "application/json" } : {}),
          ...init?.headers,
        },
      });
    } catch {
      // "Cannot reach the API" and "the API said no" need completely
      // different actions from the user, so they are different errors.
      throw new ApiClientError(
        "NETWORK",
        "Cannot reach the Veyra API. Check that it is running.",
        0,
      );
    }

    const text = await response.text();
    let payload: unknown = null;
    try {
      payload = text.length > 0 ? JSON.parse(text) : null;
    } catch {
      throw new ApiClientError("MALFORMED", "The API returned an unreadable response.", response.status);
    }

    if (!response.ok) {
      const error = (payload as { error?: { code?: string; message?: string } })?.error;
      throw new ApiClientError(
        error?.code ?? "UNKNOWN",
        error?.message ?? "Request failed",
        response.status,
      );
    }
    return payload as T;
  }

  async health(): Promise<{ status: string }> {
    return this.request("/health");
  }

  async wallet(): Promise<WalletSummary> {
    return this.request("/wallet");
  }

  async balance(): Promise<Balance> {
    const raw = await this.request<Record<string, string | number>>("/wallet/balance");
    return {
      total: BigInt(raw.total as string),
      spendable: BigInt(raw.spendable as string),
      unconfirmed: BigInt(raw.unconfirmed as string),
      unavailable: BigInt(raw.unavailable as string),
      utxoCount: raw.utxoCount as number,
    };
  }

  async address(): Promise<AddressInfo> {
    return this.request("/wallet/address");
  }

  async nextAddress(): Promise<AddressInfo> {
    return this.request("/wallet/address/next", { method: "POST", body: "{}" });
  }

  async utxos(): Promise<Utxo[]> {
    const raw = await this.request<{ utxos: Array<Record<string, string | number | boolean>> }>(
      "/wallet/utxos",
    );
    return raw.utxos.map((u) => ({
      txid: u.txid as string,
      vout: u.vout as number,
      value: BigInt(u.value as string),
      address: u.address as string,
      confirmations: u.confirmations as number,
      frozen: u.frozen as boolean,
    }));
  }

  async security(): Promise<SecurityStatus> {
    return this.request("/wallet/security");
  }

  async sync(): Promise<{ utxos: number; addressesScanned: number }> {
    return this.request("/wallet/sync", { method: "POST", body: "{}" });
  }

  /** Build and sign. Nothing is broadcast. */
  async prepare(input: { to: string; amount: bigint; feeRate: number }): Promise<TransactionReview> {
    const raw = await this.request<Record<string, string | number>>("/transactions/prepare", {
      method: "POST",
      // Amount sent as a STRING so it cannot lose precision in transit.
      body: JSON.stringify({
        to: input.to,
        amount: input.amount.toString(),
        feeRate: input.feeRate,
      }),
    });
    return parseReview(raw);
  }

  /**
   * Broadcast a prepared transaction.
   *
   * Takes only the id. There is no parameter by which the broadcast could
   * differ from what was reviewed — that property lives in the API, and the
   * UI simply has nothing else it could send.
   */
  async send(id: string): Promise<{ txid: string; broadcast: boolean }> {
    return this.request("/transactions/send", {
      method: "POST",
      body: JSON.stringify({ id }),
    });
  }

  async cancel(id: string): Promise<void> {
    await this.request(`/transactions/${id}`, { method: "DELETE" });
  }
}

function parseReview(raw: Record<string, string | number>): TransactionReview {
  return {
    id: raw.id as string,
    expiresAt: raw.expiresAt as string,
    recipient: raw.recipient as string,
    amount: BigInt(raw.amount as string),
    fee: BigInt(raw.fee as string),
    total: BigInt(raw.total as string),
    change: BigInt(raw.change as string),
    remainingBalance: BigInt(raw.remainingBalance as string),
    feeRate: raw.feeRate as number,
    vsize: raw.vsize as number,
    inputCount: raw.inputCount as number,
    txid: raw.txid as string,
  };
}

// ── Formatting ────────────────────────────────────────────────────────────

/**
 * Satoshis as BTC, always with all 8 decimal places.
 *
 * Trailing zeros are kept deliberately. `0.1` and `0.10000000` are the same
 * number, but a fixed column width means a changed digit is visible at a
 * glance rather than requiring the reader to count decimal places.
 */
export function formatBtc(satoshis: bigint): string {
  const negative = satoshis < 0n;
  const value = negative ? -satoshis : satoshis;
  const whole = value / 100_000_000n;
  const fraction = (value % 100_000_000n).toString().padStart(8, "0");
  return `${negative ? "-" : ""}${whole.toLocaleString("en-US")}.${fraction}`;
}

/** Satoshis with thousands separators — the unit the protocol actually uses. */
export function formatSats(satoshis: bigint): string {
  return satoshis.toLocaleString("en-US");
}

/** Parse a user-typed BTC amount into satoshis, exactly. */
export function parseBtc(input: string): bigint {
  const trimmed = input.trim();
  if (!/^\d*\.?\d*$/.test(trimmed) || trimmed === "" || trimmed === ".") {
    throw new Error("Enter a number");
  }
  const [whole = "0", fraction = ""] = trimmed.split(".");
  if (fraction.length > 8) throw new Error("Bitcoin has 8 decimal places");
  // String arithmetic throughout. Never `parseFloat(x) * 1e8` — that gives
  // 434999999.99999994 for 4.35.
  return BigInt(whole || "0") * 100_000_000n + BigInt((fraction + "00000000").slice(0, 8));
}
