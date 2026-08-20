/**
 * Wallet state hook.
 *
 * All server state lives here so screens stay presentational. Errors are
 * surfaced rather than swallowed — a wallet showing a zero balance because a
 * request quietly failed is worse than one showing an error, because the user
 * concludes their funds are gone.
 */
import { useCallback, useEffect, useState } from "react";
import {
  VeyraApi, ApiClientError,
  type Balance, type WalletSummary, type AddressInfo,
  type Utxo, type SecurityStatus,
} from "../api/client.js";

export interface WalletState {
  loading: boolean;
  error: string | null;
  connected: boolean;
  summary: WalletSummary | null;
  balance: Balance | null;
  address: AddressInfo | null;
  utxos: Utxo[];
  security: SecurityStatus | null;
}

const EMPTY: WalletState = {
  loading: true,
  error: null,
  connected: false,
  summary: null,
  balance: null,
  address: null,
  utxos: [],
  security: null,
};

export function useWallet(api: VeyraApi) {
  const [state, setState] = useState<WalletState>(EMPTY);

  const refresh = useCallback(async () => {
    setState((previous) => ({ ...previous, loading: true, error: null }));
    try {
      // Fetched together so the screen never shows a balance from one moment
      // beside a UTXO list from another.
      const [summary, balance, address, utxos, security] = await Promise.all([
        api.wallet(), api.balance(), api.address(), api.utxos(), api.security(),
      ]);
      setState({
        loading: false, error: null, connected: true,
        summary, balance, address, utxos, security,
      });
    } catch (error) {
      const message =
        error instanceof ApiClientError
          ? error.message
          : "Something went wrong talking to the wallet.";
      setState((previous) => ({
        ...previous,
        loading: false,
        connected: false,
        error: message,
      }));
    }
  }, [api]);

  const sync = useCallback(async () => {
    setState((previous) => ({ ...previous, loading: true, error: null }));
    try {
      await api.sync();
      await refresh();
    } catch (error) {
      setState((previous) => ({
        ...previous,
        loading: false,
        error: error instanceof ApiClientError ? error.message : "Sync failed.",
      }));
    }
  }, [api, refresh]);

  const nextAddress = useCallback(async () => {
    try {
      const address = await api.nextAddress();
      setState((previous) => ({ ...previous, address }));
    } catch (error) {
      setState((previous) => ({
        ...previous,
        error: error instanceof ApiClientError ? error.message : "Could not get a new address.",
      }));
    }
  }, [api]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  return { ...state, refresh, sync, nextAddress };
}
