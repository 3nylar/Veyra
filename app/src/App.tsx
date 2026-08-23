/**
 * VEYRA — application root.
 *
 * Holds the connection and the current screen. Everything else is
 * presentational, which keeps each screen readable on its own and means the
 * navigation logic lives in exactly one place.
 */
import { useMemo, useState } from "react";
import { VeyraApi } from "./api/client.js";
import { useWallet } from "./hooks/useWallet.js";
import { Connect } from "./screens/Connect.js";
import { Home } from "./screens/Home.js";
import { Receive } from "./screens/Receive.js";
import { Send } from "./screens/Send.js";
import { Security } from "./screens/Security.js";
import { Notice } from "./components/Primitives.js";

type Screen = "home" | "receive" | "send" | "security";

export function App() {
  const [credentials, setCredentials] = useState<{ baseUrl: string; token: string } | null>(null);

  if (!credentials) {
    return (
      <Shell network={null} isMainnet={false}>
        <Connect onConnect={(baseUrl, token) => setCredentials({ baseUrl, token })} error={null} />
      </Shell>
    );
  }
  return <Connected credentials={credentials} onDisconnect={() => setCredentials(null)} />;
}

function Connected({
  credentials, onDisconnect,
}: {
  credentials: { baseUrl: string; token: string };
  onDisconnect: () => void;
}) {
  const api = useMemo(
    () => new VeyraApi(credentials.baseUrl, credentials.token),
    [credentials.baseUrl, credentials.token],
  );
  const wallet = useWallet(api);
  const [screen, setScreen] = useState<Screen>("home");

  const isMainnet = wallet.security?.isMainnet ?? false;
  const network = wallet.summary?.network ?? null;

  // An authentication failure means the token is wrong, so the useful action
  // is to ask again rather than to show a broken wallet.
  if (wallet.error && !wallet.connected && !wallet.loading) {
    return (
      <Shell network={null} isMainnet={false}>
        <Notice tone="danger">{wallet.error}</Notice>
        <div className="spacer" />
        <button className="btn" data-variant="primary" onClick={onDisconnect}>
          Enter connection details again
        </button>
        <div className="spacer" />
        <button className="btn" data-variant="ghost" onClick={() => void wallet.refresh()}>
          Retry
        </button>
      </Shell>
    );
  }

  return (
    <Shell network={network} isMainnet={isMainnet}>
      <nav className="nav" aria-label="Sections">
        {(
          [
            ["home", "Wallet"],
            ["receive", "Receive"],
            ["send", "Send"],
            ["security", "Security"],
          ] as const
        ).map(([key, label]) => (
          <button
            key={key}
            className="nav-item"
            aria-current={screen === key ? "true" : undefined}
            onClick={() => setScreen(key)}
          >
            {label}
          </button>
        ))}
      </nav>

      {wallet.error && wallet.connected ? <Notice tone="warning">{wallet.error}</Notice> : null}

      {screen === "home" ? (
        <Home
          summary={wallet.summary}
          balance={wallet.balance}
          utxos={wallet.utxos}
          history={wallet.history}
          historyUnavailable={wallet.historyUnavailable}
          loading={wallet.loading}
          onSend={() => setScreen("send")}
          onReceive={() => setScreen("receive")}
          onSync={() => void wallet.sync()}
        />
      ) : null}

      {screen === "receive" ? (
        <Receive
          address={wallet.address}
          isMainnet={isMainnet}
          onNext={() => void wallet.nextAddress()}
          onBack={() => setScreen("home")}
        />
      ) : null}

      {screen === "send" ? (
        <Send
          api={api}
          isMainnet={isMainnet}
          spendable={wallet.balance?.spendable ?? 0n}
          fees={wallet.fees}
          onDone={() => {
            setScreen("home");
            void wallet.refresh();
          }}
          onBack={() => setScreen("home")}
        />
      ) : null}

      {screen === "security" ? (
        <Security status={wallet.security} summary={wallet.summary} onBack={() => setScreen("home")} />
      ) : null}
    </Shell>
  );
}

function Shell({
  network, isMainnet, children,
}: {
  network: string | null;
  isMainnet: boolean;
  children: React.ReactNode;
}) {
  return (
    <div className="shell">
      <header className="topbar">
        <h1 className="wordmark">Veyra</h1>
        {network ? (
          // The network is permanently visible, never buried in settings.
          // Mistaking mainnet for a test network is unrecoverable.
          <span className="network-chip" data-mainnet={isMainnet ? "true" : "false"}>
            {network}
          </span>
        ) : null}
      </header>
      <main>{children}</main>
    </div>
  );
}
