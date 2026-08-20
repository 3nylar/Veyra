/**
 * CONNECT
 *
 * The UI needs an API address and token before it can do anything.
 *
 * The token is held in React state only — never localStorage. A token in
 * localStorage survives the tab, is readable by any script that gets injected
 * into the page, and outlives the user's intent to be connected. Retyping it
 * after a refresh is a small cost for removing a persistent credential from
 * the browser entirely.
 */
import { useState } from "react";
import { Card, Button, Field, Notice } from "../components/Primitives.js";

export function Connect({
  onConnect, error,
}: {
  onConnect: (baseUrl: string, token: string) => void;
  error: string | null;
}) {
  const [baseUrl, setBaseUrl] = useState("http://127.0.0.1:3000");
  const [token, setToken] = useState("");

  return (
    <Card label="Connect to your wallet">
      <p className="field-hint" style={{ marginTop: 0, marginBottom: "var(--s4)" }}>
        Veyra's interface holds no keys. It talks to the API process, which
        prints its token once at startup.
      </p>

      <Field
        label="API address"
        value={baseUrl}
        onChange={(event) => setBaseUrl(event.target.value)}
        spellCheck={false}
        autoComplete="off"
      />

      <Field
        label="API token"
        type="password"
        value={token}
        onChange={(event) => setToken(event.target.value)}
        placeholder="Printed when you run npm run api"
        spellCheck={false}
        autoComplete="off"
        hint="Kept in memory for this tab only. Refreshing will ask again."
      />

      {error ? <Notice tone="danger">{error}</Notice> : null}

      <Button
        variant="primary"
        onClick={() => onConnect(baseUrl.replace(/\/$/, ""), token.trim())}
        disabled={token.trim().length === 0}
      >
        Connect
      </Button>
    </Card>
  );
}
