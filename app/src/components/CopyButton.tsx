import { useState } from "react";
import { Button } from "./Primitives.js";

/**
 * Copy to clipboard, with confirmation.
 *
 * The label changes to "Copied" and back. Silent success on a copy action
 * leaves the user unsure whether it worked, and re-copying an address is
 * harmless but re-typing one is not.
 */
export function CopyButton({ value, label = "Copy" }: { value: string; label?: string }) {
  const [copied, setCopied] = useState(false);

  async function copy() {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 1600);
    } catch {
      // Clipboard access can be denied. Say so rather than appearing to work.
      setCopied(false);
      window.prompt("Copy this address:", value);
    }
  }

  return (
    <Button onClick={copy} aria-live="polite">
      {copied ? "Copied" : label}
    </Button>
  );
}
