import { useEffect, useState } from "react";
import QRCode from "qrcode";

/**
 * QR code for a receiving address.
 *
 * Rendered on a white field because QR readers expect dark-on-light; inverting
 * it for aesthetic consistency with a dark interface breaks scanning on many
 * cameras, and an address that will not scan is an address the user retypes by
 * hand.
 *
 * Error correction level M (~15% recoverable). Bech32 addresses are
 * uppercase-safe and encode compactly, so a higher level is affordable, but M
 * keeps the modules large enough to scan from a phone at arm's length.
 */
export function QrCode({ value, size = 200 }: { value: string; size?: number }) {
  const [dataUrl, setDataUrl] = useState<string | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    let cancelled = false;
    QRCode.toDataURL(value.toUpperCase(), {
      errorCorrectionLevel: "M",
      margin: 1,
      width: size * 2,
      color: { dark: "#0a0c0e", light: "#ffffff" },
    })
      .then((url) => {
        if (!cancelled) { setDataUrl(url); setFailed(false); }
      })
      .catch(() => {
        if (!cancelled) setFailed(true);
      });
    return () => { cancelled = true; };
  }, [value, size]);

  if (failed) {
    return (
      <div className="notice" data-tone="warning">
        Could not render a QR code. Copy the address below instead.
      </div>
    );
  }
  if (!dataUrl) return <div className="qr-frame" style={{ height: size + 48 }} />;

  return (
    <div className="qr-frame">
      <img src={dataUrl} alt="QR code for this receiving address" width={size} height={size} />
    </div>
  );
}
