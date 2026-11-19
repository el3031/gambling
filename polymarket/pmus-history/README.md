# Polymarket US activity history (browser prototype)

A single page where you enter your Polymarket US API key and download your
activity history (trades, resolutions, deposits, withdrawals and so on) from
`GET /v1/portfolio/activities`.

## Run it

```bash
cd pmus-history
python3 -m http.server 8000
```

Open **http://localhost:8000** (use `localhost`, not `127.0.0.1` or `file://`, because WebCrypto
needs a secure context and the proxy only accepts this origin by default).

1. Paste your **Key ID** and **Secret Key** from polymarket.us/developer.
2. Click **Fetch activities**. Every page of every activity type is fetched and shown in a table.
3. Click **Download JSON** to save the raw API response (including both sides'
   `manualOrderIndicator` on trades).

The key is not saved anywhere; enter it again next time.

### If the browser blocks the request (CORS)

The Polymarket US docs don't say whether the API accepts calls from browsers. If the log
says the request failed before a response arrived, run the included proxy in a second terminal:

```bash
node proxy.mjs        # Node 18+, no npm install needed
```

Then click **Fetch activities** again. When a direct call is blocked, the page automatically
retries through the proxy at `http://localhost:8787`.
The page still signs every request itself, so the proxy never sees your secret. It only
forwards `GET /v1/portfolio/*` and rejects everything else, so it can't place orders.

## How the key is protected

- On each download, the Base64 secret is decoded and its first 32 bytes (the Ed25519 private key, per the
  Polymarket US docs) are imported into WebCrypto as a **non-extractable** key. The decoded bytes
  are then wiped.
- Nothing is persisted. The `CryptoKey` handle is held in memory only while a download runs.
  The page loads no third-party code and sets a strict Content-Security-Policy.
- Every request is signed as `Ed25519(timestamp + "GET" + path)` and sent with the
  `X-PM-Access-Key`, `X-PM-Timestamp` and `X-PM-Signature` headers.
- API data is rendered as text, never as HTML.

## Things to know

- **Query string in the signature.** The docs don't say whether `path` includes the query
  string. The page tries path-only first, retries with the query string on a 401, and
  remembers whichever works until you reload the page.
- **401 errors** usually mean a wrong or revoked key, or a computer clock more than 30 seconds off.
- **The key can probably trade.** The same keys are used to place orders, so create a separate
  key for this app and revoke it when you're done.
- **Browser support:** a current version of Chrome, Edge, Firefox or Safari (needs Ed25519 in WebCrypto).

## Files

| File | Purpose |
| --- | --- |
| `index.html` | Page layout and Content-Security-Policy |
| `app.js` | Key import, signing, fetching, table and JSON export |
| `styles.css` | Styling (light and dark mode) |
| `fonts/EBGaramond.woff2` | EB Garamond (SIL Open Font License), served locally |
| `proxy.mjs` | Optional read-only CORS proxy |
