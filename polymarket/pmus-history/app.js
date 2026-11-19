'use strict';

/*
 * Polymarket US activity history — browser prototype.
 *
 * Security model:
 *  - The Base64 secret is decoded once, imported into WebCrypto as a NON-EXTRACTABLE
 *    Ed25519 key, and the raw bytes are wiped. Nothing is persisted; the key lives in
 *    memory only for the duration of one download.
 *  - Each request is signed locally: Ed25519(timestamp + method + path), per the Polymarket US docs.
 *  - All API data is rendered with textContent (never innerHTML).
 */

(function () {
  const DEFAULT_BASE = 'https://api.polymarket.us';
  const PROXY_BASE = 'http://localhost:8787'; // optional `node proxy.mjs`, used if the browser blocks direct calls (CORS)
  const PAGE_LIMIT = 500; // API maximum
  const ACTIVITIES_PATH = '/v1/portfolio/activities';
  const MAX_PAGES = 500;
  const subtle = globalThis.crypto.subtle;

  // ---------- encoding helpers ----------

  function b64ToBytes(input) {
    let s = String(input).trim().replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    let bin;
    try { bin = atob(s); } catch { throw new Error('Secret Key is not valid Base64.'); }
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function bytesToB64(bytes) {
    const u = new Uint8Array(bytes);
    let bin = '';
    for (let i = 0; i < u.length; i++) bin += String.fromCharCode(u[i]);
    return btoa(bin);
  }

  function equalBytes(a, b) {
    if (a.length !== b.length) return false;
    let d = 0;
    for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
    return d === 0;
  }

  // ---------- crypto ----------

  // PKCS#8 wrapper for a raw 32-byte Ed25519 seed (RFC 8410).
  const PKCS8_ED25519_PREFIX = new Uint8Array([
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
    0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
  ]);

  async function supportsEd25519() {
    try {
      await subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']);
      return true;
    } catch { return false; }
  }

  /**
   * Turn the portal's Base64 secret into a non-extractable signing key.
   * Per the docs, the private key is the first 32 bytes of the decoded secret.
   * If 64 bytes are present, we check the last 32 against the derived public key.
   */
  async function importSecret(secretB64) {
    const raw = b64ToBytes(secretB64);
    if (raw.length < 32) {
      raw.fill(0);
      throw new Error(`Secret decodes to ${raw.length} bytes; expected at least 32.`);
    }
    const pkcs8 = new Uint8Array(PKCS8_ED25519_PREFIX.length + 32);
    pkcs8.set(PKCS8_ED25519_PREFIX, 0);
    pkcs8.set(raw.subarray(0, 32), PKCS8_ED25519_PREFIX.length);

    const notes = [];
    try {
      if (raw.length >= 64) {
        // Temporary extractable copy, only to derive the public key for a sanity check.
        const tmp = await subtle.importKey('pkcs8', pkcs8, { name: 'Ed25519' }, true, ['sign']);
        const jwk = await subtle.exportKey('jwk', tmp);
        const pub = b64ToBytes(jwk.x);
        if (equalBytes(pub, raw.subarray(32, 64))) notes.push('Secret format check passed (seed + matching public key).');
        else notes.push('Warning: bytes 33–64 of the secret do not match the derived public key. If requests fail with 401, re-copy the secret.');
      } else {
        notes.push(`Secret is ${raw.length} bytes; using it as a raw 32-byte seed.`);
      }
      const key = await subtle.importKey('pkcs8', pkcs8, { name: 'Ed25519' }, false, ['sign']);
      return { key, notes };
    } finally {
      raw.fill(0);
      pkcs8.fill(0);
    }
  }

  async function signMessage(key, message) {
    const sig = await subtle.sign({ name: 'Ed25519' }, key, new TextEncoder().encode(message));
    return bytesToB64(sig);
  }

  async function authHeaders(keyId, key, method, signedPath) {
    const timestamp = String(Date.now());
    const signature = await signMessage(key, timestamp + method + signedPath);
    return {
      'X-PM-Access-Key': keyId,
      'X-PM-Timestamp': timestamp,
      'X-PM-Signature': signature,
    };
  }

  // Expose pure pieces for tests (no secrets live here).
  globalThis.__pmus = { b64ToBytes, bytesToB64, importSecret, signMessage, authHeaders };

  if (typeof document === 'undefined') return;

  // Earlier versions saved the key in IndexedDB; delete that so nothing lingers.
  function deleteLegacyStore() {
    try { indexedDB.deleteDatabase('pmus-history'); } catch { /* ignore */ }
  }

  // ---------- UI helpers ----------

  const $ = (id) => document.getElementById(id);
  function log(msg, level = 'info') {
    const li = document.createElement('li');
    li.className = level;
    li.textContent = `[${new Date().toLocaleTimeString()}] ${msg}`;
    $('log').appendChild(li);
    li.scrollIntoView({ block: 'nearest' });
  }

  let activeBase = DEFAULT_BASE;
  const getBase = () => activeBase;

  // ---------- API ----------

  class CorsOrNetworkError extends Error {}
  class HttpError extends Error {
    constructor(status, body) { super(`HTTP ${status}`); this.status = status; this.body = body; }
  }

  async function signedGet(rec, path, query, signMode) {
    const qs = query.toString();
    const fullPath = qs ? `${path}?${qs}` : path;
    const signedPath = signMode === 'full' ? fullPath : path;
    const headers = await authHeaders(rec.keyId, rec.key, 'GET', signedPath);
    let res;
    try {
      res = await fetch(getBase() + fullPath, {
        method: 'GET',
        headers,
        mode: 'cors',
        credentials: 'omit',
        cache: 'no-store',
        referrerPolicy: 'no-referrer',
      });
    } catch (e) {
      throw new CorsOrNetworkError(e.message || String(e));
    }
    const text = await res.text();
    if (!res.ok) throw new HttpError(res.status, text.slice(0, 500));
    try { return JSON.parse(text); } catch { throw new Error('Response was not JSON.'); }
  }

  /**
   * The docs don't say whether the query string is part of the signed path.
   * Try path-only first; on 401 retry with the query included, then remember what worked.
   */
  async function getWithSignFallback(rec, path, query) {
    try {
      return await getWithSignFallbackAt(rec, path, query);
    } catch (e) {
      if (!(e instanceof CorsOrNetworkError) || activeBase !== DEFAULT_BASE) throw e;
      log('Direct request was blocked (likely CORS); retrying through the local proxy at ' + PROXY_BASE + '…', 'warn');
      activeBase = PROXY_BASE;
      try {
        return await getWithSignFallbackAt(rec, path, query);
      } catch (e2) {
        if (e2 instanceof CorsOrNetworkError) activeBase = DEFAULT_BASE;
        throw e2;
      }
    }
  }

  async function getWithSignFallbackAt(rec, path, query) {
    const hasQuery = [...query.keys()].length > 0;
    const modes = rec.signMode ? [rec.signMode] : hasQuery ? ['path', 'full'] : ['path'];
    let lastErr;
    for (const mode of modes) {
      try {
        const data = await signedGet(rec, path, query, mode);
        if (hasQuery && rec.signMode !== mode) {
          rec.signMode = mode;
          log(`Signing mode confirmed: ${mode === 'full' ? 'path + query string' : 'path only'}.`, 'ok');
        }
        return data;
      } catch (e) {
        lastErr = e;
        if (!(e instanceof HttpError && e.status === 401) || mode === modes[modes.length - 1]) break;
        log('Got 401 signing path only; retrying with the query string in the signature…', 'warn');
      }
    }
    if (lastErr instanceof HttpError && lastErr.status === 401 && rec.signMode) {
      // A remembered mode stopped working; forget it so the next attempt re-probes.
      rec.signMode = undefined;
    }
    throw lastErr;
  }

  // ---------- normalising activities into rows ----------

  const prettyType = (t) => String(t || 'UNKNOWN').replace(/^ACTIVITY_TYPE_/, '').toLowerCase()
    .split('_').map((w) => w[0].toUpperCase() + w.slice(1)).join(' ');
  const amt = (a) => (a && a.value != null ? a.value : '');
  const enumTail = (s, prefix) => (s ? String(s).replace(prefix, '').toLowerCase().replace(/_/g, ' ') : '');

  function toRow(a) {
    const base = { time: '', type: prettyType(a.type), market: '', details: '', amount: '', pnl: '', status: '' };
    if (a.trade) {
      const t = a.trade;
      return {
        ...base,
        time: t.createTime || t.updateTime || '',
        market: t.marketSlug || '',
        details: `${t.qtyDecimal ?? t.qty ?? '?'} @ ${amt(t.price) || '?'}${t.isAggressor != null ? (t.isAggressor ? ' · taker' : ' · maker') : ''}`,
        amount: amt(t.costBasis),
        pnl: amt(t.realizedPnl),
        status: enumTail(t.state, /^TRADE_STATE_/),
      };
    }
    if (a.positionResolution) {
      const r = a.positionResolution;
      const before = r.beforePosition || {};
      const after = r.afterPosition || {};
      let pnl = '';
      const rb = Number(amt(before.realized)); const ra = Number(amt(after.realized));
      if (amt(after.realized) !== '' && Number.isFinite(ra)) pnl = Number.isFinite(rb) ? String(+(ra - rb).toFixed(6)) : String(ra);
      return {
        ...base,
        time: r.updateTime || '',
        market: r.marketSlug || '',
        details: `${enumTail(r.side, /^POSITION_RESOLUTION_SIDE_/)} · position ${before.netPositionDecimal ?? '?'} → ${after.netPositionDecimal ?? '?'}`,
        amount: amt(after.cashValue),
        pnl,
      };
    }
    if (a.accountBalanceChange) {
      const c = a.accountBalanceChange;
      return {
        ...base,
        time: c.createTime || c.updateTime || '',
        details: c.transactionId ? `txn ${c.transactionId}` : '',
        amount: amt(c.amount),
        status: String(c.status || '').toLowerCase().replace(/_/g, ' '),
      };
    }
    return { ...base, details: JSON.stringify(a).slice(0, 160) };
  }

  function fmtTime(iso) {
    const d = new Date(iso);
    return isNaN(d) ? iso : d.toLocaleString();
  }

  function numCell(td, v, colorize = false) {
    td.className = 'num';
    td.textContent = v;
    const n = Number(v);
    if (colorize && v !== '' && Number.isFinite(n) && n !== 0) td.classList.add(n > 0 ? 'pos' : 'neg');
  }

  function renderRows(rows) {
    const tbody = $('rows');
    const frag = document.createDocumentFragment();
    for (const r of rows) {
      const tr = document.createElement('tr');
      const cells = [
        ['time', fmtTime(r.time)], ['', r.type], ['', r.market], ['', r.details],
      ];
      for (const [cls, v] of cells) {
        const td = document.createElement('td');
        if (cls) td.className = cls;
        td.textContent = v;
        tr.appendChild(td);
      }
      const a = document.createElement('td'); numCell(a, r.amount); tr.appendChild(a);
      const p = document.createElement('td'); numCell(p, r.pnl, true); tr.appendChild(p);
      const s = document.createElement('td'); s.textContent = r.status; tr.appendChild(s);
      frag.appendChild(tr);
    }
    tbody.appendChild(frag);
  }

  // ---------- export ----------

  function download(name, mime, text) {
    const url = URL.createObjectURL(new Blob([text], { type: mime }));
    const a = document.createElement('a');
    a.href = url; a.download = name;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  // ---------- state & wiring ----------

  let rawActivities = [];
  let rows = [];
  let stopRequested = false;
  // Remembered for this page session only (not persisted).
  let rememberedSignMode;

  function explainError(e) {
    if (e instanceof CorsOrNetworkError) {
      log(`Request failed before a response was readable (${e.message}).`, 'error');
      log('The browser blocked the direct API call (CORS) and the local proxy was not reachable. Run `node proxy.mjs` in a terminal and click Download again.', 'error');
      return;
    }
    if (e instanceof HttpError) {
      log(`API returned ${e.status}: ${e.body || '(empty body)'}`, 'error');
      if (e.status === 401) log('401 usually means a wrong Key ID/secret, a revoked key, or your computer clock being more than 30 seconds off.', 'warn');
      if (e.status === 429) log('Rate limited (20 requests/second per key). Wait a moment and try again.', 'warn');
      return;
    }
    log(`Error: ${e.message}`, 'error');
  }

  async function onFetch(ev) {
    ev.preventDefault();
    const keyId = $('key-id').value.trim();
    const secretEl = $('secret');
    let rec;
    try {
      const { key, notes } = await importSecret(secretEl.value);
      notes.forEach((n) => { if (n.startsWith('Warning')) log(n, 'warn'); });
      rec = { keyId, key, signMode: rememberedSignMode };
    } catch (e) {
      log(`Could not import key: ${e.message}`, 'error');
      return;
    }

    stopRequested = false;
    $('fetch').disabled = true; $('stop').hidden = false;
    rawActivities = []; rows = [];
    $('rows').replaceChildren();
    $('results').hidden = false;
    $('results-title').textContent = 'Results';


    let cursor = '';
    let page = 0;
    let ok = false;
    try {
      log(`Fetching from ${getBase()}${ACTIVITIES_PATH}…`);
      do {
        const q = new URLSearchParams();
        q.set('limit', String(PAGE_LIMIT));
        q.set('sortOrder', 'SORT_ORDER_DESCENDING');
        if (cursor) q.set('cursor', cursor);

        const data = await getWithSignFallback(rec, ACTIVITIES_PATH, q);
        const acts = Array.isArray(data.activities) ? data.activities : [];
        page++;
        rawActivities.push(...acts);
        const newRows = acts.map(toRow);
        rows.push(...newRows);
        renderRows(newRows);
        $('results-title').textContent = `Results · ${rows.length} activit${rows.length === 1 ? 'y' : 'ies'}`;
        log(`Page ${page}: ${acts.length} activities${data.eof ? ' (last page)' : ''}.`, 'ok');

        cursor = data.eof ? '' : (data.nextCursor || '');
        if (cursor) await new Promise((r) => setTimeout(r, 120)); // stay well under rate limits
      } while (cursor && !stopRequested && page < MAX_PAGES);
      if (stopRequested) log('Stopped by user.', 'warn');
      if (page >= MAX_PAGES) log(`Stopped after ${MAX_PAGES} pages (safety limit).`, 'warn');
      ok = true;
    } catch (e) {
      explainError(e);
    } finally {
      rememberedSignMode = rec.signMode;
      rec = null; // drop the key handle
      $('fetch').disabled = false; $('stop').hidden = true;
    }

    if (ok && !rows.length) log('No activities found on this account.');
    else if (rows.length) {
      log(`Loaded ${rows.length} activities. Click "Download JSON" to save them.${ok ? '' : ' (partial — fetch stopped on an error)'}`, ok ? 'ok' : 'warn');
    }
  }

  function onExportJson() {
    download(`polymarket-us-activity-${new Date().toISOString().slice(0, 10)}.json`, 'application/json',
      JSON.stringify(rawActivities, null, 2));
  }

  async function init() {
    if (!window.isSecureContext) log('This page is not in a secure context; WebCrypto may be unavailable. Serve it from http://localhost or https.', 'warn');
    if (!(await supportsEd25519())) {
      $('unsupported').hidden = false;
      log('Ed25519 is not available in this browser.', 'error');
      return;
    }
    try { localStorage.removeItem('pmus-base'); } catch { /* ignore */ }
    deleteLegacyStore();
    // Where CSS masking isn't supported, fall back to a password field so the secret isn't shown.
    if (!(window.CSS && CSS.supports('-webkit-text-security', 'disc'))) $('secret').type = 'password';
    $('fetch-form').addEventListener('submit', onFetch);
    $('stop').addEventListener('click', () => { stopRequested = true; });
    $('export-json').addEventListener('click', onExportJson);
    log('Ready.');
  }

  init().catch((e) => log(`Startup failed: ${e.message}`, 'error'));
})();
