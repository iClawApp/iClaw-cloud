/**
 * Viewer page logic.
 *
 * Flow:
 *   1. Parse share id from /s/<id>/ and optional key from URL fragment (#k=...).
 *   2. Fetch ciphertext metadata from /api/shares/<id>.
 *   3. If the share is password-protected, prompt for password, derive the
 *      unwrap-key via PBKDF2(SHA-256, 200 000 iter), unwrap the real key,
 *      then decrypt. Otherwise the fragment key is the real key.
 *   4. gunzip the plaintext, parse JSON, render as a chat transcript that
 *      visually matches iClaw 1:1 (same .msg / .msg-body markup, same
 *      marked.js + highlight.js stack, same code-block copy button).
 *
 * Everything happens in the browser — the server only sees opaque bytes.
 */

(() => {
  'use strict';

  const idMatch = location.pathname.match(/^\/s\/([A-Za-z0-9_-]{6,32})\/?$/);
  const shareId = idMatch ? idMatch[1] : '';
  /** @type {string | null} */
  const fragmentKeyB64 = readFragmentKey();

  const $ = (sel) => /** @type {HTMLElement | null} */ (document.querySelector(sel));
  /** Avoid crashing the whole viewer if markup is missing or out of sync. */
  function setText(el, text) {
    if (el) el.textContent = text;
  }

  const titleEl = $('#share-title');
  const metaEl = $('#share-meta');
  const loading = $('#loading');
  const gate = $('#gate');
  const errorSection = $('#error');
  const errorDetail = $('#error-detail');
  const gateError = $('#gate-error');
  const messagesSection = $('#messages');
  const thread = $('#thread');
  const pwForm = /** @type {HTMLFormElement | null} */ ($('#pw-form'));
  const pwInput = /** @type {HTMLInputElement | null} */ ($('#pw-input'));

  const domOk =
    titleEl &&
    metaEl &&
    loading &&
    gate &&
    errorSection &&
    errorDetail &&
    gateError &&
    messagesSection &&
    thread &&
    pwForm &&
    pwInput;
  if (!domOk) {
    console.error('[viewer] missing required DOM nodes — check viewer.html');
    document.body.insertAdjacentHTML(
      'afterbegin',
      '<p style="padding:1rem;font-family:system-ui">Viewer page is incomplete. Hard-refresh (clear cache) or redeploy iClaw-cloud <code>public/viewer.html</code>.</p>',
    );
    return;
  }

  if (!idMatch || !shareId) {
    showError('Invalid share URL.');
    return;
  }

  configureMarkdown();

  fetchShare()
    .then((blob) => {
      if (!blob) return;
      renderMetaFromBlob(blob);
      if (blob.hasPassword) {
        gate.hidden = false;
        setDecryptLoading(false);
        setText(titleEl, 'Password required');
        pwForm.addEventListener('submit', async (e) => {
          e.preventDefault();
          const pw = pwInput.value;
          if (!pw) return;
          gateError.hidden = true;
          setText(gateError, '');
          gate.hidden = true;
          setDecryptLoading(true);
          try {
            await unlockWithPassword(blob, pw);
          } catch (err) {
            console.error(err);
            if (errorSection && !errorSection.hidden) return;
            setDecryptLoading(false);
            gate.hidden = false;
            showGateError('Wrong password or corrupted payload.');
          }
        });
      } else {
        unlockWithFragment(blob).catch((err) => {
          console.error(err);
          if (errorSection && !errorSection.hidden) return;
          showError(
            'Decryption failed. The URL may be missing the key (the part after #), ' +
              'or the share may be corrupted.',
          );
        });
      }
    })
    .catch((err) => {
      console.error(err);
      showError(err instanceof Error ? err.message : 'Unexpected error while loading share.');
    });

  /* ----------------------------------------- networking ----------------- */

  async function fetchShare() {
    try {
      const res = await fetch('/api/shares/' + encodeURIComponent(shareId), {
        headers: { Accept: 'application/json' },
      });
      if (res.status === 404) {
        showError('This share has expired or never existed.');
        return null;
      }
      if (!res.ok) {
        const errText = await res.text().catch(() => '');
        let detail = '';
        try {
          const j = JSON.parse(errText);
          if (j && typeof j.error === 'string') detail = j.error;
        } catch {
          if (errText) detail = errText.replace(/\s+/g, ' ').slice(0, 200);
        }
        showError(
          detail
            ? `Server error (${res.status}): ${detail}`
            : 'Server error: ' + res.status,
        );
        return null;
      }
      const raw = await res.text();
      try {
        return JSON.parse(raw);
      } catch {
        throw new Error(
          'Share API returned non-JSON (check you are on iClaw-cloud, not a proxy HTML page): ' +
            raw.replace(/\s+/g, ' ').slice(0, 180),
        );
      }
    } catch (err) {
      console.error(err);
      showError('Network error: ' + (err && err.message ? err.message : 'unknown'));
      return null;
    }
  }

  function renderMetaFromBlob(data) {
    const parts = [];
    if (data.expiresAt) parts.push('expires ' + new Date(data.expiresAt).toLocaleString());
    if (data.maxViews) parts.push(`view ${data.viewCount}/${data.maxViews}`);
    if (data.hasPassword) parts.push('password');
    setText(metaEl, parts.join(' · '));
  }

  /* ----------------------------------------- unlock paths ---------------- */

  async function unlockWithFragment(blob) {
    if (!fragmentKeyB64) throw new Error('missing fragment key');
    const rawKey = base64urlToBytes(fragmentKeyB64);
    const key = await importAesKey(rawKey);
    await decryptAndRender(blob, key);
  }

  async function unlockWithPassword(blob, password) {
    if (!blob.salt || !blob.wrappedKey) {
      throw new Error('password share is missing salt or wrappedKey');
    }
    const salt = base64ToBytes(blob.salt);
    const wrappedKey = base64ToBytes(blob.wrappedKey);

    const baseKey = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(password),
      { name: 'PBKDF2' },
      false,
      ['deriveBits', 'deriveKey'],
    );
    const wrapKey = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: 200_000, hash: 'SHA-256' },
      baseKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt'],
    );

    if (wrappedKey.length < 13) throw new Error('wrappedKey too short');
    const wrapNonce = wrappedKey.slice(0, 12);
    const wrapCiphertext = wrappedKey.slice(12);
    const rawKeyBuf = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: wrapNonce },
      wrapKey,
      wrapCiphertext,
    );
    const key = await importAesKey(new Uint8Array(rawKeyBuf));
    await decryptAndRender(blob, key);
  }

  async function decryptAndRender(blob, key) {
    try {
      setDecryptLoading(true);
      const ciphertext = base64ToBytes(blob.ciphertext);
      const nonce = base64ToBytes(blob.nonce);
      const plainBuf = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: nonce },
        key,
        ciphertext,
      );

      const gunzipped = await gunzip(new Uint8Array(plainBuf));
      const text = new TextDecoder().decode(gunzipped);
      /** @type {{title?:string, agent?:string, messages?: Array<{role:string,content:string,createdAt?:string}>}} */
      const payload = JSON.parse(text);

      setDecryptLoading(false);

      setText(titleEl, payload.title || 'Shared chat');
      const subParts = [];
      if (payload.agent) subParts.push(payload.agent);
      if (Array.isArray(payload.messages)) subParts.push(`${payload.messages.length} messages`);
      const prevMeta = metaEl.textContent || '';
      if (prevMeta) subParts.push(prevMeta);
      setText(metaEl, subParts.join(' · '));

      renderTranscript(payload.messages || []);

      messagesSection.hidden = false;
      document.title = (payload.title || 'Shared chat') + ' — iClaw share';
    } catch (err) {
      console.error(err);
      setDecryptLoading(false);
      if (messagesSection) messagesSection.hidden = true;
      let msg =
        err instanceof Error
          ? err.name === 'OperationError' || err.name === 'InvalidCharacterError'
            ? 'Decryption failed — wrong key, corrupted ciphertext, or incompatible data.'
            : err.message
          : String(err);
      if (err instanceof Error && /Unexpected token|JSON/.test(err.message)) {
        msg = 'Decrypted payload is not valid JSON (version mismatch or truncated upload).';
      }
      showError(msg);
      throw err;
    }
  }

  /* ----------------------------------------- markdown + transcript ------ */

  function configureMarkdown() {
    if (!window.marked) return;
    const VIDEO_EXT_RE = /\.(mp4|webm|ogg|mov|m4v)(\?[^#]*)?$/i;

    if (typeof window.marked.setOptions === 'function') {
      window.marked.setOptions({ breaks: true, gfm: true, silent: true });
    }
    if (typeof window.marked.use === 'function') {
      window.marked.use({
        renderer: {
          // Render links to .mp4/.webm etc. as <video> tags (like iClaw does).
          link(token) {
            const href = (token && token.href) || '';
            const text = (token && token.text) || '';
            if (VIDEO_EXT_RE.test(href) && !/<img/i.test(text)) {
              const safe = String(href).replace(/"/g, '&quot;');
              return (
                '<video controls preload="metadata" src="' +
                safe +
                '">Your browser does not support video.</video>'
              );
            }
            return false; // let marked fall back to default rendering
          },
        },
      });
    }
  }

  function renderTranscript(messages) {
    if (!thread) return;
    thread.replaceChildren();
    for (const m of messages) {
      const wrap = document.createElement('div');
      wrap.className = 'msg ' + (m.role || 'system');
      const contentStr = String(m.content || '');
      if (
        (m.role || '').toLowerCase() === 'system' &&
        /^Error:/i.test(contentStr.trim())
      ) {
        wrap.classList.add('msg-system--error');
      }
      const role = document.createElement('div');
      role.className = 'role';
      role.textContent = m.role || '';
      const body = document.createElement('div');
      body.className = 'msg-body';
      body.innerHTML = renderMarkdown(m.content || '');
      decorateLinks(body);
      wrap.appendChild(role);
      wrap.appendChild(body);
      thread.appendChild(wrap);
    }
    // Apply highlight.js + wrap code blocks with copy buttons.
    enhanceCodeBlocks();
  }

  function renderMarkdown(src) {
    if (!src) return '';
    if (window.marked && typeof window.marked.parse === 'function') {
      try {
        const out = window.marked.parse(src);
        if (out != null && typeof /** @type {{ then?: unknown }} */ (out).then === 'function') {
          console.warn('[viewer] marked.parse returned a Promise; falling back to escaped text');
          return '<p>' + escapeHtml(src).replace(/\n/g, '<br>') + '</p>';
        }
        return out;
      } catch {
        /* fall through to escape */
      }
    }
    return '<p>' + escapeHtml(src).replace(/\n/g, '<br>') + '</p>';
  }

  function decorateLinks(root) {
    root.querySelectorAll('a[href]').forEach((a) => {
      a.target = '_blank';
      a.rel = 'noopener noreferrer';
    });
  }

  function enhanceCodeBlocks() {
    if (!window.hljs) return;
    thread.querySelectorAll('pre > code').forEach((codeEl) => {
      try {
        window.hljs.highlightElement(codeEl);
      } catch {
        /* hljs may bail on weird input — leave plain. */
      }
      // Wrap in .code-block-wrap + add floating copy button (matches iClaw).
      const pre = codeEl.parentElement;
      if (!pre || pre.parentElement?.classList.contains('code-block-wrap')) return;
      const wrap = document.createElement('div');
      wrap.className = 'code-block-wrap';
      pre.parentElement.insertBefore(wrap, pre);
      wrap.appendChild(pre);
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'code-copy-btn';
      btn.setAttribute('aria-label', 'Copy code');
      btn.title = 'Copy';
      btn.innerHTML = COPY_ICON;
      wrap.appendChild(btn);
    });
  }

  // Single click handler delegates copy + check icon swap.
  thread.addEventListener('click', (e) => {
    const btn = /** @type {HTMLElement | null} */ (
      e.target instanceof Element ? e.target.closest('.code-copy-btn') : null
    );
    if (!btn) return;
    const wrap = btn.closest('.code-block-wrap');
    const pre = wrap?.querySelector(':scope > pre');
    const code = pre?.querySelector('code');
    const raw = (code?.textContent ?? pre?.textContent ?? '').replace(/ /g, ' ');
    if (!raw.trim()) return;
    e.preventDefault();
    const show = () => {
      btn.innerHTML = COPIED_ICON;
      btn.setAttribute('aria-label', 'Copied');
      btn.disabled = true;
      setTimeout(() => {
        btn.innerHTML = COPY_ICON;
        btn.setAttribute('aria-label', 'Copy code');
        btn.disabled = false;
      }, 1700);
    };
    if (navigator.clipboard?.writeText) {
      navigator.clipboard.writeText(raw).then(show).catch(() => {});
    }
  });

  const COPY_ICON =
    '<svg class="code-copy-icon" xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
    '<rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>' +
    '<path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>';
  const COPIED_ICON =
    '<svg class="code-copy-icon code-copy-icon--ok" xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
    '<polyline points="20 6 9 17 4 12"/></svg>';

  /* ----------------------------------------- crypto helpers ------------- */

  function importAesKey(raw) {
    return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['decrypt']);
  }

  async function gunzip(bytes) {
    if (typeof DecompressionStream === 'undefined') {
      throw new Error('this browser does not support DecompressionStream');
    }
    const ds = new DecompressionStream('gzip');
    const stream = new Response(new Blob([bytes]).stream().pipeThrough(ds));
    const buf = await stream.arrayBuffer();
    return new Uint8Array(buf);
  }

  function base64ToBytes(b64) {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  function base64urlToBytes(s) {
    let b = s.replace(/-/g, '+').replace(/_/g, '/');
    while (b.length % 4 !== 0) b += '=';
    return base64ToBytes(b);
  }
  /**
   * Extract `k` from the URL fragment. Avoid relying on URLSearchParams alone:
   * `application/x-www-form-urlencoded` rules treat `+` as space, which would
   * corrupt a hypothetical standard-base64 key; we also tolerate `#/?k=`.
   */
  function readFragmentKey() {
    let h = typeof location !== 'undefined' && location.hash ? location.hash.replace(/^#/, '') : '';
    if (!h) return null;
    h = h.replace(/^\/?\??/, '');
    const m = /(?:^|[?&])k=([^&]*)/.exec(h);
    if (!m || m[1] === undefined || m[1] === '') return null;
    let v = m[1];
    try {
      v = decodeURIComponent(v.replace(/\+/g, '%2B'));
    } catch {
      /* use raw fragment slice */
    }
    return v || null;
  }
  function escapeHtml(s) {
    return s
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  /* ----------------------------------------- UI helpers ---------------- */

  function setDecryptLoading(on) {
    if (!loading) return;
    loading.hidden = !on;
    loading.setAttribute('aria-busy', on ? 'true' : 'false');
    if (on) {
      loading.setAttribute('aria-label', 'Decrypting…');
    } else {
      loading.removeAttribute('aria-label');
    }
  }

  function showError(text) {
    setDecryptLoading(false);
    if (gate) gate.hidden = true;
    setText(errorDetail, text);
    if (errorSection) errorSection.hidden = false;
    setText(titleEl, 'Share unavailable');
  }
  function showGateError(text) {
    setText(gateError, text);
    if (gateError) gateError.hidden = false;
  }
})();
