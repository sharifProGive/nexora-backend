'use strict';
/* © 2026 Zentora CLC. All rights reserved. Platform Core engineered by Zentora. */
/**
 * Self-hosted identity for Nexora (Vault 03).
 *
 *  - The ONLY third-party input is the Google ID token the phone obtained when the user picked an account.
 *    It is verified here (signature, expiry, issuer, audience) and is used exactly once per sign-in.
 *  - nexoraId = HMAC-SHA256(NEXORA_ID_SECRET, Google `sub`). The same Google account therefore always maps
 *    to the same id, even if the database is ever lost. Keep NEXORA_ID_SECRET forever.
 *  - After sign-in the server issues its own session token (HMAC signed, 30 days, renewed automatically
 *    while the app is used). Every other endpoint accepts only that token, never an e-mail or an id from the body.
 */
const crypto = require('crypto');

const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000;
const RENEW_WINDOW_MS = 7 * 24 * 60 * 60 * 1000;

const b64url = (value) => Buffer.from(value).toString('base64url');

function createAuth({ idSecret, googleAudiences, googleVerifier, store, now = Date.now }) {
  if (typeof idSecret !== 'string' || idSecret.length < 16) throw new Error('NEXORA_ID_SECRET must be set (16+ characters)');
  if (!Array.isArray(googleAudiences) || googleAudiences.length === 0) throw new Error('GOOGLE_WEB_CLIENT_ID must be set');
  if (typeof googleVerifier !== 'function') throw new Error('googleVerifier is required');
  if (!store) throw new Error('store is required');

  const sessionKey = crypto.createHmac('sha256', idSecret).update('nexora-session-v1').digest();

  function deriveNexoraId(sub) {
    const mac = crypto.createHmac('sha256', idSecret).update('nexora-id-v1:' + sub).digest('base64url');
    return 'nx_' + mac.slice(0, 22);
  }

  function signSession(sub, nexoraId) {
    const payload = b64url(JSON.stringify({ sub, nid: nexoraId, exp: now() + SESSION_TTL_MS }));
    const sig = b64url(crypto.createHmac('sha256', sessionKey).update(payload).digest());
    return `v1.${payload}.${sig}`;
  }

  function verifySession(token) {
    const parts = String(token || '').split('.');
    if (parts.length !== 3 || parts[0] !== 'v1') return null;
    const expected = crypto.createHmac('sha256', sessionKey).update(parts[1]).digest();
    let given;
    try {
      given = Buffer.from(parts[2], 'base64url');
    } catch (_e) {
      return null;
    }
    if (given.length !== expected.length || !crypto.timingSafeEqual(given, expected)) return null;
    try {
      const p = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
      if (!p || typeof p.sub !== 'string' || typeof p.nid !== 'string' || typeof p.exp !== 'number' || p.exp < now()) return null;
      return { sub: p.sub, nexoraId: p.nid, exp: p.exp };
    } catch (_e) {
      return null;
    }
  }

  function bearer(req) {
    const m = /^Bearer (.+)$/.exec(req.get('authorization') || '');
    return m ? m[1] : null;
  }

  /** Verifies a Google ID token. Sets req.google = { sub, email, name, picture }. */
  async function requireGoogle(req, res, next) {
    const token = bearer(req);
    if (!token) return res.status(401).json({ success: false, error: 'missing_token' });
    let payload;
    try {
      payload = await googleVerifier(token, googleAudiences);
    } catch (_e) {
      return res.status(401).json({ success: false, error: 'invalid_token' });
    }
    if (!payload || typeof payload.sub !== 'string' || payload.sub.length === 0) {
      return res.status(401).json({ success: false, error: 'invalid_token' });
    }
    req.google = {
      sub: payload.sub,
      email: payload.email_verified && typeof payload.email === 'string' ? payload.email : '',
      name: typeof payload.name === 'string' ? payload.name : '',
      picture: typeof payload.picture === 'string' ? payload.picture : ''
    };
    return next();
  }

  /**
   * Requires a session token issued by this server AND an existing account.
   * Sets req.user = { sub, nexoraId, email, username, handle, avatarUri }.
   * When the token is close to expiry a fresh one is returned in the X-Nexora-Session-Token header.
   */
  async function requireAccount(req, res, next) {
    const session = verifySession(bearer(req));
    if (!session) return res.status(401).json({ success: false, error: 'invalid_session' });
    let user;
    try {
      user = await store.findUserBySub(session.sub);
    } catch (e) {
      console.error('[nexora] account lookup failed', e && e.message);
      return res.status(503).json({ success: false, error: 'unavailable' });
    }
    if (!user || user.nexoraId !== session.nexoraId) {
      return res.status(401).json({ success: false, error: 'unknown_account' });
    }
    req.user = user;
    if (session.exp - now() < RENEW_WINDOW_MS) {
      res.set('X-Nexora-Session-Token', signSession(user.sub, user.nexoraId));
    }
    return next();
  }

  return { deriveNexoraId, signSession, verifySession, requireGoogle, requireAccount };
}

/** Small fixed-window limiter per client IP (no dependency). */
function rateLimit({ windowMs, max }) {
  let hits = new Map();
  setInterval(() => { hits = new Map(); }, windowMs).unref();
  return (req, res, next) => {
    const key = req.ip || 'unknown';
    const n = (hits.get(key) || 0) + 1;
    hits.set(key, n);
    if (n > max) {
      res.set('Retry-After', String(Math.ceil(windowMs / 1000)));
      return res.status(429).json({ success: false, error: 'rate_limited' });
    }
    return next();
  };
}

module.exports = { createAuth, rateLimit, SESSION_TTL_MS, RENEW_WINDOW_MS };
