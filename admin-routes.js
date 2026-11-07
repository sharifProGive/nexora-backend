'use strict';
/* © 2026 Zentora CLC. All rights reserved. Platform Core engineered by Zentora. */
/**
 * Owner administration (Vault 37, master backend) for the private Nexmora Admin app, plus account deletion by the user.
 *
 * Who may call it. Only the owner's phone:
 *   1. ADMIN_APP_TOKEN (32+ random characters, set in the host's environment) travels in "Authorization: Bearer ...".
 *   2. Every request except /state, /setup and /rebind is ALSO signed by a key that lives inside the phone's hardware
 *      keystore (ECDSA P-256, SHA-256). The server learns the public half once, at /setup. After that a stolen token is
 *      useless on any other phone. The signed text is
 *          METHOD \n originalUrl(with query) \n X-Admin-Time \n X-Admin-Nonce \n sha256hex(raw request body)
 *      and goes in X-Admin-Signature (base64, DER). A request older than 5 minutes or a repeated nonce is refused.
 *   3. Banning, deleting and restoring an account also need the delete password chosen at /setup (checked here, never
 *      only in the app); 5 wrong tries lock it for 15 minutes.
 *   4. Changing the phone's key (/rebind) needs the 25-digit recovery code that /setup returned once. The last resort, if
 *      that code is lost, is to put a new random value (16+ characters) in ADMIN_RESET: the next /setup is then allowed once.
 *
 * What the owner can do.
 *   GET  /state                      is a phone registered? (token only)
 *   POST /setup | /rebind            register the phone / move to a new key
 *   GET  /overview                   numbers for the home screen (cached 30 s)
 *   GET  /users?q=&before=&limit=    list or search (@handle prefix, nx_ id, e-mail, name prefix)
 *   GET  /users/:id                  everything about one account (counts, videos, comments, friends, calls, status)
 *   POST /users/:id/private          reveals phone and billing (written to the ledger every time)
 *   POST /users/:id/ban | /unban     blocks the account and hides its public videos | undoes both
 *   POST /users/:id/delete           moves the whole account into the recycle vault, kept until restored (never expires)
 *   POST /archive/:id/restore        gives the account back with the same nexoraId and Google identity
 *   GET  /archive | /bans | /videos | /comments | /vaults | /ledger | /ledger/verify | /actions
 *
 * Deleting by the user. POST /api/v1/account/delete-me (session token, {"confirm":"DELETE"}) puts the account into the
 * recycle vault for SELF_DELETE_DAYS (180). The owner can restore it in that time; after it the account's rows and media files
 * are erased for good by an hourly job. What stays: the ledger blocks (they hold no personal data) and a per-day count.
 *
 * A banned or deleted account is refused on every authenticated call with 403 account_banned / account_deleted.
 * Admin tables are created here (CREATE ... IF NOT EXISTS) through a second connection to the same SQLite file, so the
 * schema version, the backup snapshots and db.js stay as they are.
 */
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const express = require('express');
const { DatabaseSync } = require('node:sqlite');
const { str, clampInt, guard, publicBase, absolutize, MEDIA_NAME_RE } = require('./util');
const { rateLimit } = require('./auth');
const { VAULTS } = require('./vaults');

const MIN_TOKEN_CHARS = 32;
const SELF_DELETE_DAYS = 180;
const DAY_MS = 24 * 60 * 60 * 1000;
const SIGNATURE_WINDOW_MS = 5 * 60 * 1000;
const MAX_ARCHIVE_BYTES = 256 * 1024 * 1024;
const NID_RE = /^nx_[A-Za-z0-9_-]{22}$/;
const NONCE_RE = /^[A-Za-z0-9_-]{16,64}$/;

const SCHEMA = `
CREATE TABLE IF NOT EXISTS admin_meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS admin_bans (
  nexora_id TEXT PRIMARY KEY,
  banned_at INTEGER NOT NULL,
  reason TEXT NOT NULL DEFAULT '',
  hidden_json TEXT NOT NULL DEFAULT '[]'
);
CREATE TABLE IF NOT EXISTS admin_archive (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  nexora_id TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('admin', 'self')),
  username TEXT NOT NULL DEFAULT '',
  handle TEXT NOT NULL DEFAULT '',
  avatar_uri TEXT NOT NULL DEFAULT '',
  reason TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  restored_at INTEGER NOT NULL DEFAULT 0,
  payload TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_admin_archive_nid ON admin_archive(nexora_id);
CREATE INDEX IF NOT EXISTS idx_admin_archive_kind ON admin_archive(kind, restored_at, created_at);
CREATE TABLE IF NOT EXISTS admin_actions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  at INTEGER NOT NULL,
  action TEXT NOT NULL,
  target TEXT NOT NULL DEFAULT '',
  detail TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS admin_purge_stats (day TEXT PRIMARY KEY, purged INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS idx_comments_owner ON comments(owner_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_vshares_user ON video_shares(user_id);
CREATE INDEX IF NOT EXISTS idx_vsparks_user ON video_sparks(user_id);
CREATE INDEX IF NOT EXISTS idx_cshares_user ON comment_shares(user_id);
CREATE INDEX IF NOT EXISTS idx_shard_user ON shard_events(user_id);
CREATE INDEX IF NOT EXISTS idx_users_created ON users(created_at);
`;

const OWN_VIDEOS = '(SELECT id FROM videos WHERE owner_id = :n)';
const OWN_COMMENTS = '(SELECT comment_id FROM comments WHERE owner_id = :n OR video_id IN ' + OWN_VIDEOS + ')';
const BY_USER_OR_ON_OWN_VIDEO = 'user_id = :n OR video_id IN ' + OWN_VIDEOS;
/** [table, where]. Children come before the tables their where-clause reads from, because rows are deleted in this order. */
const ARCHIVE_SPECS = [
  ['video_likes', BY_USER_OR_ON_OWN_VIDEO],
  ['video_dislikes', BY_USER_OR_ON_OWN_VIDEO],
  ['video_shares', BY_USER_OR_ON_OWN_VIDEO],
  ['video_sparks', BY_USER_OR_ON_OWN_VIDEO],
  ['shard_events', BY_USER_OR_ON_OWN_VIDEO],
  ['comment_shares', 'user_id = :n OR comment_id IN ' + OWN_COMMENTS],
  ['comments', 'owner_id = :n OR video_id IN ' + OWN_VIDEOS],
  ['videos', 'owner_id = :n'],
  ['media', 'owner_id = :n'],
  ['uploads', 'owner_id = :n'],
  ['friend_links', 'requester_id = :n OR addressee_id = :n'],
  ['chat_events', 'sender_id = :n OR recipient_id = :n'],
  ['call_log', 'caller_id = :n OR callee_id = :n'],
  ['users', 'nexora_id = :n']
];
const RESTORE_ORDER = ['users', 'videos', 'media', 'uploads', 'comments', 'video_likes', 'video_dislikes', 'video_shares',
  'video_sparks', 'shard_events', 'comment_shares', 'friend_links', 'chat_events', 'call_log'];

const same = (a, b) => crypto.timingSafeEqual(
  crypto.createHash('sha256').update(String(a)).digest(),
  crypto.createHash('sha256').update(String(b)).digest()
);

const sha256hex = (buf) => crypto.createHash('sha256').update(buf).digest('hex');

function scrypt(secret, salt) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(String(secret), salt, 32, { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 }, (e, key) => (e ? reject(e) : resolve(key)));
  });
}

async function hashSecret(secret) {
  const salt = crypto.randomBytes(16);
  const key = await scrypt(secret, salt);
  return 'scrypt1$' + salt.toString('base64') + '$' + key.toString('base64');
}

async function checkSecret(secret, stored) {
  const parts = String(stored || '').split('$');
  if (parts.length !== 3 || parts[0] !== 'scrypt1') return false;
  const expected = Buffer.from(parts[2], 'base64');
  const given = await scrypt(secret, Buffer.from(parts[1], 'base64'));
  return given.length === expected.length && crypto.timingSafeEqual(given, expected);
}

/** A P-256 public key in SubjectPublicKeyInfo form (what Android's Keystore exports), as base64. Returns the key object or null. */
function parsePublicKey(b64) {
  try {
    if (typeof b64 !== 'string' || b64.length < 80 || b64.length > 400) return null;
    const key = crypto.createPublicKey({ key: Buffer.from(b64, 'base64'), format: 'der', type: 'spki' });
    if (key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails.namedCurve !== 'prime256v1') return null;
    return key;
  } catch (_e) {
    return null;
  }
}

const exportKey = (key) => key.export({ format: 'der', type: 'spki' }).toString('base64');

function recoveryCode() {
  let out = '';
  for (let i = 0; i < 25; i += 1) out += String(crypto.randomInt(0, 10));
  return out;
}

function dayOf(ms) {
  return new Date(ms).toISOString().slice(0, 10);
}

/**
 * @param {{ store: object, auth: object, config: object }} deps
 *   config: adminToken, adminResetNonce, mediaDir
 */
function createAdmin({ store, auth, config }) {
  const dbReady = store.path !== ':memory:';
  const enabled = dbReady && typeof config.adminToken === 'string' && config.adminToken.length >= MIN_TOKEN_CHARS;
  const adminRouter = express.Router();
  const selfRouter = express.Router();

  if (!dbReady) {
    const off = (_req, res) => res.status(404).json({ success: false, error: 'not_found' });
    adminRouter.get('/state', off);
    selfRouter.post('/', off);
    return { enabled: false, router: adminRouter, selfRouter, banGate: (_req, _res, next) => next(), close() {} };
  }

  const adb = new DatabaseSync(store.path);
  adb.exec('PRAGMA busy_timeout = 10000');
  adb.exec(SCHEMA);

  const cache = new Map();
  const stmt = (sql) => {
    let s = cache.get(sql);
    if (!s) {
      s = adb.prepare(sql);
      cache.set(sql, s);
    }
    return s;
  };
  const count = (sql, ...params) => Number(stmt(sql).get(...params).n);

  function tx(fn) {
    adb.exec('BEGIN IMMEDIATE');
    try {
      const out = fn();
      adb.exec('COMMIT');
      return out;
    } catch (e) {
      try { adb.exec('ROLLBACK'); } catch (_e) { /* already rolled back */ }
      throw e;
    }
  }

  const getMeta = (k) => {
    const r = stmt('SELECT v FROM admin_meta WHERE k = ?').get(k);
    return r ? r.v : '';
  };
  const setMeta = (k, v) => { stmt('INSERT INTO admin_meta (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v').run(k, String(v)); };

  function ledger(event, payload) {
    try {
      store.anchor(event, 'VAULT_37', payload);
    } catch (e) {
      console.error('[nexora] ledger write failed for ' + event, e && e.message);
    }
  }

  function logAction(action, target, detail) {
    stmt('INSERT INTO admin_actions (at, action, target, detail) VALUES (?, ?, ?, ?)')
      .run(Date.now(), action, target || '', detail ? JSON.stringify(detail) : '');
  }

  // ---------------------------------------------------------------- blocked accounts

  function blockReason(nexoraId) {
    if (stmt('SELECT 1 AS x FROM admin_bans WHERE nexora_id = ?').get(nexoraId)) return 'account_banned';
    if (stmt("SELECT 1 AS x FROM admin_archive WHERE nexora_id = ? AND kind = 'admin' AND restored_at = 0 LIMIT 1").get(nexoraId)) return 'account_deleted';
    return '';
  }

  /** Express middleware for the whole app: a banned or deleted account is refused whatever it asks for. */
  function banGate(req, res, next) {
    const p = req.path;
    if (p.startsWith('/api/v1/admin') || p.startsWith('/api/v1/backup') || p.startsWith('/media')) return next();
    const m = /^Bearer (v1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$/.exec(req.get('authorization') || '');
    if (!m) return next();
    const session = auth.verifySession(m[1]);
    if (!session) return next();
    let reason = '';
    try {
      reason = blockReason(session.nexoraId);
    } catch (e) {
      console.error('[nexora] ban lookup failed', e && e.message);
      return res.status(503).json({ success: false, error: 'unavailable' });
    }
    if (!reason) return next();
    return res.status(403).json({ success: false, error: reason });
  }

  // ---------------------------------------------------------------- archive (recycle vault)

  function archiveUser(nexoraId, kind, reason) {
    const user = stmt('SELECT * FROM users WHERE nexora_id = ?').get(nexoraId);
    if (!user) return { error: 'not_found' };
    const result = tx(() => {
      const now = Date.now();
      const bind = { n: nexoraId };
      const payload = { v: 1, sub: user.sub, tables: {}, deltas: [], files: [], hiddenVideos: [] };
      for (const [table, where] of ARCHIVE_SPECS) {
        payload.tables[table] = adb.prepare('SELECT * FROM ' + table + ' WHERE ' + where).all(bind);
      }
      payload.files = (payload.tables.media || []).map((r) => r.name).filter((name) => MEDIA_NAME_RE.test(name));

      // Counters other people's videos and comments keep for what this account did: taken back now, given back on restore.
      const delta = (table, col, key, sql) => {
        for (const r of adb.prepare(sql).all(bind)) payload.deltas.push({ table, col, key, id: r.id, by: Number(r.c) });
      };
      const NOT_OWN = ' AND video_id NOT IN ' + OWN_VIDEOS + ' GROUP BY video_id';
      delta('videos', 'likes', 'id', 'SELECT video_id AS id, COUNT(*) AS c FROM video_likes WHERE user_id = :n' + NOT_OWN);
      delta('videos', 'dislikes', 'id', 'SELECT video_id AS id, COUNT(*) AS c FROM video_dislikes WHERE user_id = :n' + NOT_OWN);
      delta('videos', 'shares', 'id', 'SELECT video_id AS id, COUNT(*) AS c FROM video_shares WHERE user_id = :n' + NOT_OWN);
      delta('videos', 'sparks', 'id', 'SELECT video_id AS id, COALESCE(SUM(amount), 0) AS c FROM video_sparks WHERE user_id = :n' + NOT_OWN);
      delta('comments', 'shares', 'comment_id',
        'SELECT comment_id AS id, COUNT(*) AS c FROM comment_shares WHERE user_id = :n AND comment_id NOT IN ' + OWN_COMMENTS + ' GROUP BY comment_id');

      const ban = stmt('SELECT hidden_json FROM admin_bans WHERE nexora_id = ?').get(nexoraId);
      if (ban) {
        try { payload.hiddenVideos = JSON.parse(ban.hidden_json); } catch (_e) { payload.hiddenVideos = []; }
      }
      const json = JSON.stringify(payload);
      if (json.length > MAX_ARCHIVE_BYTES) return { error: 'too_large' };

      const info = stmt(
        'INSERT INTO admin_archive (nexora_id, kind, username, handle, avatar_uri, reason, created_at, payload) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
      ).run(nexoraId, kind, user.username, user.handle, user.avatar_uri, reason, now, json);

      for (const [table, where] of ARCHIVE_SPECS) adb.prepare('DELETE FROM ' + table + ' WHERE ' + where).run(bind);
      for (const d of payload.deltas) {
        adb.prepare('UPDATE ' + d.table + ' SET ' + d.col + ' = MAX(0, ' + d.col + ' - ?) WHERE ' + d.key + ' = ?').run(d.by, d.id);
      }
      stmt('DELETE FROM admin_bans WHERE nexora_id = ?').run(nexoraId);
      return { archiveId: Number(info.lastInsertRowid), rows: Object.values(payload.tables).reduce((s, r) => s + r.length, 0) };
    });
    return result;
  }

  function columnsOf(table) {
    return adb.prepare('PRAGMA table_info(' + table + ')').all().map((c) => c.name);
  }

  function restoreArchive(archiveId) {
    const entry = stmt('SELECT * FROM admin_archive WHERE id = ?').get(archiveId);
    if (!entry) return { error: 'not_found' };
    if (entry.restored_at !== 0) return { error: 'already_restored' };
    return tx(() => {
      const payload = JSON.parse(entry.payload);
      const taken = stmt('SELECT 1 AS x FROM users WHERE nexora_id = ? OR sub = ?').get(entry.nexora_id, payload.sub);
      if (taken) return { error: 'exists' };
      let rows = 0;
      for (const table of RESTORE_ORDER) {
        const list = payload.tables[table] || [];
        if (list.length === 0) continue;
        const allowed = new Set(columnsOf(table));
        for (const row of list) {
          if (table === 'users' && row.handle) {
            const clash = stmt('SELECT 1 AS x FROM users WHERE lower(handle) = lower(?) LIMIT 1').get(row.handle);
            if (clash) row.handle = row.handle + '_' + crypto.randomBytes(2).toString('hex');
          }
          const cols = Object.keys(row).filter((c) => allowed.has(c));
          const sql = (table === 'users' ? 'INSERT' : 'INSERT OR IGNORE') + ' INTO ' + table + ' (' + cols.join(', ') + ') VALUES (' +
            cols.map(() => '?').join(', ') + ')';
          adb.prepare(sql).run(...cols.map((c) => row[c]));
          rows += 1;
        }
      }
      for (const d of payload.deltas) {
        adb.prepare('UPDATE ' + d.table + ' SET ' + d.col + ' = ' + d.col + ' + ? WHERE ' + d.key + ' = ?').run(d.by, d.id);
      }
      for (const id of payload.hiddenVideos || []) {
        stmt("UPDATE videos SET visibility = 'Public' WHERE id = ? AND visibility = 'Private'").run(id);
      }
      stmt("UPDATE admin_archive SET restored_at = ?, payload = '{}' WHERE id = ?").run(Date.now(), archiveId);
      return { rows, nexoraId: entry.nexora_id };
    });
  }

  /** Erases self-deleted accounts whose SELF_DELETE_DAYS are over: the archive row and the media files. */
  function purgeExpired() {
    try {
      const cutoff = Date.now() - SELF_DELETE_DAYS * DAY_MS;
      const due = stmt("SELECT id, payload FROM admin_archive WHERE kind = 'self' AND restored_at = 0 AND created_at < ? LIMIT 200").all(cutoff);
      for (const row of due) {
        let files = [];
        try { files = JSON.parse(row.payload).files || []; } catch (_e) { files = []; }
        for (const name of files) {
          if (MEDIA_NAME_RE.test(name) && config.mediaDir) fs.rmSync(path.join(config.mediaDir, name), { force: true });
        }
        tx(() => {
          stmt('DELETE FROM admin_archive WHERE id = ?').run(row.id);
          stmt('INSERT INTO admin_purge_stats (day, purged) VALUES (?, 1) ON CONFLICT(day) DO UPDATE SET purged = purged + 1').run(dayOf(Date.now()));
        });
        ledger('ACCOUNT_PURGED', { day: dayOf(Date.now()) });
      }
    } catch (e) {
      console.error('[nexora] purge of expired accounts failed', e && e.message);
    }
  }
  purgeExpired();
  const purgeTimer = setInterval(purgeExpired, 60 * 60 * 1000);
  purgeTimer.unref();

  // ---------------------------------------------------------------- self deletion (every user)

  const jsonBody = express.json({ limit: '16kb', verify: (req, _res, buf) => { req.rawBody = buf; } });
  const selfLimiter = rateLimit({ windowMs: 60 * 60 * 1000, max: 10 });
  selfRouter.post('/', selfLimiter, auth.requireAccount, jsonBody, guard(async (req, res) => {
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    if (body.confirm !== 'DELETE') return res.status(400).json({ success: false, error: 'confirm_required' });
    const result = archiveUser(req.user.nexoraId, 'self', 'user_request');
    if (result.error) return res.status(result.error === 'not_found' ? 404 : 413).json({ success: false, error: result.error });
    ledger('ACCOUNT_SELF_DELETED', { day: dayOf(Date.now()) });
    return res.json({ success: true, restorableDays: SELF_DELETE_DAYS });
  }));

  if (!enabled) {
    const off = (_req, res) => res.status(404).json({ success: false, error: 'not_found' });
    adminRouter.get('/state', off);
    return { enabled: false, router: adminRouter, selfRouter, banGate, close() { clearInterval(purgeTimer); adb.close(); } };
  }

  // ---------------------------------------------------------------- owner authentication

  const ipLimiter = rateLimit({ windowMs: 60 * 1000, max: 240 });
  const failures = new Map();
  const noteFailure = (ip) => {
    const f = failures.get(ip) || { n: 0, until: 0, first: Date.now() };
    if (Date.now() - f.first > 15 * 60 * 1000) { f.n = 0; f.first = Date.now(); }
    f.n += 1;
    if (f.n >= 10) f.until = Date.now() + 15 * 60 * 1000;
    failures.set(ip, f);
    if (failures.size > 5000) for (const [k, v] of failures) if (v.until < Date.now() && Date.now() - v.first > 15 * 60 * 1000) failures.delete(k);
  };
  const locked = (ip) => { const f = failures.get(ip); return !!f && f.until > Date.now(); };

  const seenNonces = new Map();
  function remember(nonce, until) {
    seenNonces.set(nonce, until);
    if (seenNonces.size > 5000) for (const [k, v] of seenNonces) if (v < Date.now()) seenNonces.delete(k);
  }

  let keyCache = { b64: '', key: null };
  function deviceKey() {
    const b64 = getMeta('device_key');
    if (!b64) return null;
    if (keyCache.b64 !== b64) keyCache = { b64, key: parsePublicKey(b64) };
    return keyCache.key;
  }

  const requireAdmin = (signed) => (req, res, next) => {
    if (locked(req.ip)) {
      res.set('Retry-After', '900');
      return res.status(429).json({ success: false, error: 'locked' });
    }
    const m = /^Bearer (.+)$/.exec(req.get('authorization') || '');
    if (!m || !same(m[1], config.adminToken)) {
      noteFailure(req.ip);
      res.set('WWW-Authenticate', 'Bearer');
      return res.status(401).json({ success: false, error: 'unauthorized' });
    }
    if (!signed) return next();
    const key = deviceKey();
    if (!key) return res.status(409).json({ success: false, error: 'not_registered' });
    const time = String(req.get('x-admin-time') || '');
    const nonce = String(req.get('x-admin-nonce') || '');
    const sig = Buffer.from(String(req.get('x-admin-signature') || ''), 'base64');
    const t = Number(time);
    const bad = (error) => { noteFailure(req.ip); return res.status(401).json({ success: false, error }); };
    if (!Number.isFinite(t) || Math.abs(Date.now() - t) > SIGNATURE_WINDOW_MS) return bad('stale_request');
    if (!NONCE_RE.test(nonce)) return bad('bad_signature');
    if (seenNonces.has(nonce)) return bad('replayed_request');
    if (sig.length < 8 || sig.length > 140) return bad('bad_signature');
    const data = Buffer.from([req.method, req.originalUrl, time, nonce, sha256hex(req.rawBody || Buffer.alloc(0))].join('\n'));
    let ok = false;
    try {
      ok = crypto.verify('sha256', data, key, sig);
    } catch (_e) {
      ok = false;
    }
    if (!ok) return bad('bad_signature');
    remember(nonce, t + 2 * SIGNATURE_WINDOW_MS);
    return next();
  };
  const signed = [ipLimiter, jsonBody, requireAdmin(true)];
  const tokenOnly = [ipLimiter, requireAdmin(false), jsonBody];

  const deleteFailures = { n: 0, first: 0, until: 0 };
  /** Verifies the delete password sent in the body. Answers the request itself and returns false when it is wrong. */
  async function passwordOk(req, res) {
    if (deleteFailures.until > Date.now()) {
      res.set('Retry-After', String(Math.ceil((deleteFailures.until - Date.now()) / 1000)));
      res.status(429).json({ success: false, error: 'password_locked' });
      return false;
    }
    const given = str(req.body && req.body.deletePassword, 128);
    const ok = given.length > 0 && await checkSecret(given, getMeta('delete_password'));
    if (ok) {
      deleteFailures.n = 0;
      return true;
    }
    if (Date.now() - deleteFailures.first > 15 * 60 * 1000) { deleteFailures.n = 0; deleteFailures.first = Date.now(); }
    deleteFailures.n += 1;
    if (deleteFailures.n >= 5) deleteFailures.until = Date.now() + 15 * 60 * 1000;
    res.status(403).json({ success: false, error: 'wrong_password' });
    return false;
  }

  // ---------------------------------------------------------------- setup of the owner's phone

  const setupAllowed = () => !getMeta('device_key') ||
    (config.adminResetNonce && config.adminResetNonce.length >= 16 && getMeta('reset_nonce_used') !== config.adminResetNonce);

  adminRouter.get('/state', ipLimiter, requireAdmin(false), guard(async (_req, res) => res.json({
    success: true,
    registered: !!getMeta('device_key'),
    setupAllowed: !!setupAllowed(),
    serverTime: Date.now()
  })));

  adminRouter.post('/setup', ...tokenOnly, guard(async (req, res) => {
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const key = parsePublicKey(body.devicePublicKey);
    const password = str(body.deletePassword, 128);
    if (!key || password.length < 8) return res.status(400).json({ success: false, error: 'invalid_request' });
    if (!setupAllowed()) return res.status(409).json({ success: false, error: 'already_registered' });
    const code = recoveryCode();
    const passwordHash = await hashSecret(password);
    const codeHash = await hashSecret(code);
    const reset = tx(() => {
      if (!setupAllowed()) return null;
      const was = !!getMeta('device_key');
      setMeta('device_key', exportKey(key));
      setMeta('delete_password', passwordHash);
      setMeta('recovery_hash', codeHash);
      setMeta('registered_at', Date.now());
      setMeta('reset_nonce_used', config.adminResetNonce || '');
      return { was };
    });
    if (!reset) return res.status(409).json({ success: false, error: 'already_registered' });
    ledger('ADMIN_DEVICE_REGISTERED', { reset: reset.was });
    return res.status(201).json({ success: true, recoveryCode: code });
  }));

  const recoveryFailures = { n: 0, first: 0, until: 0 };
  adminRouter.post('/rebind', ...tokenOnly, guard(async (req, res) => {
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const key = parsePublicKey(body.devicePublicKey);
    const given = str(body.recoveryCode, 40);
    if (!key || !/^\d{25}$/.test(given)) return res.status(400).json({ success: false, error: 'invalid_request' });
    if (!getMeta('device_key')) return res.status(409).json({ success: false, error: 'not_registered' });
    if (recoveryFailures.until > Date.now()) {
      res.set('Retry-After', String(Math.ceil((recoveryFailures.until - Date.now()) / 1000)));
      return res.status(429).json({ success: false, error: 'recovery_locked' });
    }
    if (!(await checkSecret(given, getMeta('recovery_hash')))) {
      if (Date.now() - recoveryFailures.first > 60 * 60 * 1000) { recoveryFailures.n = 0; recoveryFailures.first = Date.now(); }
      recoveryFailures.n += 1;
      if (recoveryFailures.n >= 5) recoveryFailures.until = Date.now() + 60 * 60 * 1000;
      return res.status(403).json({ success: false, error: 'wrong_recovery_code' });
    }
    recoveryFailures.n = 0;
    const fresh = recoveryCode();
    const freshHash = await hashSecret(fresh);
    tx(() => {
      setMeta('device_key', exportKey(key));
      setMeta('recovery_hash', freshHash);
    });
    ledger('ADMIN_DEVICE_REBOUND', {});
    return res.json({ success: true, recoveryCode: fresh });
  }));

  // ---------------------------------------------------------------- read: overview, vaults, ledger

  let overviewCache = { at: 0, data: null };
  adminRouter.get('/overview', ...signed, guard(async (_req, res) => {
    if (!overviewCache.data || Date.now() - overviewCache.at > 30000) {
      const now = Date.now();
      let dbBytes = 0;
      try { dbBytes = fs.statSync(store.path).size; } catch (_e) { dbBytes = 0; }
      const base = store.counts();
      overviewCache = {
        at: now,
        data: {
          users: base.users,
          newUsers24h: count('SELECT COUNT(*) AS n FROM users WHERE created_at > ?', now - DAY_MS),
          videos: base.videos,
          comments: count('SELECT COUNT(*) AS n FROM comments'),
          mediaFiles: base.media,
          mediaBytes: count('SELECT COALESCE(SUM(size), 0) AS n FROM media'),
          ads: base.ads,
          friendLinks: count("SELECT COUNT(*) AS n FROM friend_links WHERE status = 'accepted'"),
          friendRequests: count("SELECT COUNT(*) AS n FROM friend_links WHERE status = 'pending'"),
          chatMessages: count("SELECT COUNT(*) AS n FROM chat_events WHERE kind = 'message'"),
          calls: count('SELECT COUNT(*) AS n FROM call_log'),
          ledgerBlocks: base.ledgerBlocks,
          banned: count('SELECT COUNT(*) AS n FROM admin_bans'),
          deletedByAdmin: count("SELECT COUNT(*) AS n FROM admin_archive WHERE kind = 'admin' AND restored_at = 0"),
          deletedByUser: count("SELECT COUNT(*) AS n FROM admin_archive WHERE kind = 'self' AND restored_at = 0"),
          purgedTotal: count('SELECT COALESCE(SUM(purged), 0) AS n FROM admin_purge_stats'),
          dbBytes
        }
      };
    }
    return res.json({
      success: true,
      cachedAt: overviewCache.at,
      now: Date.now(),
      server: { uptimeSeconds: Math.floor(process.uptime()), node: process.version, memoryBytes: process.memoryUsage().rss },
      ...overviewCache.data
    });
  }));

  let vaultCache = { at: 0, data: null };
  adminRouter.get('/vaults', ...signed, guard(async (_req, res) => {
    if (!vaultCache.data || Date.now() - vaultCache.at > 30000) {
      const records = store.vaultRecords();
      const stats = store.getVaultStats();
      vaultCache = {
        at: Date.now(),
        data: VAULTS.map((v) => {
          const s = stats.get(v.no) || { ops: 0, errors: 0, lastOpAt: 0 };
          return { no: v.no, name: v.name, cluster: v.cluster, subVaults: v.subVaults, ops: s.ops, errors: s.errors, lastOpAt: s.lastOpAt, records: records[v.no] };
        })
      };
    }
    return res.json({ success: true, cachedAt: vaultCache.at, vaults: vaultCache.data });
  }));

  adminRouter.get('/ledger', ...signed, guard(async (req, res) => {
    const limit = clampInt(req.query.limit || 50, 1, 100);
    const before = clampInt(req.query.before || Number.MAX_SAFE_INTEGER, 1, Number.MAX_SAFE_INTEGER);
    const rows = stmt('SELECT seq, tx_id, source_vault, event_type, created_at, payload, vault_hash FROM ledger WHERE seq < ? ORDER BY seq DESC LIMIT ?').all(before, limit);
    return res.json({
      success: true,
      blocks: rows.map((r) => ({ seq: r.seq, txId: r.tx_id, vault: r.source_vault, event: r.event_type, createdAt: r.created_at, payload: r.payload, hash: r.vault_hash })),
      next: rows.length === limit ? rows[rows.length - 1].seq : null
    });
  }));

  adminRouter.get('/ledger/verify', ...signed, guard(async (_req, res) => res.json({ success: true, chainValid: store.verifyLedger(), checkedAt: Date.now() })));

  adminRouter.get('/actions', ...signed, guard(async (req, res) => {
    const limit = clampInt(req.query.limit || 50, 1, 100);
    const before = clampInt(req.query.before || Number.MAX_SAFE_INTEGER, 1, Number.MAX_SAFE_INTEGER);
    const rows = stmt('SELECT * FROM admin_actions WHERE id < ? ORDER BY id DESC LIMIT ?').all(before, limit);
    return res.json({
      success: true,
      actions: rows.map((r) => ({ id: r.id, at: r.at, action: r.action, target: r.target, detail: r.detail })),
      next: rows.length === limit ? rows[rows.length - 1].id : null
    });
  }));

  // ---------------------------------------------------------------- read: users

  const personOf = (r, base) => ({
    nexoraId: r.nexora_id,
    username: r.username,
    handle: r.handle,
    avatarUri: absolutize(r.avatar_uri, base)
  });

  adminRouter.get('/users', ...signed, guard(async (req, res) => {
    const base = publicBase(req, config);
    const limit = clampInt(req.query.limit || 30, 1, 100);
    const q = str(req.query.q, 100).trim();
    const item = (r) => ({
      ...personOf(r, base),
      email: r.email,
      createdAt: r.created_at,
      lastSeenAt: r.last_seen_at,
      status: stmt('SELECT 1 AS x FROM admin_bans WHERE nexora_id = ?').get(r.nexora_id) ? 'banned' : 'active'
    });
    if (!q) {
      const before = clampInt(req.query.before || Number.MAX_SAFE_INTEGER, 1, Number.MAX_SAFE_INTEGER);
      const rows = stmt('SELECT rowid AS rid, * FROM users WHERE rowid < ? ORDER BY rowid DESC LIMIT ?').all(before, limit);
      return res.json({ success: true, users: rows.map(item), next: rows.length === limit ? rows[rows.length - 1].rid : null });
    }
    let rows = [];
    if (NID_RE.test(q)) {
      rows = stmt('SELECT * FROM users WHERE nexora_id = ?').all(q);
    } else if (q.includes('@') && !q.startsWith('@')) {
      rows = stmt('SELECT * FROM users WHERE lower(email) = lower(?) LIMIT ?').all(q, limit);
    } else {
      const clean = q.replace(/^@+/, '').toLowerCase();
      const low = '@' + clean;
      rows = stmt("SELECT * FROM users WHERE handle <> '' AND lower(handle) >= ? AND lower(handle) < ? ORDER BY lower(handle) LIMIT ?").all(low, low + '￿', limit);
      if (rows.length < limit && clean.length >= 2) {
        const like = clean.replace(/[\\%_]/g, (c) => '\\' + c) + '%';
        const seen = new Set(rows.map((r) => r.nexora_id));
        for (const r of stmt("SELECT * FROM users WHERE username LIKE ? ESCAPE '\\' LIMIT ?").all(like, limit)) {
          if (!seen.has(r.nexora_id) && rows.length < limit) rows.push(r);
        }
      }
    }
    return res.json({ success: true, users: rows.map(item), next: null });
  }));

  adminRouter.get('/users/:id', ...signed, guard(async (req, res) => {
    const id = String(req.params.id || '');
    if (!NID_RE.test(id)) return res.status(400).json({ success: false, error: 'invalid_request' });
    const u = stmt('SELECT * FROM users WHERE nexora_id = ?').get(id);
    if (!u) return res.status(404).json({ success: false, error: 'not_found' });
    const base = publicBase(req, config);
    const ban = stmt('SELECT banned_at, reason FROM admin_bans WHERE nexora_id = ?').get(id);
    const media = stmt('SELECT COUNT(*) AS files, COALESCE(SUM(size), 0) AS bytes FROM media WHERE owner_id = ?').get(id);
    const sums = stmt('SELECT COUNT(*) AS n, COALESCE(SUM(views), 0) AS views, COALESCE(SUM(likes), 0) AS likes FROM videos WHERE owner_id = ?').get(id);
    return res.json({
      success: true,
      user: {
        ...personOf(u, base),
        email: u.email,
        createdAt: u.created_at,
        lastSeenAt: u.last_seen_at,
        hasPhone: u.phone !== '',
        hasBilling: u.billing !== ''
      },
      status: ban ? { state: 'banned', since: ban.banned_at, reason: ban.reason } : { state: 'active' },
      stats: {
        videos: Number(sums.n),
        views: Number(sums.views),
        likesReceived: Number(sums.likes),
        commentsWritten: count('SELECT COUNT(*) AS n FROM comments WHERE owner_id = ?', id),
        likesGiven: count('SELECT COUNT(*) AS n FROM video_likes WHERE user_id = ?', id),
        dislikesGiven: count('SELECT COUNT(*) AS n FROM video_dislikes WHERE user_id = ?', id),
        friends: count("SELECT COUNT(*) AS n FROM friend_links WHERE status = 'accepted' AND (requester_id = ? OR addressee_id = ?)", id, id),
        requestsReceived: count("SELECT COUNT(*) AS n FROM friend_links WHERE status = 'pending' AND addressee_id = ?", id),
        requestsSent: count("SELECT COUNT(*) AS n FROM friend_links WHERE status = 'pending' AND requester_id = ?", id),
        chatMessagesSent: count("SELECT COUNT(*) AS n FROM chat_events WHERE kind = 'message' AND sender_id = ?", id),
        chatMessagesReceived: count("SELECT COUNT(*) AS n FROM chat_events WHERE kind = 'message' AND recipient_id = ?", id),
        callsMade: count('SELECT COUNT(*) AS n FROM call_log WHERE caller_id = ?', id),
        callsReceived: count('SELECT COUNT(*) AS n FROM call_log WHERE callee_id = ?', id),
        mediaFiles: Number(media.files),
        mediaBytes: Number(media.bytes)
      },
      videos: stmt('SELECT id, title, visibility, views, likes, dislikes, shares, sparks, duration, created_at FROM videos WHERE owner_id = ? ORDER BY created_at DESC LIMIT 20')
        .all(id).map((v) => ({ id: v.id, title: v.title, visibility: v.visibility, views: v.views, likes: v.likes, dislikes: v.dislikes, shares: v.shares, sparks: v.sparks, duration: v.duration, createdAt: v.created_at })),
      comments: stmt('SELECT comment_id, video_id, body, like_count, created_at FROM comments WHERE owner_id = ? ORDER BY created_at DESC LIMIT 20')
        .all(id).map((c) => ({ commentId: c.comment_id, videoId: c.video_id, body: str(c.body, 300), likes: c.like_count, createdAt: c.created_at })),
      friends: stmt(
        `SELECT x.* FROM friend_links l JOIN users x ON x.nexora_id = CASE WHEN l.requester_id = ? THEN l.addressee_id ELSE l.requester_id END
         WHERE l.status = 'accepted' AND (l.requester_id = ? OR l.addressee_id = ?) LIMIT 100`
      ).all(id, id, id).map((r) => personOf(r, base)),
      calls: stmt('SELECT * FROM call_log WHERE caller_id = ? OR callee_id = ? ORDER BY ended_at DESC LIMIT 20').all(id, id).map((c) => ({
        callId: c.call_id, direction: c.caller_id === id ? 'out' : 'in', with: c.caller_id === id ? c.callee_id : c.caller_id,
        video: c.video === 1, outcome: c.outcome, createdAt: c.created_at, answeredAt: c.answered_at, endedAt: c.ended_at
      }))
    });
  }));

  adminRouter.post('/users/:id/private', ...signed, guard(async (req, res) => {
    const id = String(req.params.id || '');
    if (!NID_RE.test(id)) return res.status(400).json({ success: false, error: 'invalid_request' });
    const u = stmt('SELECT phone, billing FROM users WHERE nexora_id = ?').get(id);
    if (!u) return res.status(404).json({ success: false, error: 'not_found' });
    logAction('VIEW_PRIVATE', id);
    ledger('ADMIN_VIEW_PRIVATE', { target: id });
    return res.json({ success: true, phoneNumber: u.phone, billingInfo: u.billing });
  }));

  // ---------------------------------------------------------------- read: videos, comments, archive, bans

  adminRouter.get('/videos', ...signed, guard(async (req, res) => {
    const limit = clampInt(req.query.limit || 30, 1, 100);
    const before = clampInt(req.query.before || Number.MAX_SAFE_INTEGER, 1, Number.MAX_SAFE_INTEGER);
    const rows = stmt(
      `SELECT v.rowid AS rid, v.id, v.owner_id, v.title, v.visibility, v.views, v.likes, v.dislikes, v.shares, v.sparks, v.duration, v.created_at,
              COALESCE(NULLIF(u.username, ''), u.handle) AS owner_name
       FROM videos v LEFT JOIN users u ON u.nexora_id = v.owner_id WHERE v.rowid < ? ORDER BY v.rowid DESC LIMIT ?`
    ).all(before, limit);
    return res.json({
      success: true,
      videos: rows.map((v) => ({ id: v.id, ownerId: v.owner_id, ownerName: v.owner_name || '', title: v.title, visibility: v.visibility, views: v.views, likes: v.likes, dislikes: v.dislikes, shares: v.shares, sparks: v.sparks, duration: v.duration, createdAt: v.created_at })),
      next: rows.length === limit ? rows[rows.length - 1].rid : null
    });
  }));

  adminRouter.get('/comments', ...signed, guard(async (req, res) => {
    const limit = clampInt(req.query.limit || 30, 1, 100);
    const before = clampInt(req.query.before || Number.MAX_SAFE_INTEGER, 1, Number.MAX_SAFE_INTEGER);
    const rows = stmt('SELECT rowid AS rid, comment_id, video_id, owner_id, author_name, body, like_count, created_at FROM comments WHERE rowid < ? ORDER BY rowid DESC LIMIT ?').all(before, limit);
    return res.json({
      success: true,
      comments: rows.map((c) => ({ commentId: c.comment_id, videoId: c.video_id, ownerId: c.owner_id, author: c.author_name, body: str(c.body, 300), likes: c.like_count, createdAt: c.created_at })),
      next: rows.length === limit ? rows[rows.length - 1].rid : null
    });
  }));

  adminRouter.get('/archive', ...signed, guard(async (req, res) => {
    const base = publicBase(req, config);
    const limit = clampInt(req.query.limit || 30, 1, 100);
    const before = clampInt(req.query.before || Number.MAX_SAFE_INTEGER, 1, Number.MAX_SAFE_INTEGER);
    const rows = stmt('SELECT id, nexora_id, kind, username, handle, avatar_uri, reason, created_at, restored_at FROM admin_archive WHERE id < ? ORDER BY id DESC LIMIT ?').all(before, limit);
    return res.json({
      success: true,
      entries: rows.map((r) => ({
        id: r.id, nexoraId: r.nexora_id, kind: r.kind, username: r.username, handle: r.handle, avatarUri: absolutize(r.avatar_uri, base),
        reason: r.reason, deletedAt: r.created_at, restoredAt: r.restored_at,
        purgeAt: r.kind === 'self' && r.restored_at === 0 ? r.created_at + SELF_DELETE_DAYS * DAY_MS : 0
      })),
      next: rows.length === limit ? rows[rows.length - 1].id : null
    });
  }));

  adminRouter.get('/bans', ...signed, guard(async (req, res) => {
    const base = publicBase(req, config);
    const rows = stmt('SELECT b.nexora_id, b.banned_at, b.reason, u.username, u.handle, u.avatar_uri FROM admin_bans b LEFT JOIN users u ON u.nexora_id = b.nexora_id ORDER BY b.banned_at DESC LIMIT 200').all();
    return res.json({
      success: true,
      bans: rows.map((r) => ({ nexoraId: r.nexora_id, username: r.username || '', handle: r.handle || '', avatarUri: absolutize(r.avatar_uri || '', base), bannedAt: r.banned_at, reason: r.reason }))
    });
  }));

  // ---------------------------------------------------------------- write: ban, unban, delete, restore (delete password required)

  const targetOf = (req, res) => {
    const id = String(req.params.id || '');
    if (!NID_RE.test(id)) {
      res.status(400).json({ success: false, error: 'invalid_request' });
      return null;
    }
    return id;
  };

  adminRouter.post('/users/:id/ban', ...signed, guard(async (req, res) => {
    const id = targetOf(req, res);
    if (!id) return undefined;
    if (!(await passwordOk(req, res))) return undefined;
    const reason = str(req.body && req.body.reason, 300).trim();
    const outcome = tx(() => {
      if (!stmt('SELECT 1 AS x FROM users WHERE nexora_id = ?').get(id)) return 'not_found';
      if (stmt('SELECT 1 AS x FROM admin_bans WHERE nexora_id = ?').get(id)) return 'already_banned';
      const hidden = stmt("SELECT id FROM videos WHERE owner_id = ? AND visibility = 'Public'").all(id).map((r) => r.id);
      for (const videoId of hidden) stmt("UPDATE videos SET visibility = 'Private' WHERE id = ?").run(videoId);
      stmt('INSERT INTO admin_bans (nexora_id, banned_at, reason, hidden_json) VALUES (?, ?, ?, ?)').run(id, Date.now(), reason, JSON.stringify(hidden));
      logAction('BAN', id, { reason, hiddenVideos: hidden.length });
      return 'ok';
    });
    if (outcome === 'not_found') return res.status(404).json({ success: false, error: 'not_found' });
    if (outcome === 'already_banned') return res.status(409).json({ success: false, error: 'already_banned' });
    ledger('ADMIN_USER_BANNED', { target: id });
    return res.json({ success: true });
  }));

  adminRouter.post('/users/:id/unban', ...signed, guard(async (req, res) => {
    const id = targetOf(req, res);
    if (!id) return undefined;
    if (!(await passwordOk(req, res))) return undefined;
    const outcome = tx(() => {
      const ban = stmt('SELECT hidden_json FROM admin_bans WHERE nexora_id = ?').get(id);
      if (!ban) return 'not_banned';
      let hidden = [];
      try { hidden = JSON.parse(ban.hidden_json); } catch (_e) { hidden = []; }
      for (const videoId of hidden) stmt("UPDATE videos SET visibility = 'Public' WHERE id = ? AND owner_id = ? AND visibility = 'Private'").run(videoId, id);
      stmt('DELETE FROM admin_bans WHERE nexora_id = ?').run(id);
      logAction('UNBAN', id, {});
      return 'ok';
    });
    if (outcome === 'not_banned') return res.status(409).json({ success: false, error: 'not_banned' });
    ledger('ADMIN_USER_UNBANNED', { target: id });
    return res.json({ success: true });
  }));

  adminRouter.post('/users/:id/delete', ...signed, guard(async (req, res) => {
    const id = targetOf(req, res);
    if (!id) return undefined;
    if (!(await passwordOk(req, res))) return undefined;
    const reason = str(req.body && req.body.reason, 300).trim();
    const result = archiveUser(id, 'admin', reason);
    if (result.error) return res.status(result.error === 'not_found' ? 404 : 413).json({ success: false, error: result.error });
    logAction('DELETE', id, { reason, archiveId: result.archiveId, rows: result.rows });
    ledger('ADMIN_USER_DELETED', { target: id });
    overviewCache.at = 0;
    return res.json({ success: true, archiveId: result.archiveId, rows: result.rows });
  }));

  adminRouter.post('/archive/:id/restore', ...signed, guard(async (req, res) => {
    const archiveId = clampInt(req.params.id, 0, Number.MAX_SAFE_INTEGER);
    if (archiveId < 1) return res.status(400).json({ success: false, error: 'invalid_request' });
    if (!(await passwordOk(req, res))) return undefined;
    const result = restoreArchive(archiveId);
    if (result.error) return res.status(result.error === 'not_found' ? 404 : 409).json({ success: false, error: result.error });
    logAction('RESTORE', result.nexoraId, { archiveId, rows: result.rows });
    ledger('ADMIN_USER_RESTORED', { target: result.nexoraId });
    overviewCache.at = 0;
    return res.json({ success: true, nexoraId: result.nexoraId, rows: result.rows });
  }));

  return { enabled: true, router: adminRouter, selfRouter, banGate, close() { clearInterval(purgeTimer); adb.close(); } };
}

module.exports = { createAdmin, MIN_TOKEN_CHARS, SELF_DELETE_DAYS };
