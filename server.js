'use strict';
/* © 2026 Zentora CLC. All rights reserved. Platform Core engineered by Zentora. */
/**
 * Nexora backend (self-hosted): Express + SQLite (node:sqlite) + local media storage.
 * Architecture: a 30-chain-server mesh (mesh.js) in front of 35 categorized vaults (vaults.js, db.js), secured by
 * Vault 35, the SHA-256 hash-chained master ledger.
 * No Firebase, no third-party database, no third-party storage. The only external call is the
 * verification of the Google ID token the phone obtained at sign-in.
 *
 * Required environment:
 *   GOOGLE_WEB_CLIENT_ID  OAuth *Web* client id (same value as GOOGLE_WEB_CLIENT_ID in the app)
 *   NEXORA_ID_SECRET      16+ random characters. Never change it: every nexoraId is derived from it.
 * Strongly recommended:
 *   NEXORA_DATA_DIR       directory on a PERSISTENT disk (database + uploaded media live here)
 * Optional:
 *   PUBLIC_BASE_URL, ADMIN_USER, ADMIN_PASSWORD, MAX_VIDEO_MB, MAX_IMAGE_MB, USER_QUOTA_MB, PORT,
 *   REQUIRE_HTTPS (true = chain server 2 rejects plain http), MESH_RATE_PER_MINUTE, MESH_BURST_PER_SECOND
 */
const crypto = require('crypto');
const path = require('path');
const express = require('express');
const cors = require('cors');
const { createSqliteStore } = require('./db');
const { createAuth } = require('./auth');
const { createUserRouter } = require('./user-routes');
const { createContentRouter, cleanupStaleUploads } = require('./content-routes');
const { createMesh } = require('./mesh');
const { VAULTS, VAULT_COUNT, vaultByNo, vaultCode } = require('./vaults');
const { str, clampInt, isHttpsUrl, guard } = require('./util');

const MB = 1024 * 1024;

function loadConfig(env = process.env) {
  const dataDir = path.resolve(env.NEXORA_DATA_DIR || path.join(__dirname, 'data'));
  return {
    port: clampInt(env.PORT || 3000, 1, 65535),
    dataDir,
    dbPath: path.join(dataDir, 'nexora.db'),
    mediaDir: path.join(dataDir, 'media'),
    tmpDir: path.join(dataDir, 'uploads-tmp'),
    idSecret: env.NEXORA_ID_SECRET || '',
    googleAudiences: String(env.GOOGLE_WEB_CLIENT_ID || '').split(',').map((s) => s.trim()).filter(Boolean),
    publicBaseUrl: env.PUBLIC_BASE_URL || '',
    adminUser: env.ADMIN_USER || 'admin',
    adminPassword: env.ADMIN_PASSWORD || '',
    maxVideoBytes: clampInt(env.MAX_VIDEO_MB || 500, 1, 20000) * MB,
    maxImageBytes: clampInt(env.MAX_IMAGE_MB || 10, 1, 200) * MB,
    quotaBytes: clampInt(env.USER_QUOTA_MB || 2048, 1, 1000000) * MB,
    chunkBytes: 8 * MB,
    requireHttps: String(env.REQUIRE_HTTPS || '').toLowerCase() === 'true',
    meshRatePerMinute: clampInt(env.MESH_RATE_PER_MINUTE || 1200, 10, 1000000),
    meshBurstPerSecond: clampInt(env.MESH_BURST_PER_SECOND || 60, 1, 100000)
  };
}

/** Verifies a Google ID token (signature, expiry, issuer, audience). The package is loaded lazily. */
function defaultGoogleVerifier() {
  const { OAuth2Client } = require('google-auth-library');
  const client = new OAuth2Client();
  return async (idToken, audiences) => {
    const ticket = await client.verifyIdToken({ idToken, audience: audiences });
    return ticket.getPayload();
  };
}

function safeEqual(a, b) {
  const ha = crypto.createHash('sha256').update(String(a)).digest();
  const hb = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}

function requireAdmin(config) {
  return (req, res, next) => {
    if (!config.adminPassword) return res.status(404).json({ success: false, error: 'admin_disabled' });
    const m = /^Basic (.+)$/.exec(req.get('authorization') || '');
    const decoded = m ? Buffer.from(m[1], 'base64').toString('utf8') : '';
    const idx = decoded.indexOf(':');
    const user = idx >= 0 ? decoded.slice(0, idx) : '';
    const pass = idx >= 0 ? decoded.slice(idx + 1) : '';
    if (idx < 0 || !safeEqual(user, config.adminUser) || !safeEqual(pass, config.adminPassword)) {
      res.set('WWW-Authenticate', 'Basic realm="Nexora Admin", charset="UTF-8"');
      return res.status(401).json({ success: false, error: 'unauthorized' });
    }
    return next();
  };
}

const ADMIN_PAGE = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Nexora Ads Admin</title>
<style>body{font-family:system-ui,sans-serif;max-width:520px;margin:32px auto;padding:0 16px}label{display:block;margin-top:12px;font-weight:600}
input{width:100%;padding:10px;margin-top:4px;box-sizing:border-box}button{margin-top:16px;padding:12px 18px}pre{background:#f3f3f3;padding:12px;overflow:auto}</style>
</head><body><h1>Create ad</h1>
<form id="f">
<label>Title<input name="title" required maxlength="100"></label>
<label>Sponsor<input name="sponsorName" required maxlength="60"></label>
<label>Ad media URL (https)<input name="adMediaUrl" type="url" required></label>
<label>Click-through URL (https)<input name="clickThroughUrl" type="url" required></label>
<label>Skippable after (seconds, 0-30)<input name="skippableAfterSeconds" type="number" min="0" max="30" value="5" required></label>
<button type="submit">Create</button></form><pre id="out"></pre>
<script>
document.getElementById('f').addEventListener('submit', async function (e) {
  e.preventDefault();
  var d = Object.fromEntries(new FormData(e.target));
  d.skippableAfterSeconds = Number(d.skippableAfterSeconds);
  var r = await fetch('/api/v1/ads/admin', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(d) });
  document.getElementById('out').textContent = r.status + ' ' + await r.text();
});
</script></body></html>`;

function createApp({ config, store, googleVerifier }) {
  const auth = createAuth({
    idSecret: config.idSecret,
    googleAudiences: config.googleAudiences,
    googleVerifier: googleVerifier || defaultGoogleVerifier(),
    store
  });

  const app = express();
  app.set('trust proxy', 1);
  app.disable('x-powered-by');
  app.use(cors({ exposedHeaders: ['X-Nexora-Session-Token', 'X-Nexora-Mesh', 'X-Request-Id'] }));
  const mesh = createMesh({ store, config });
  app.use(mesh.middleware);
  app.use((_req, res, next) => {
    res.set('X-Content-Type-Options', 'nosniff');
    next();
  });

  const health = (_req, res) => res.json({ status: 'ok', service: 'nexora-backend', time: Date.now() });
  app.get('/', health);
  app.get('/health', health);

  app.use('/media', express.static(config.mediaDir, {
    index: false,
    dotfiles: 'ignore',
    maxAge: '365d',
    immutable: true,
    setHeaders: (res) => res.set('X-Content-Type-Options', 'nosniff')
  }));

  app.use('/api/v1/account', createUserRouter({ store, auth, config }));
  app.use('/api/v1', createContentRouter({ store, auth, config }));

  /** Vault 35: the audit of the whole platform. chainValid re-computes every block of the ledger. */
  app.get('/api/v1/vaults/audit', guard(async (_req, res) => {
    const records = await store.vaultRecords();
    const stats = mesh.vaultStats();
    const vaults = {};
    for (const v of VAULTS) {
      const s = stats[v.no - 1];
      vaults['vault' + String(v.no).padStart(2, '0')] = {
        no: v.no, name: v.name, cluster: v.cluster, subVaults: v.subVaults,
        ops: s.ops, errors: s.errors, lastOpAt: s.lastOpAt, breaker: s.breaker, records: records[v.no]
      };
    }
    return res.json({
      status: 'ONLINE',
      system: 'Zentora Nexora Platform Core',
      storage: { engine: 'sqlite', persistent: true },
      mesh: { chainServers: mesh.STAGE_COUNT, egressGateway: 30 },
      vaultCount: VAULT_COUNT,
      ledger: { blocks: records[35].blocks, head: records[35].head, chainValid: await store.verifyLedger() },
      vaults,
      timestamp: Date.now()
    });
  }));

  app.get('/api/v1/mesh/status', guard(async (_req, res) => res.json({
    success: true,
    chainServers: mesh.describe(),
    vaults: mesh.vaultStats().map((s) => ({ ...s, name: vaultByNo(s.no).name })),
    timestamp: Date.now()
  })));

  app.get('/api/v1/vaults/:no', guard(async (req, res) => {
    const no = Number(req.params.no);
    const vault = Number.isInteger(no) ? vaultByNo(no) : null;
    if (!vault) return res.status(404).json({ success: false, error: 'not_found' });
    const records = await store.vaultRecords();
    const stats = mesh.vaultStats()[no - 1];
    return res.json({ success: true, vault: { ...vault, ...stats, code: vaultCode(no), records: records[no] } });
  }));

  /** Seals the current state of vaults 1..34 into one ledger block (also runs every hour). */
  app.post('/api/v1/vaults/checkpoint', requireAdmin(config), guard(async (_req, res) => {
    const block = await store.checkpointVaults();
    return res.status(201).json({ success: true, txId: block.txId, vaultHash: block.vaultHash });
  }));

  // ------------------------------------------------------------------ ads (vault 02)
  const adminOnly = requireAdmin(config);
  app.get('/admin', adminOnly, (_req, res) => res.set('Content-Type', 'text/html; charset=utf-8').send(ADMIN_PAGE));

  app.post('/api/v1/ads/admin', adminOnly, express.json({ limit: '16kb' }), guard(async (req, res) => {
    const b = req.body && typeof req.body === 'object' ? req.body : {};
    const title = str(b.title, 100).trim();
    const sponsorName = str(b.sponsorName, 60).trim();
    if (!title || !sponsorName || !isHttpsUrl(b.adMediaUrl) || !isHttpsUrl(b.clickThroughUrl)) {
      return res.status(400).json({ success: false, error: 'invalid_ad' });
    }
    const ad = {
      adId: 'ad_' + crypto.randomBytes(8).toString('hex'),
      title,
      sponsorName,
      adMediaUrl: b.adMediaUrl,
      clickThroughUrl: b.clickThroughUrl,
      skippableAfterSeconds: clampInt(b.skippableAfterSeconds, 0, 30)
    };
    await store.createAd(ad);
    await store.anchor('AD_CREATED', 'VAULT_02', { adId: ad.adId });
    return res.status(201).json({ success: true, adId: ad.adId });
  }));

  app.get('/api/v1/ads/next', guard(async (_req, res) => {
    const ad = await store.pickRandomAd();
    return res.json({ success: true, ad: ad ? { ...ad, metrics: undefined } : null });
  }));

  app.post('/api/v1/ads/track', express.json({ limit: '4kb' }), guard(async (req, res) => {
    const b = req.body && typeof req.body === 'object' ? req.body : {};
    const metrics = await store.trackAd(str(b.adId, 40), str(b.action, 16));
    if (!metrics) return res.status(404).json({ success: false, error: 'not_found' });
    return res.json({ success: true });
  }));

  app.use((_req, res) => res.status(404).json({ success: false, error: 'not_found' }));

  // eslint-disable-next-line no-unused-vars
  app.use((err, _req, res, _next) => {
    const status = err && (err.status || err.statusCode) ? err.status || err.statusCode : 500;
    if (status >= 500) console.error('[nexora] unhandled', err && err.stack ? err.stack : err);
    if (res.headersSent) return res.end();
    return res.status(status).json({ success: false, error: status === 413 ? 'payload_too_large' : status === 400 ? 'bad_request' : 'unavailable' });
  });

  return { app, auth, mesh };
}

function main() {
  const config = loadConfig();
  if (config.idSecret.length < 16) throw new Error('NEXORA_ID_SECRET must be set to 16+ random characters');
  if (config.googleAudiences.length === 0) throw new Error('GOOGLE_WEB_CLIENT_ID must be set');
  const store = createSqliteStore({ dbPath: config.dbPath });
  const { app, mesh } = createApp({ config, store });

  const sweep = () => cleanupStaleUploads({ store, tmpDir: config.tmpDir, maxAgeMs: 24 * 60 * 60 * 1000 })
    .catch((e) => console.error('[nexora] upload cleanup failed', e && e.message));
  sweep();
  const timer = setInterval(sweep, 60 * 60 * 1000);
  timer.unref();

  const checkpoint = () => {
    try {
      store.checkpointVaults();
    } catch (e) {
      console.error('[nexora] vault checkpoint failed', e && e.message);
    }
  };
  checkpoint();
  const checkpointTimer = setInterval(checkpoint, 60 * 60 * 1000);
  checkpointTimer.unref();

  const server = app.listen(config.port, () => {
    console.log(`[nexora] listening on ${config.port}, data dir ${config.dataDir}`);
  });
  server.requestTimeout = 0;
  server.headersTimeout = 65 * 1000;
  server.keepAliveTimeout = 65 * 1000;

  const shutdown = () => {
    server.close(() => {
      mesh.close();
      store.close();
      process.exit(0);
    });
    setTimeout(() => process.exit(0), 10000).unref();
  };
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
}

if (require.main === module) main();

module.exports = { createApp, loadConfig, defaultGoogleVerifier };
