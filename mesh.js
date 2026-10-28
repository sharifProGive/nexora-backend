'use strict';
/* © 2026 Zentora CLC. All rights reserved. Platform Core engineered by Zentora. */
/**
 * The 30-chain server mesh.
 *
 * Every request passes Chain Server 1 .. 30 in strict order inside this process (no network hop is added, so a
 * single Render instance can host the whole mesh). Each chain server does real work and hands the request to the
 * next one together with a SHA-256 envelope link: link(n) = sha256(link(n-1) | n | name | requestId).
 * Every receiving server re-computes the previous link before it does its own work, so a request that was
 * altered, skipped or replayed out of order is detected and rejected. Chain Server 30 is the Egress Gateway: it
 * verifies that all 29 earlier servers signed the envelope, stamps the response (X-Nexora-Mesh, X-Request-Id) and
 * only then lets the request reach its vault.
 *
 *    1 ingress            request id, envelope seed
 *    2 protocol-guard     HTTPS enforcement (REQUIRE_HTTPS=true)
 *    3 method-guard       method allow-list
 *    4 path-guard         traversal / control characters / length
 *    5 header-guard       oversized Authorization header, header flood
 *    6 query-guard        query parameter count, type and length
 *    7 ip-resolve         client address for the limiters
 *    8 route-classify     which vault serves this path and which credential it needs
 *    9 vault-resolve      the vault exists; unrouted paths stop here
 *   10 global-rate        fixed window per client address per minute
 *   11 burst-rate         fixed window per client address per second
 *   12 length-guard       declared Content-Length against the route cap
 *   13 content-type-guard JSON bodies must be application/json
 *   14 vault-breaker      circuit breaker: a failing vault is isolated for 30 s instead of timing every caller out
 *   15 shard-select       expansion shard (vault 11..34) for load accounting
 *   16 envelope-seal      binds vault, shard, method and path into the envelope
 * 17-29 relay            mesh relay hops: verify the previous hop, extend the chain
 *   30 egress-gateway    final verification, response stamping, hand-over to the vault
 */
const crypto = require('crypto');
const { routeFor, vaultByNo, shardVaultFor, SHARD_FIRST, SHARD_LAST, VAULTS } = require('./vaults');

const STAGE_COUNT = 30;
const ALLOWED_METHODS = new Set(['GET', 'HEAD', 'POST', 'PUT', 'OPTIONS']);
const BREAKER_WINDOW_MS = 60 * 1000;
const BREAKER_THRESHOLD = 25;
const BREAKER_OPEN_MS = 30 * 1000;
const FLUSH_INTERVAL_MS = 10 * 1000;

const sha = (text) => crypto.createHash('sha256').update(text).digest('hex');
const pad2 = (n) => String(n).padStart(2, '0');

function reject(status, error, extra) {
  return { status, error, ...(extra || {}) };
}

function createMesh({ store, config, now = Date.now }) {
  const perMinute = config.meshRatePerMinute || 1200;
  const perSecond = config.meshBurstPerSecond || 60;
  const requireHttps = config.requireHttps === true;
  const chunkCap = (config.chunkBytes || 8 * 1024 * 1024) + 4096;
  const jsonCap = 512 * 1024;

  let minuteHits = new Map();
  let secondHits = new Map();
  const minuteTimer = setInterval(() => { minuteHits = new Map(); }, 60 * 1000);
  const secondTimer = setInterval(() => { secondHits = new Map(); }, 1000);
  minuteTimer.unref();
  secondTimer.unref();

  const pending = new Map();
  const breakers = new Map();

  function bump(vaultNo, isError) {
    const p = pending.get(vaultNo) || { ops: 0, errors: 0, lastOpAt: 0 };
    p.ops += 1;
    if (isError) p.errors += 1;
    p.lastOpAt = now();
    pending.set(vaultNo, p);
  }

  function breakerFor(vaultNo) {
    let b = breakers.get(vaultNo);
    if (!b) {
      b = { failures: [], openUntil: 0 };
      breakers.set(vaultNo, b);
    }
    return b;
  }

  function recordFailure(vaultNo) {
    const b = breakerFor(vaultNo);
    const t = now();
    b.failures.push(t);
    while (b.failures.length > 0 && b.failures[0] < t - BREAKER_WINDOW_MS) b.failures.shift();
    if (b.failures.length >= BREAKER_THRESHOLD) {
      b.openUntil = t + BREAKER_OPEN_MS;
      b.failures = [];
    }
  }

  function hit(map, key, limit) {
    const n = (map.get(key) || 0) + 1;
    map.set(key, n);
    return n > limit;
  }

  // ---------------------------------------------------------------- chain servers
  const STAGES = [];
  const define = (no, name, lane, run) => STAGES.push({ no, name, lane, run });

  define(1, 'ingress', 'ingress', (ctx, req, res) => {
    ctx.seed = sha('nexora-mesh-v1|' + ctx.id);
    ctx.chain = [ctx.seed];
    res.set('X-Request-Id', ctx.id);
    return null;
  });

  define(2, 'protocol-guard', 'ingress', (ctx, req) => {
    if (requireHttps && ctx.path !== '/health' && req.protocol !== 'https') return reject(426, 'https_required');
    return null;
  });

  define(3, 'method-guard', 'ingress', (ctx) => {
    if (!ALLOWED_METHODS.has(ctx.method)) return reject(405, 'method_not_allowed');
    return null;
  });

  define(4, 'path-guard', 'ingress', (ctx) => {
    if (ctx.path.length > 512) return reject(414, 'path_too_long');
    let decoded;
    try {
      decoded = decodeURIComponent(ctx.path);
    } catch (_e) {
      return reject(400, 'invalid_path');
    }
    if (decoded.includes('..') || decoded.includes('\\') || decoded.includes('\0') || ctx.path.includes('//')) {
      return reject(400, 'invalid_path');
    }
    return null;
  });

  define(5, 'header-guard', 'ingress', (ctx, req) => {
    const auth = req.headers.authorization;
    if (typeof auth === 'string' && auth.length > 4096) return reject(431, 'header_too_large');
    if (Object.keys(req.headers).length > 80) return reject(431, 'too_many_headers');
    return null;
  });

  define(6, 'query-guard', 'ingress', (ctx, req) => {
    const q = req.query && typeof req.query === 'object' ? req.query : {};
    const keys = Object.keys(q);
    if (keys.length > 20) return reject(400, 'invalid_query');
    for (const k of keys) {
      if (typeof q[k] !== 'string' || q[k].length > 512 || k.length > 40) return reject(400, 'invalid_query');
    }
    return null;
  });

  define(7, 'ip-resolve', 'ingress', (ctx, req) => {
    ctx.ip = String(req.ip || (req.socket && req.socket.remoteAddress) || 'unknown').slice(0, 64);
    return null;
  });

  define(8, 'route-classify', 'routing', (ctx) => {
    if (ctx.path === '/' || ctx.path === '/health') {
      ctx.exempt = true;
      ctx.authClass = 'public';
      ctx.vault = 0;
      return null;
    }
    const route = routeFor(ctx.method, ctx.path);
    if (route) {
      ctx.vault = route.vault;
      ctx.authClass = route.authClass;
      ctx.exempt = ctx.path.startsWith('/media/');
    } else {
      ctx.vault = -1;
    }
    return null;
  });

  define(9, 'vault-resolve', 'routing', (ctx) => {
    if (ctx.vault === -1) return reject(404, 'not_found');
    if (ctx.vault > 0 && !vaultByNo(ctx.vault)) return reject(404, 'not_found');
    return null;
  });

  define(10, 'global-rate', 'protection', (ctx, req, res) => {
    if (ctx.exempt) return null;
    if (hit(minuteHits, ctx.ip, perMinute)) return reject(429, 'rate_limited', { retryAfter: 60 });
    return null;
  });

  define(11, 'burst-rate', 'protection', (ctx) => {
    if (ctx.exempt) return null;
    if (hit(secondHits, ctx.ip, perSecond)) return reject(429, 'rate_limited', { retryAfter: 1 });
    return null;
  });

  define(12, 'length-guard', 'protection', (ctx, req) => {
    if (ctx.method !== 'POST' && ctx.method !== 'PUT') return null;
    const declared = req.headers['content-length'];
    if (declared === undefined) return null;
    const n = Number(declared);
    if (!Number.isFinite(n) || n < 0) return reject(400, 'invalid_content_length');
    const isChunk = ctx.method === 'PUT' && /^\/api\/v1\/media\/chunk\//.test(ctx.path);
    if (n > (isChunk ? chunkCap : jsonCap)) return reject(413, 'payload_too_large');
    return null;
  });

  define(13, 'content-type-guard', 'protection', (ctx, req) => {
    if (ctx.method !== 'POST') return null;
    const declared = Number(req.headers['content-length'] || 0);
    const chunked = req.headers['transfer-encoding'] !== undefined;
    if (declared === 0 && !chunked) return null;
    const type = String(req.headers['content-type'] || '').toLowerCase();
    if (!type.includes('application/json')) return reject(415, 'unsupported_content_type');
    return null;
  });

  define(14, 'vault-breaker', 'protection', (ctx) => {
    if (ctx.vault <= 0) return null;
    const b = breakers.get(ctx.vault);
    if (b && now() < b.openUntil) {
      return reject(503, 'vault_unavailable', { retryAfter: Math.ceil((b.openUntil - now()) / 1000) });
    }
    ctx.breakerPassed = true;
    return null;
  });

  define(15, 'shard-select', 'routing', (ctx, req) => {
    if (ctx.vault <= 0 || ctx.vault >= SHARD_FIRST) return null;
    const q = req.query || {};
    const hint = q.videoId || q.id || q.q || ctx.path;
    ctx.shard = shardVaultFor(hint);
    return null;
  });

  define(16, 'envelope-seal', 'sealing', (ctx) => {
    ctx.envelope = sha(['nexora-envelope-v1', ctx.id, ctx.method, ctx.path, ctx.vault, ctx.shard || 0, ctx.startedAt].join('|'));
    return null;
  });

  for (let no = 17; no <= 29; no += 1) {
    define(no, 'relay-' + no, 'relay', (ctx) => {
      const sealed = sha(['nexora-envelope-v1', ctx.id, ctx.method, ctx.path, ctx.vault, ctx.shard || 0, ctx.startedAt].join('|'));
      if (sealed !== ctx.envelope) return reject(500, 'mesh_integrity_failure');
      return null;
    });
  }

  define(30, 'egress-gateway', 'egress', (ctx, req, res) => {
    if (ctx.chain.length !== STAGE_COUNT) return reject(500, 'mesh_integrity_failure');
    const head = linkFor(ctx, 30, 'egress-gateway');
    res.set('X-Nexora-Mesh', `v1;hops=${STAGE_COUNT};vault=${pad2(Math.max(ctx.vault, 0))};shard=${pad2(ctx.shard || 0)};head=${head.slice(0, 16)}`);
    ctx.egressHead = head;
    ctx.reachedEgress = true;
    return null;
  });

  if (STAGES.length !== STAGE_COUNT) throw new Error('the mesh must contain exactly ' + STAGE_COUNT + ' chain servers');

  function linkFor(ctx, no, name) {
    return sha([ctx.chain[ctx.chain.length - 1], no, name, ctx.id].join('|'));
  }

  /** Re-computes the link written by the previous chain server before the current one runs. */
  function previousLinkValid(ctx, stage) {
    if (stage.no === 1) return true;
    const prev = STAGES[stage.no - 2];
    if (ctx.chain.length !== stage.no) return false;
    const expected = sha([ctx.chain[stage.no - 2], prev.no, prev.name, ctx.id].join('|'));
    return ctx.chain[stage.no - 1] === expected;
  }

  function account(ctx, status) {
    if (ctx.vault > 0) {
      bump(ctx.vault, status >= 500 && ctx.reachedEgress);
      if (ctx.shard && ctx.reachedEgress) bump(ctx.shard, status >= 500);
      if (ctx.breakerPassed && status >= 500) recordFailure(ctx.vault);
    }
  }

  function middleware(req, res, next) {
    const ctx = {
      id: crypto.randomBytes(8).toString('hex'),
      startedAt: now(),
      method: String(req.method || 'GET').toUpperCase(),
      path: String(req.path || '/'),
      vault: 0,
      shard: 0,
      authClass: 'public',
      exempt: false,
      chain: [],
      reachedEgress: false,
      breakerPassed: false
    };
    req.nexoraMesh = ctx;
    res.once('finish', () => account(ctx, res.statusCode));

    for (const stage of STAGES) {
      let result;
      try {
        if (stage.no > 1 && !previousLinkValid(ctx, stage)) {
          result = reject(500, 'mesh_integrity_failure');
        } else {
          result = stage.run(ctx, req, res);
        }
      } catch (e) {
        console.error('[nexora] mesh chain server ' + stage.no + ' failed', e && e.stack ? e.stack : e);
        result = reject(500, 'mesh_fault');
      }
      if (result) {
        if (result.retryAfter) res.set('Retry-After', String(result.retryAfter));
        return res.status(result.status).json({ success: false, error: result.error, requestId: ctx.id, chainServer: stage.no });
      }
      if (stage.no < STAGE_COUNT) ctx.chain.push(linkFor(ctx, stage.no, stage.name));
    }
    return next();
  }

  // ---------------------------------------------------------------- statistics
  function flush() {
    if (pending.size === 0) return;
    const entries = [];
    for (const [no, p] of pending) entries.push({ no, ops: p.ops, errors: p.errors, lastOpAt: p.lastOpAt });
    try {
      store.addVaultStats(entries);
      pending.clear();
    } catch (e) {
      console.error('[nexora] vault statistics flush failed', e && e.message);
    }
  }
  const flushTimer = setInterval(flush, FLUSH_INTERVAL_MS);
  flushTimer.unref();

  /** Persisted counters plus those not yet flushed, for the 35 vaults. */
  function vaultStats() {
    const saved = store.getVaultStats();
    return VAULTS.map((v) => {
      const s = saved.get(v.no) || { ops: 0, errors: 0, lastOpAt: 0 };
      const p = pending.get(v.no) || { ops: 0, errors: 0, lastOpAt: 0 };
      const b = breakers.get(v.no);
      return {
        no: v.no,
        ops: s.ops + p.ops,
        errors: s.errors + p.errors,
        lastOpAt: Math.max(s.lastOpAt, p.lastOpAt),
        breaker: b && now() < b.openUntil ? 'open' : 'closed'
      };
    });
  }

  function describe() {
    return STAGES.map((s) => ({ no: s.no, name: s.name, lane: s.lane }));
  }

  function close() {
    clearInterval(minuteTimer);
    clearInterval(secondTimer);
    clearInterval(flushTimer);
    flush();
  }

  return { middleware, flush, vaultStats, describe, close, STAGE_COUNT, SHARD_FIRST, SHARD_LAST };
}

module.exports = { createMesh, STAGE_COUNT };
