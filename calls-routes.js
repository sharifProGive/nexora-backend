'use strict';
/* © 2026 Zentora CLC. All rights reserved. Platform Core engineered by Zentora. */
/**
 * Voice and video calls between friends (mounted at /api/v1/account/friends/calls). Served by Vault 35 (sub-vault
 * friend-calls). Every call needs a Nexora session token; the caller is always req.user. The media itself goes
 * phone to phone (WebRTC); this router only carries the signaling.
 *
 *   GET  /ice                                  -> { iceServers, configured, ttlSeconds }  STUN/TURN servers for WebRTC
 *   POST /start   { nexoraId, video }          -> 201 { call }   rings a friend
 *   POST /answer  { callId }                   -> { call }       the callee picks up
 *   POST /decline { callId }                   -> { call }       the callee refuses
 *   POST /end     { callId, reason? }          -> { call }       hang up / cancel (reason: ended | failed)
 *   POST /signal  { callId, type, data }       -> { success }    type: offer | answer | candidate (data: a string)
 *   GET   /poll   ?callId=&rev=&after=&wait=   -> long poll. Without callId: "is someone calling me?".
 *                                                 With callId: changes of that call since rev, plus signaling after n.
 *
 * Errors: 403 not_friends, 409 busy / peer_busy, 404 call_not_found, 409 bad_state, 400 invalid_request, 429 slow_down.
 */
const crypto = require('node:crypto');
const express = require('express');
const { str, clampInt, guard } = require('./util');
const { rateLimit } = require('./auth');
const { createChatHub } = require('./chat-hub');

const NEXORA_ID_RE = /^nx_[A-Za-z0-9_-]{22}$/;
const CALL_ID_RE = /^[A-Za-z0-9_-]{8,40}$/;
const MAX_WAIT_SECONDS = 25;
const STARTS_PER_MINUTE = 10;
const ICE_TTL_SECONDS = 3600;

/**
 * STUN is plain configuration. TURN uses short-lived credentials (the "TURN REST" scheme that coturn understands with
 * use-auth-secret): username "<expiry>:<account>", credential base64(HMAC-SHA1(secret, username)). The shared secret
 * never leaves the server, and a leaked credential stops working after an hour.
 */
function buildIceServers(config, userId, nowMs = Date.now()) {
  const servers = [];
  const stun = Array.isArray(config.stunUrls) ? config.stunUrls : [];
  const turn = Array.isArray(config.turnUrls) ? config.turnUrls : [];
  if (stun.length > 0) servers.push({ urls: stun });
  if (turn.length > 0 && config.turnSecret) {
    const username = `${Math.floor(nowMs / 1000) + ICE_TTL_SECONDS}:${userId}`;
    const credential = crypto.createHmac('sha1', config.turnSecret).update(username).digest('base64');
    servers.push({ urls: turn, username, credential });
  }
  return { iceServers: servers, configured: servers.length > 0, ttlSeconds: ICE_TTL_SECONDS };
}

function createCallsRouter({ store, auth, config, hub = createChatHub(), sweepEveryMs = 5000 }) {
  const router = express.Router();
  const jsonBody = express.json({ limit: '16kb' });
  const writeLimiter = rateLimit({ windowMs: 60 * 1000, max: 1200 });
  const pollLimiter = rateLimit({ windowMs: 60 * 1000, max: 600 });

  let started = new Map();
  setInterval(() => { started = new Map(); }, 60 * 1000).unref();
  function startAllowed(nexoraId) {
    const n = (started.get(nexoraId) || 0) + 1;
    started.set(nexoraId, n);
    return n <= STARTS_PER_MINUTE;
  }

  // Calls nobody answers, and calls whose phones went silent, are ended here and both phones are woken up.
  const sweeper = setInterval(() => {
    for (const s of store.sweepCalls()) {
      hub.notify(s.callerId);
      hub.notify(s.calleeId);
    }
  }, sweepEveryMs);
  sweeper.unref();

  const bodyOf = (req) => (req.body && typeof req.body === 'object' ? req.body : {});
  const callIdOf = (value) => {
    const id = str(value, 40).trim();
    return CALL_ID_RE.test(id) ? id : '';
  };
  const wake = (call, me) => {
    hub.notify(me);
    hub.notify(call.peerId);
  };
  const reply = (res, out, okStatus = 200) => {
    if (out.result === 'ok') return res.status(okStatus).json({ success: true, call: out.call });
    if (out.result === 'not_found') return res.status(404).json({ success: false, error: 'call_not_found' });
    if (out.result === 'bad_state') return res.status(409).json({ success: false, error: 'bad_state' });
    return res.status(400).json({ success: false, error: 'invalid_request' });
  };

  router.get('/ice', pollLimiter, auth.requireAccount, guard(async (req, res) => {
    res.set('Cache-Control', 'no-store');
    return res.json({ success: true, ...buildIceServers(config, req.user.nexoraId) });
  }));

  router.post('/start', writeLimiter, auth.requireAccount, jsonBody, guard(async (req, res) => {
    const body = bodyOf(req);
    const peerId = str(body.nexoraId, 40).trim();
    if (!NEXORA_ID_RE.test(peerId) || typeof body.video !== 'boolean') {
      return res.status(400).json({ success: false, error: 'invalid_request' });
    }
    if (!startAllowed(req.user.nexoraId)) {
      res.set('Retry-After', '60');
      return res.status(429).json({ success: false, error: 'slow_down' });
    }
    const out = store.startCall(req.user.nexoraId, peerId, body.video);
    if (out.result === 'self') return res.status(400).json({ success: false, error: 'cannot_call_self' });
    if (out.result === 'not_friends') return res.status(403).json({ success: false, error: 'not_friends' });
    if (out.result === 'busy') return res.status(409).json({ success: false, error: 'busy' });
    if (out.result === 'peer_busy') return res.status(409).json({ success: false, error: 'peer_busy' });
    if (out.result === 'overloaded') {
      res.set('Retry-After', '30');
      return res.status(503).json({ success: false, error: 'overloaded' });
    }
    wake(out.call, req.user.nexoraId);
    return res.status(201).json({ success: true, call: out.call });
  }));

  router.post('/answer', writeLimiter, auth.requireAccount, jsonBody, guard(async (req, res) => {
    const callId = callIdOf(bodyOf(req).callId);
    if (!callId) return res.status(400).json({ success: false, error: 'invalid_request' });
    const out = store.answerCall(req.user.nexoraId, callId);
    if (out.result === 'ok') wake(out.call, req.user.nexoraId);
    return reply(res, out);
  }));

  router.post('/decline', writeLimiter, auth.requireAccount, jsonBody, guard(async (req, res) => {
    const callId = callIdOf(bodyOf(req).callId);
    if (!callId) return res.status(400).json({ success: false, error: 'invalid_request' });
    const out = store.declineCall(req.user.nexoraId, callId);
    if (out.result === 'ok') wake(out.call, req.user.nexoraId);
    return reply(res, out);
  }));

  router.post('/end', writeLimiter, auth.requireAccount, jsonBody, guard(async (req, res) => {
    const body = bodyOf(req);
    const callId = callIdOf(body.callId);
    if (!callId) return res.status(400).json({ success: false, error: 'invalid_request' });
    const out = store.endCall(req.user.nexoraId, callId, typeof body.reason === 'string' ? body.reason : 'ended');
    if (out.result === 'ok') wake(out.call, req.user.nexoraId);
    return reply(res, out);
  }));

  router.post('/signal', writeLimiter, auth.requireAccount, jsonBody, guard(async (req, res) => {
    const body = bodyOf(req);
    const callId = callIdOf(body.callId);
    if (!callId || typeof body.type !== 'string' || typeof body.data !== 'string') {
      return res.status(400).json({ success: false, error: 'invalid_request' });
    }
    const out = store.signalCall(req.user.nexoraId, callId, body.type, body.data);
    if (out.result === 'too_many') return res.status(429).json({ success: false, error: 'too_many_signals' });
    if (out.result !== 'ok') return reply(res, out);
    hub.notify(out.peerId);
    return res.json({ success: true });
  }));

  router.get('/poll', pollLimiter, auth.requireAccount, guard(async (req, res) => {
    const me = req.user.nexoraId;
    const rawId = typeof req.query.callId === 'string' ? req.query.callId : '';
    const callId = rawId ? callIdOf(rawId) : '';
    if (rawId && !callId) return res.status(400).json({ success: false, error: 'invalid_request' });
    const rev = clampInt(req.query.rev === undefined ? 0 : req.query.rev, 0, Number.MAX_SAFE_INTEGER);
    const after = clampInt(req.query.after === undefined ? 0 : req.query.after, 0, Number.MAX_SAFE_INTEGER);
    const wait = clampInt(req.query.wait === undefined ? 0 : req.query.wait, 0, MAX_WAIT_SECONDS);

    // No await between the check and park(): a change made in between cannot be missed.
    let result = store.checkCall(me, callId, rev, after);
    let retryAfterMs = 0;
    if ((result.status === 'none' || result.status === 'unchanged') && wait > 0) {
      const parkedRequest = hub.park(me, wait * 1000);
      const onClose = () => parkedRequest.cancel();
      res.on('close', onClose);
      const reason = await parkedRequest.promise;
      res.off('close', onClose);
      if (res.destroyed || res.writableEnded) return undefined;
      if (reason === 'full') retryAfterMs = 5000;
      result = store.checkCall(me, callId, rev, after);
    }
    if (result.status === 'gone') return res.status(404).json({ success: false, error: 'call_not_found' });
    if (result.status === 'changed') {
      return res.json({ success: true, call: result.call, signals: result.signals, cursor: result.cursor, retryAfterMs });
    }
    return res.json({ success: true, call: null, signals: [], cursor: after, retryAfterMs });
  }));

  return router;
}

module.exports = { createCallsRouter, buildIceServers };
