'use strict';
/* © 2026 Zentora CLC. All rights reserved. Platform Core engineered by Zentora. */
/**
 * Private chat between friends (mounted at /api/v1/account/friends/chat). Served by Vault 35 (sub-vault
 * friend-chat). Every call needs a Nexora session token; the caller is always req.user.
 *
 *   POST /send  { nexoraId, clientId, text }  -> stores a message for a friend (a retry with the same clientId is harmless)
 *   POST /read  { nexoraId, upToSeq }         -> "I have read everything this friend sent up to upToSeq"
 *   GET  /sync  ?after=<seq>&wait=<0-25>&limit=<1-200>
 *                                             -> events after <seq>; with wait > 0 an empty answer is held until
 *                                                something arrives (long poll) or the time is over
 *
 * Event shapes (see chat-store.js):
 *   { seq, kind: 'message', peerId, fromMe, createdAt, clientId, body }
 *   { seq, kind: 'read',    peerId, fromMe, createdAt, upTo }
 * A device keeps the largest seq it has handled and passes it as ?after= next time.
 */
const express = require('express');
const { str, clampInt, absolutize, publicBase, guard } = require('./util');
const { rateLimit } = require('./auth');
const { createChatHub } = require('./chat-hub');

const NEXORA_ID_RE = /^nx_[A-Za-z0-9_-]{22}$/;
const MAX_WAIT_SECONDS = 25;
const DEFAULT_PAGE = 100;
const MAX_PAGE = 200;
const SEND_PER_MINUTE = 60;

function createChatRouter({ store, auth, config, hub = createChatHub() }) {
  const router = express.Router();
  const jsonBody = express.json({ limit: '16kb' });
  const writeLimiter = rateLimit({ windowMs: 60 * 1000, max: 240 });
  const syncLimiter = rateLimit({ windowMs: 60 * 1000, max: 600 });

  // One account may send SEND_PER_MINUTE messages a minute, whatever the network address (many accounts share one).
  let sent = new Map();
  setInterval(() => { sent = new Map(); }, 60 * 1000).unref();
  function sendAllowed(nexoraId) {
    const n = (sent.get(nexoraId) || 0) + 1;
    sent.set(nexoraId, n);
    return n <= SEND_PER_MINUTE;
  }

  const bodyOf = (req) => (req.body && typeof req.body === 'object' ? req.body : {});
  const peerIdOf = (body) => {
    const id = str(body.nexoraId, 40).trim();
    return NEXORA_ID_RE.test(id) ? id : '';
  };

  router.post('/send', writeLimiter, auth.requireAccount, jsonBody, guard(async (req, res) => {
    const body = bodyOf(req);
    const peerId = peerIdOf(body);
    if (!peerId || typeof body.clientId !== 'string' || typeof body.text !== 'string') {
      return res.status(400).json({ success: false, error: 'invalid_request' });
    }
    if (!sendAllowed(req.user.nexoraId)) {
      res.set('Retry-After', '60');
      return res.status(429).json({ success: false, error: 'slow_down' });
    }
    const out = store.sendChat(req.user.nexoraId, peerId, body.clientId, body.text);
    if (out.result === 'self') return res.status(400).json({ success: false, error: 'cannot_message_self' });
    if (out.result === 'invalid') return res.status(400).json({ success: false, error: 'invalid_message' });
    if (out.result === 'not_friends') return res.status(403).json({ success: false, error: 'not_friends' });
    if (out.result === 'sent') {
      hub.notify(peerId);
      hub.notify(req.user.nexoraId);
    }
    return res.status(out.result === 'sent' ? 201 : 200).json({ success: true, duplicate: out.result === 'duplicate', message: out.event });
  }));

  router.post('/read', writeLimiter, auth.requireAccount, jsonBody, guard(async (req, res) => {
    const body = bodyOf(req);
    const peerId = peerIdOf(body);
    const upToSeq = Number(body.upToSeq);
    if (!peerId || !Number.isSafeInteger(upToSeq) || upToSeq < 1) {
      return res.status(400).json({ success: false, error: 'invalid_request' });
    }
    const out = store.markChatRead(req.user.nexoraId, peerId, upToSeq);
    if (!out) return res.status(404).json({ success: false, error: 'nothing_to_mark' });
    if (out.changed) {
      hub.notify(peerId);
      hub.notify(req.user.nexoraId);
    }
    return res.json({ success: true, upTo: out.upTo });
  }));

  router.get('/sync', syncLimiter, auth.requireAccount, guard(async (req, res) => {
    const me = req.user.nexoraId;
    const after = clampInt(req.query.after, 0, Number.MAX_SAFE_INTEGER);
    const limit = clampInt(req.query.limit === undefined ? DEFAULT_PAGE : req.query.limit, 1, MAX_PAGE);
    const wait = clampInt(req.query.wait === undefined ? 0 : req.query.wait, 0, MAX_WAIT_SECONDS);

    // No await between the check and park(): a message stored in between cannot be missed.
    let page = store.chatSync(me, after, limit);
    let retryAfterMs = 0;
    if (page.events.length === 0 && wait > 0) {
      const parkedRequest = hub.park(me, wait * 1000);
      const onClose = () => parkedRequest.cancel();
      res.on('close', onClose);
      const reason = await parkedRequest.promise;
      res.off('close', onClose);
      if (res.destroyed || res.writableEnded) return undefined;
      if (reason === 'full') retryAfterMs = 5000;
      page = store.chatSync(me, after, limit);
    }
    const base = publicBase(req, config);
    const last = page.events.length > 0 ? page.events[page.events.length - 1].seq : after;
    return res.json({
      success: true,
      events: page.events,
      people: page.people.map((p) => ({ ...p, avatarUri: absolutize(p.avatarUri, base) })),
      cursor: last,
      more: page.more,
      retryAfterMs,
      timestamp: Date.now()
    });
  }));

  return router;
}

module.exports = { createChatRouter };
