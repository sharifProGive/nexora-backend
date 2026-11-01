'use strict';
/* © 2026 Zentora CLC. All rights reserved. Platform Core engineered by Zentora. */
/**
 * Friends (mounted at /api/v1/account/friends). Served by Vault 35 (Friends; sub-vaults: friends, friend-requests,
 * friend-relationships). Every call needs a Nexora session token; the caller is always req.user, never an id
 * from the request body.
 *
 *   GET  /list      -> { friends, incoming, outgoing }  (the whole Friends screen in one response)
 *   GET  /search    ?q=<start of a handle, 3+ characters>  -> people with their relation to the caller
 *   POST /request   { handle } or { nexoraId }          -> sends a request (meeting requests become a friendship)
 *   POST /respond   { nexoraId, accept }                -> accepts or declines a request that person sent to the caller
 *   POST /cancel    { nexoraId }                        -> withdraws a request the caller sent
 *   POST /remove    { nexoraId }                        -> ends a friendship
 *
 * A person is always { nexoraId, username, handle, avatarUri }. Nothing else about an account is shared.
 */
const express = require('express');
const { str, absolutize, publicBase, guard } = require('./util');
const { rateLimit } = require('./auth');

const NEXORA_ID_RE = /^nx_[A-Za-z0-9_-]{22}$/;
const HANDLE_RE = /^@?[A-Za-z0-9_.]{3,64}$/;

function createFriendsRouter({ store, auth, config }) {
  const router = express.Router();
  const jsonBody = express.json({ limit: '4kb' });
  const readLimiter = rateLimit({ windowMs: 60 * 1000, max: 240 });
  const writeLimiter = rateLimit({ windowMs: 60 * 1000, max: 60 });
  const searchLimiter = rateLimit({ windowMs: 60 * 1000, max: 60 });

  const person = (p, base) => ({
    nexoraId: p.nexoraId,
    username: p.username,
    handle: p.handle,
    avatarUri: absolutize(p.avatarUri, base)
  });

  const bodyOf = (req) => (req.body && typeof req.body === 'object' ? req.body : {});

  function targetId(body) {
    const id = str(body.nexoraId, 40).trim();
    return NEXORA_ID_RE.test(id) ? id : '';
  }

  router.get('/list', readLimiter, auth.requireAccount, guard(async (req, res) => {
    const base = publicBase(req, config);
    const all = await store.listFriendships(req.user.nexoraId);
    const mapAll = (rows) => rows.map((r) => ({ ...person(r, base), since: r.since, requestedAt: r.requestedAt }));
    return res.json({
      success: true,
      me: person(req.user, base),
      friends: mapAll(all.friends),
      incoming: mapAll(all.incoming),
      outgoing: mapAll(all.outgoing),
      timestamp: Date.now()
    });
  }));

  router.get('/search', searchLimiter, auth.requireAccount, guard(async (req, res) => {
    const q = str(req.query.q, 64).trim();
    if (q.replace(/^@+/, '').length < 3) return res.status(400).json({ success: false, error: 'query_too_short' });
    const base = publicBase(req, config);
    const people = await store.searchPeople(req.user.nexoraId, q, 20);
    return res.json({ success: true, people: people.map((p) => ({ ...person(p, base), relation: p.relation })) });
  }));

  router.post('/request', writeLimiter, auth.requireAccount, jsonBody, guard(async (req, res) => {
    const body = bodyOf(req);
    let target = null;
    const id = targetId(body);
    if (id) {
      target = await store.findUserByNexoraId(id);
    } else {
      const handle = str(body.handle, 64).trim();
      if (!HANDLE_RE.test(handle)) return res.status(400).json({ success: false, error: 'invalid_request' });
      target = await store.findUserByHandle(handle.startsWith('@') ? handle : '@' + handle);
    }
    if (!target) return res.status(404).json({ success: false, error: 'user_not_found' });
    const outcome = await store.requestFriend(req.user.nexoraId, target.nexoraId);
    if (outcome === 'self') return res.status(400).json({ success: false, error: 'cannot_add_self' });
    if (outcome === 'not_found') return res.status(404).json({ success: false, error: 'user_not_found' });
    if (outcome === 'limit_reached') return res.status(429).json({ success: false, error: 'too_many_requests' });
    const base = publicBase(req, config);
    const status = outcome === 'sent' ? 201 : 200;
    return res.status(status).json({
      success: true,
      outcome,
      relation: outcome === 'accepted' || outcome === 'already_friends' ? 'friends' : 'request_sent',
      person: person(target, base)
    });
  }));

  router.post('/respond', writeLimiter, auth.requireAccount, jsonBody, guard(async (req, res) => {
    const body = bodyOf(req);
    const id = targetId(body);
    if (!id || typeof body.accept !== 'boolean') return res.status(400).json({ success: false, error: 'invalid_request' });
    const done = await store.respondFriendRequest(req.user.nexoraId, id, body.accept);
    if (!done) return res.status(404).json({ success: false, error: 'request_not_found' });
    return res.json({ success: true, accepted: body.accept });
  }));

  router.post('/cancel', writeLimiter, auth.requireAccount, jsonBody, guard(async (req, res) => {
    const id = targetId(bodyOf(req));
    if (!id) return res.status(400).json({ success: false, error: 'invalid_request' });
    const done = await store.cancelFriendRequest(req.user.nexoraId, id);
    if (!done) return res.status(404).json({ success: false, error: 'request_not_found' });
    return res.json({ success: true });
  }));

  router.post('/remove', writeLimiter, auth.requireAccount, jsonBody, guard(async (req, res) => {
    const id = targetId(bodyOf(req));
    if (!id) return res.status(400).json({ success: false, error: 'invalid_request' });
    const done = await store.removeFriend(req.user.nexoraId, id);
    if (!done) return res.status(404).json({ success: false, error: 'friend_not_found' });
    return res.json({ success: true });
  }));

  return router;
}

module.exports = { createFriendsRouter };
