'use strict';
/* © 2026 Zentora CLC. All rights reserved. Platform Core engineered by Zentora. */
/**
 * Account routes (mounted at /api/v1/account). Served by Vault 03 (identity); phone and billing by Vault 05 (private data).
 *
 *   GET  /get-profile   Google ID token  -> 200 profile | 404 not_found (the app then calls /register)
 *   POST /register      Google ID token  -> creates the account (idempotent) and returns the permanent nexoraId
 *   GET  /restore       session token    -> profile + every video this account published + liked / disliked video ids
 *   GET  /get-private   session token    -> phone / billing (Vault 3, owner only)
 *   POST /save-private  session token
 *   POST /save-profile  session token    -> display name, handle, avatar
 */
const express = require('express');
const { str, isHttpsUrl, creatorLevel, canonicalizeMediaUrl, publicBase, absolutize, toVideoItem, guard } = require('./util');
const { rateLimit } = require('./auth');

function slugHandle(name, nexoraId) {
  const base = str(name, 40).toLowerCase().replace(/[^a-z0-9]+/g, '');
  return '@' + (base.length >= 3 ? base.slice(0, 24) : 'user') + nexoraId.slice(3, 9).toLowerCase().replace(/[^a-z0-9]/g, 'x');
}

function profileJson(user, base, sessionToken) {
  const out = {
    success: true,
    nexoraId: user.nexoraId,
    email: user.email,
    username: user.username,
    handle: user.handle,
    avatarUri: absolutize(user.avatarUri, base)
  };
  if (sessionToken) out.sessionToken = sessionToken;
  return out;
}

function createUserRouter({ store, auth, config }) {
  const router = express.Router();
  const jsonBody = express.json({ limit: '64kb' });
  const authLimiter = rateLimit({ windowMs: 60 * 1000, max: 60 });

  router.get('/get-profile', authLimiter, auth.requireGoogle, guard(async (req, res) => {
    const user = await store.findUserBySub(req.google.sub);
    if (!user) return res.status(404).json({ success: false, error: 'not_found' });
    await store.touchUser(req.google.sub);
    return res.json(profileJson(user, publicBase(req, config), auth.signSession(user.sub, user.nexoraId)));
  }));

  router.post('/register', authLimiter, auth.requireGoogle, jsonBody, guard(async (req, res) => {
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const nexoraId = auth.deriveNexoraId(req.google.sub);
    const username = str(body.username, 60).trim() || str(req.google.name, 60).trim() || 'Nexora User';
    const picture = str(body.avatarUri, 1000);
    const avatarUri = isHttpsUrl(picture) ? picture : isHttpsUrl(req.google.picture) ? req.google.picture : '';
    const result = await store.createUserIfAbsent(req.google.sub, {
      nexoraId,
      email: req.google.email,
      username,
      handle: slugHandle(username, nexoraId),
      avatarUri
    });
    if (result.created) await store.anchor('ACCOUNT_REGISTERED', 'VAULT_03', { nexoraId });
    const status = result.created ? 201 : 200;
    return res.status(status).json({
      ...profileJson(result.user, publicBase(req, config), auth.signSession(result.user.sub, result.user.nexoraId)),
      created: result.created
    });
  }));

  router.get('/restore', auth.requireAccount, guard(async (req, res) => {
    const base = publicBase(req, config);
    const videos = await store.listVideosByOwner(req.user.nexoraId, 500);
    const liked = await store.likedVideoIds(req.user.nexoraId, 2000);
    const disliked = await store.dislikedVideoIds(req.user.nexoraId, 2000);
    return res.json({
      success: true,
      profile: { ...profileJson(req.user, base, null), creatorLevel: creatorLevel(0, videos.reduce((sum, v) => sum + v.views, 0)) },
      videos: videos.map((v) => toVideoItem(v, base)),
      likedVideoIds: liked,
      dislikedVideoIds: disliked
    });
  }));

  router.get('/get-private', auth.requireAccount, guard(async (req, res) => {
    const priv = await store.getPrivate(req.user.nexoraId);
    return res.json({ success: true, phoneNumber: priv ? priv.phoneNumber : '', billingInfo: priv ? priv.billingInfo : '' });
  }));

  router.post('/save-private', auth.requireAccount, jsonBody, guard(async (req, res) => {
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    await store.savePrivate(req.user.nexoraId, {
      phoneNumber: str(body.phoneNumber, 32),
      billingInfo: str(body.billingInfo, 500)
    });
    return res.json({ success: true });
  }));

  router.post('/save-profile', auth.requireAccount, jsonBody, guard(async (req, res) => {
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const username = str(body.username, 60).trim() || req.user.username;
    const handleRaw = str(body.handle, 40).trim();
    const handle = /^@[A-Za-z0-9_.]{3,32}$/.test(handleRaw) ? handleRaw : req.user.handle;
    let avatarUri = req.user.avatarUri;
    if (typeof body.avatarUri === 'string') {
      const candidate = await canonicalizeMediaUrl(body.avatarUri, req.user.nexoraId, store);
      if (candidate !== null && (candidate === '' || candidate.startsWith('/media/') || isHttpsUrl(candidate))) avatarUri = candidate;
    }
    const updated = await store.updateProfile(req.user.nexoraId, { username, handle, avatarUri });
    return res.json(profileJson(updated, publicBase(req, config), null));
  }));

  return router;
}

module.exports = { createUserRouter };
