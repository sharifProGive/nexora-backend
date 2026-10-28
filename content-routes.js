'use strict';
/* © 2026 Zentora CLC. All rights reserved. Platform Core engineered by Zentora. */
/**
 * Content routes (mounted at /api/v1). Every write requires a Nexora session token.
 *   Vault 01 social engagement   POST /videos/interact, POST /comments/post, POST /comments/share, GET /comments
 *   Vault 04 video & metadata    POST /videos/publish, POST /videos/delete
 *   Vault 06 channels            GET /channels/:id, GET /channels/:id/videos
 *   Vault 07 feed engine         GET /feed
 *   Vault 08 search index        GET /videos/search
 *   Vault 09 resumable media     /media/limits, /media/start, /media/status/:id, /media/chunk/:id, /media/finish/:id
 *   Vault 10 premiere & live     GET /premieres
 */
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const express = require('express');
const {
  ID_RE, MEDIA_NAME_RE, VISIBILITIES, str, clampInt, isHttpsUrl, publicBase, absolutize, creatorLevel, canonicalizeMediaUrl, toVideoItem, guard
} = require('./util');
const { rateLimit } = require('./auth');

const VIDEO_EXT = ['mp4', 'mov', '3gp', 'webm', 'mkv'];
const IMAGE_EXT = ['jpg', 'png', 'webp'];
const MAX_OPEN_UPLOADS = 3;
const UPLOAD_ID_RE = /^[a-f0-9]{32}$/;
const PREMIERE_LIVE_WINDOW_MS = 3 * 60 * 60 * 1000;
const CHANNEL_ID_RE = /^(?:ch_)?(nx_[A-Za-z0-9_-]{22})$/;

/** Returns the file extension matching the leading bytes, or null when the bytes are not a supported media file. */
function sniffExtension(head) {
  if (head.length >= 12 && head.toString('latin1', 4, 8) === 'ftyp') {
    const brand = head.toString('latin1', 8, 12);
    if (brand === 'qt  ') return 'mov';
    if (brand.startsWith('3gp') || brand.startsWith('3g2')) return '3gp';
    return 'mp4';
  }
  if (head.length >= 4 && head[0] === 0x1a && head[1] === 0x45 && head[2] === 0xdf && head[3] === 0xa3) {
    return head.toString('latin1').includes('webm') ? 'webm' : 'mkv';
  }
  if (head.length >= 3 && head[0] === 0xff && head[1] === 0xd8 && head[2] === 0xff) return 'jpg';
  if (head.length >= 8 && head.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) return 'png';
  if (head.length >= 12 && head.toString('latin1', 0, 4) === 'RIFF' && head.toString('latin1', 8, 12) === 'WEBP') return 'webp';
  return null;
}

/** Streams the request body onto the end of [file]. On any failure the file is cut back to [expectedOffset]. */
function receiveChunk(req, file, expectedOffset, maxBytes) {
  return new Promise((resolve, reject) => {
    const out = fs.createWriteStream(file, { flags: 'a' });
    let received = 0;
    let failed = false;
    const fail = (err) => {
      if (failed) return;
      failed = true;
      req.unpipe(out);
      out.destroy();
      fs.truncate(file, expectedOffset, () => reject(err));
    };
    req.on('data', (c) => {
      received += c.length;
      if (received > maxBytes) {
        const e = new Error('chunk_too_large');
        e.code = 'chunk_too_large';
        fail(e);
      }
    });
    req.on('close', () => {
      if (!req.complete) fail(new Error('aborted'));
    });
    req.on('error', fail);
    out.on('error', fail);
    out.on('finish', () => {
      if (!failed) resolve(received);
    });
    req.pipe(out);
  });
}

function readHead(file, bytes) {
  const fd = fs.openSync(file, 'r');
  try {
    const buf = Buffer.alloc(bytes);
    const n = fs.readSync(fd, buf, 0, bytes, 0);
    return buf.subarray(0, n);
  } finally {
    fs.closeSync(fd);
  }
}

function unlinkQuiet(file) {
  try {
    fs.unlinkSync(file);
  } catch (_e) {
    /* already gone */
  }
}

/** Removes unfinished upload sessions (and their partial files) older than [maxAgeMs]. */
async function cleanupStaleUploads({ store, tmpDir, maxAgeMs }) {
  const ids = await store.listStaleUploads(Date.now() - maxAgeMs);
  for (const id of ids) {
    if (UPLOAD_ID_RE.test(id)) unlinkQuiet(path.join(tmpDir, id + '.part'));
    await store.deleteUpload(id);
  }
  return ids.length;
}

function createContentRouter({ store, auth, config }) {
  const router = express.Router();
  const jsonBody = express.json({ limit: '256kb' });
  const writeLimiter = rateLimit({ windowMs: 60 * 1000, max: 240 });
  const busyUploads = new Set();

  function canSee(video, user) {
    return video.visibility !== 'Private' || video.ownerId === user.nexoraId;
  }

  // ------------------------------------------------------------------ read
  router.get('/feed', guard(async (req, res) => {
    const limit = clampInt(req.query.limit === undefined ? 50 : req.query.limit, 1, 100);
    const before = req.query.before === undefined ? 0 : clampInt(req.query.before, 0, Number.MAX_SAFE_INTEGER);
    const base = publicBase(req, config);
    const rows = await store.listFeed({ limit, before });
    return res.json({ success: true, videos: rows.map((v) => toVideoItem(v, base)) });
  }));

  router.get('/videos/search', guard(async (req, res) => {
    const q = str(req.query.q, 100).trim();
    if (q.length === 0) return res.json({ success: true, videos: [] });
    const base = publicBase(req, config);
    const rows = await store.searchVideos(q, clampInt(req.query.limit === undefined ? 40 : req.query.limit, 1, 100));
    return res.json({ success: true, videos: rows.map((v) => toVideoItem(v, base)) });
  }));

  // ------------------------------------------------------------------ videos
  router.post('/videos/publish', writeLimiter, auth.requireAccount, jsonBody, guard(async (req, res) => {
    const b = req.body && typeof req.body === 'object' ? req.body : {};
    const owner = req.user.nexoraId;
    const id = str(b.id, 80);
    if (!ID_RE.test(id)) return res.status(400).json({ success: false, error: 'invalid_id' });
    const existing = await store.getVideo(id);
    if (existing && existing.ownerId !== owner) return res.status(403).json({ success: false, error: 'not_owner' });
    const has = (key) => b[key] !== undefined;

    const title = has('title') ? str(b.title, 150).trim() : existing ? existing.title : '';
    if (title.length === 0) return res.status(400).json({ success: false, error: 'title_required' });

    let videoUrl;
    if (has('videoUrl') && str(b.videoUrl, 1000).length > 0) {
      videoUrl = await canonicalizeMediaUrl(str(b.videoUrl, 1000), owner, store);
    } else {
      videoUrl = existing ? existing.videoUrl : null;
    }
    if (videoUrl === null || !(videoUrl.startsWith('/media/') || isHttpsUrl(videoUrl))) {
      return res.status(400).json({ success: false, error: 'invalid_video_url' });
    }

    let thumbnailUrl = existing ? existing.thumbnailUrl : '';
    if (has('thumbnailUrl')) {
      const raw = str(b.thumbnailUrl, 1000);
      if (raw.length === 0) {
        thumbnailUrl = '';
      } else {
        const t = await canonicalizeMediaUrl(raw, owner, store);
        if (t !== null && (t.startsWith('/media/') || isHttpsUrl(t))) thumbnailUrl = t;
      }
    }

    const visibility = VISIBILITIES.includes(b.visibility) ? b.visibility : undefined;
    const now = Date.now();
    const stamp = Number(b.timestamp);
    const createdAt = existing
      ? existing.createdAt
      : Number.isFinite(stamp) && stamp > 0 && stamp <= now + 86400000 ? Math.floor(stamp) : now;

    let premiereMs = existing ? existing.premiereScheduledTimeMs : null;
    if (has('premiereScheduledTimeMs')) {
      premiereMs = b.premiereScheduledTimeMs === null ? null : clampInt(b.premiereScheduledTimeMs, 0, Number.MAX_SAFE_INTEGER);
    }
    let chapters = existing ? existing.chapterMarkersJson : '[]';
    if (has('chapterMarkersJson')) {
      chapters = str(b.chapterMarkersJson, 20000);
      try {
        if (!Array.isArray(JSON.parse(chapters))) chapters = '[]';
      } catch (_e) {
        chapters = '[]';
      }
    }
    let collab = existing ? existing.collabChannelId : null;
    if (has('collabChannelId')) {
      collab = typeof b.collabChannelId === 'string' && b.collabChannelId.length > 0 ? str(b.collabChannelId, 100) : null;
    }

    const result = await store.upsertVideo({
      id,
      ownerId: owner,
      title,
      description: has('description') ? str(b.description, 5000) : existing ? existing.description : '',
      category: has('category') ? str(b.category, 40).trim() || 'General' : existing ? existing.category : 'General',
      tags: has('tags') ? str(b.tags, 300) : existing ? existing.tags : '',
      videoUrl,
      thumbnailUrl,
      duration: has('duration') ? clampInt(b.duration, 0, 86400000) : existing ? existing.duration : 0,
      visibility,
      chapterMarkersJson: chapters,
      collabChannelId: collab,
      isPremiere: has('isPremiere') ? b.isPremiere === true : existing ? existing.isPremiere : false,
      premiereScheduledTimeMs: premiereMs,
      createdAt
    });
    if (!result.ok) return res.status(403).json({ success: false, error: 'not_owner' });
    if (result.created) await store.anchor('VIDEO_PUBLISHED', 'VAULT_04', { videoId: id, ownerId: owner });
    const stored = await store.getVideo(id);
    return res.status(result.created ? 201 : 200).json({ success: true, created: result.created, video: toVideoItem(stored, publicBase(req, config)) });
  }));

  router.post('/videos/delete', writeLimiter, auth.requireAccount, jsonBody, guard(async (req, res) => {
    const id = str(req.body && req.body.id, 80);
    if (!ID_RE.test(id)) return res.status(400).json({ success: false, error: 'invalid_id' });
    const result = await store.deleteVideo(id, req.user.nexoraId);
    if (!result.ok) return res.status(403).json({ success: false, error: 'not_owner' });
    for (const name of result.orphanMedia) {
      if (MEDIA_NAME_RE.test(name)) unlinkQuiet(path.join(config.mediaDir, name));
    }
    if (result.removed) await store.anchor('VIDEO_DELETED', 'VAULT_04', { videoId: id, ownerId: req.user.nexoraId });
    return res.json({ success: true, removed: result.removed });
  }));

  router.post('/videos/interact', writeLimiter, auth.requireAccount, jsonBody, guard(async (req, res) => {
    const b = req.body && typeof req.body === 'object' ? req.body : {};
    const id = str(b.id, 80);
    if (!ID_RE.test(id)) return res.status(400).json({ success: false, error: 'invalid_id' });
    const video = await store.getVideo(id);
    if (!video || !canSee(video, req.user)) return res.status(404).json({ success: false, error: 'not_found' });
    const sign = (value) => Math.max(-1, Math.min(1, Math.trunc(Number(value) || 0)));
    const sparks = clampInt(b.sparks, 0, 1000);
    const counts = await store.addVideoDelta(id, req.user.nexoraId, {
      views: clampInt(b.views, 0, 1),
      like: sign(b.like),
      dislike: sign(b.dislike),
      sparks,
      share: b.share === true || (b.share && typeof b.share === 'object') ? { channel: str(b.share.channel, 40) } : null
    });
    if (sparks > 0) await store.anchor('SPARK_SENT', 'VAULT_01', { videoId: id, from: req.user.nexoraId, to: video.ownerId, amount: sparks });
    return res.json({
      success: true,
      viewCount: counts.views,
      likeCount: counts.likes,
      dislikeCount: counts.dislikes,
      shareCount: counts.shares,
      sparkCount: counts.sparks
    });
  }));

  // ------------------------------------------------------------------ comments
  router.post('/comments/post', writeLimiter, auth.requireAccount, jsonBody, guard(async (req, res) => {
    const b = req.body && typeof req.body === 'object' ? req.body : {};
    const commentId = str(b.commentId, 80);
    const videoId = str(b.videoId, 80);
    const text = str(b.text, 1000).trim();
    if (!ID_RE.test(commentId) || !ID_RE.test(videoId)) return res.status(400).json({ success: false, error: 'invalid_id' });
    if (text.length === 0) return res.status(400).json({ success: false, error: 'text_required' });
    const video = await store.getVideo(videoId);
    if (!video || !canSee(video, req.user)) return res.status(404).json({ success: false, error: 'not_found' });
    const now = Date.now();
    const stamp = Number(b.timestamp);
    const timestamp = Number.isFinite(stamp) && stamp > 0 && stamp <= now + 86400000 ? Math.floor(stamp) : now;
    const result = await store.upsertComment({
      commentId, videoId, ownerId: req.user.nexoraId, authorName: str(req.user.username, 60), text, timestamp
    });
    if (!result.ok) return res.status(403).json({ success: false, error: 'not_owner' });
    return res.json({ success: true });
  }));

  router.post('/comments/share', writeLimiter, auth.requireAccount, jsonBody, guard(async (req, res) => {
    const b = req.body && typeof req.body === 'object' ? req.body : {};
    const commentId = str(b.commentId, 80);
    if (!ID_RE.test(commentId)) return res.status(400).json({ success: false, error: 'invalid_id' });
    const comment = await store.getComment(commentId);
    const video = comment ? await store.getVideo(comment.videoId) : null;
    if (!comment || !video || !canSee(video, req.user)) return res.status(404).json({ success: false, error: 'not_found' });
    const result = await store.shareComment(commentId, req.user.nexoraId, str(b.channel, 40));
    return res.json({ success: true, shareCount: result.shares });
  }));

  router.get('/comments', guard(async (req, res) => {
    const videoId = str(req.query.videoId, 80);
    if (!ID_RE.test(videoId)) return res.status(400).json({ success: false, error: 'invalid_id' });
    const video = await store.getVideo(videoId);
    if (!video || video.visibility === 'Private') return res.json({ success: true, comments: [] });
    return res.json({ success: true, comments: await store.listComments(videoId, clampInt(req.query.limit === undefined ? 100 : req.query.limit, 1, 200)) });
  }));

  // ------------------------------------------------------------------ vault 06 channels
  router.get('/channels/:id', guard(async (req, res) => {
    const m = CHANNEL_ID_RE.exec(str(req.params.id, 40));
    if (!m) return res.status(400).json({ success: false, error: 'invalid_id' });
    const channel = await store.getChannel(m[1]);
    if (!channel) return res.status(404).json({ success: false, error: 'not_found' });
    return res.json({
      success: true,
      channelId: 'ch_' + channel.nexoraId,
      nexoraId: channel.nexoraId,
      channelName: channel.username || channel.handle,
      handle: channel.handle,
      avatarUri: absolutize(channel.avatarUri, publicBase(req, config)),
      creatorLevel: creatorLevel(0, channel.totalViews),
      joinedAt: channel.joinedAt,
      videoCount: channel.videoCount,
      totalViews: channel.totalViews,
      totalLikes: channel.totalLikes
    });
  }));

  router.get('/channels/:id/videos', guard(async (req, res) => {
    const m = CHANNEL_ID_RE.exec(str(req.params.id, 40));
    if (!m) return res.status(400).json({ success: false, error: 'invalid_id' });
    const rows = await store.listPublicVideosByOwner(m[1], clampInt(req.query.limit === undefined ? 50 : req.query.limit, 1, 100));
    const base = publicBase(req, config);
    return res.json({ success: true, videos: rows.map((v) => toVideoItem(v, base)) });
  }));

  // ------------------------------------------------------------------ vault 10 premiere & live
  router.get('/premieres', guard(async (req, res) => {
    const now = Date.now();
    const base = publicBase(req, config);
    const rows = await store.listPremieres(now - PREMIERE_LIVE_WINDOW_MS, clampInt(req.query.limit === undefined ? 50 : req.query.limit, 1, 100));
    const premieres = rows.map((v) => {
      const start = v.premiereScheduledTimeMs;
      const end = start + (v.duration > 0 ? v.duration : PREMIERE_LIVE_WINDOW_MS);
      const status = now < start ? 'upcoming' : now < end ? 'live' : 'ended';
      return { status, startsInMs: Math.max(0, start - now), video: toVideoItem(v, base) };
    }).filter((p) => p.status !== 'ended');
    return res.json({ success: true, premieres });
  }));

  // ------------------------------------------------------------------ resumable media upload
  router.get('/media/limits', auth.requireAccount, guard(async (req, res) => {
    return res.json({
      success: true,
      maxVideoBytes: config.maxVideoBytes,
      maxImageBytes: config.maxImageBytes,
      chunkBytes: config.chunkBytes,
      quotaBytes: config.quotaBytes,
      usedBytes: await store.storageUsed(req.user.nexoraId)
    });
  }));

  router.post('/media/start', writeLimiter, auth.requireAccount, jsonBody, guard(async (req, res) => {
    const b = req.body && typeof req.body === 'object' ? req.body : {};
    const kind = b.kind === 'video' || b.kind === 'image' ? b.kind : null;
    const size = Math.floor(Number(b.size));
    if (!kind || !Number.isFinite(size) || size < 64) return res.status(400).json({ success: false, error: 'invalid_request' });
    const max = kind === 'video' ? config.maxVideoBytes : config.maxImageBytes;
    if (size > max) return res.status(413).json({ success: false, error: 'file_too_large', maxBytes: max });
    const owner = req.user.nexoraId;
    if ((await store.countOpenUploads(owner)) >= MAX_OPEN_UPLOADS) return res.status(429).json({ success: false, error: 'too_many_uploads' });
    if ((await store.storageUsed(owner)) + size > config.quotaBytes) return res.status(413).json({ success: false, error: 'quota_exceeded', quotaBytes: config.quotaBytes });
    const uploadId = crypto.randomBytes(16).toString('hex');
    fs.mkdirSync(config.tmpDir, { recursive: true });
    fs.writeFileSync(path.join(config.tmpDir, uploadId + '.part'), Buffer.alloc(0));
    await store.createUpload({ id: uploadId, ownerId: owner, kind, size });
    return res.status(201).json({ success: true, uploadId, chunkBytes: config.chunkBytes, offset: 0 });
  }));

  async function ownedUpload(req, res) {
    const id = str(req.params.id, 40);
    const upload = UPLOAD_ID_RE.test(id) ? await store.getUpload(id) : null;
    if (!upload || upload.ownerId !== req.user.nexoraId) {
      res.status(404).json({ success: false, error: 'unknown_upload' });
      return null;
    }
    return upload;
  }

  router.get('/media/status/:id', auth.requireAccount, guard(async (req, res) => {
    const upload = await ownedUpload(req, res);
    if (!upload) return undefined;
    if (upload.finalName) return res.json({ success: true, offset: upload.size, complete: true });
    const file = path.join(config.tmpDir, upload.id + '.part');
    const offset = fs.existsSync(file) ? fs.statSync(file).size : 0;
    return res.json({ success: true, offset, complete: false });
  }));

  router.put('/media/chunk/:id', auth.requireAccount, guard(async (req, res) => {
    const upload = await ownedUpload(req, res);
    if (!upload) return undefined;
    if (upload.finalName) return res.status(409).json({ success: false, error: 'already_complete' });
    if (busyUploads.has(upload.id)) return res.status(409).json({ success: false, error: 'busy' });
    const file = path.join(config.tmpDir, upload.id + '.part');
    if (!fs.existsSync(file)) return res.status(404).json({ success: false, error: 'unknown_upload' });
    const current = fs.statSync(file).size;
    const claimed = Math.floor(Number(req.query.offset));
    if (!Number.isFinite(claimed) || claimed !== current) {
      return res.status(409).json({ success: false, error: 'offset_mismatch', expectedOffset: current });
    }
    busyUploads.add(upload.id);
    try {
      let received;
      try {
        received = await receiveChunk(req, file, current, config.chunkBytes);
      } catch (e) {
        if (e && e.code === 'chunk_too_large') return res.status(413).json({ success: false, error: 'chunk_too_large', maxBytes: config.chunkBytes });
        return undefined;
      }
      if (current + received > upload.size) {
        fs.truncateSync(file, current);
        return res.status(413).json({ success: false, error: 'exceeds_declared_size' });
      }
      if (current === 0) {
        const ext = sniffExtension(readHead(file, 64));
        const allowed = upload.kind === 'video' ? VIDEO_EXT : IMAGE_EXT;
        if (!ext || !allowed.includes(ext)) {
          unlinkQuiet(file);
          await store.deleteUpload(upload.id);
          return res.status(415).json({ success: false, error: 'unsupported_media_type' });
        }
        await store.setUploadExt(upload.id, ext);
      }
      return res.json({ success: true, offset: current + received });
    } finally {
      busyUploads.delete(upload.id);
    }
  }));

  router.post('/media/finish/:id', writeLimiter, auth.requireAccount, guard(async (req, res) => {
    const upload = await ownedUpload(req, res);
    if (!upload) return undefined;
    const base = publicBase(req, config);
    if (upload.finalName) {
      return res.json({ success: true, name: upload.finalName, path: '/media/' + upload.finalName, url: base + '/media/' + upload.finalName, size: upload.size });
    }
    const file = path.join(config.tmpDir, upload.id + '.part');
    const actual = fs.existsSync(file) ? fs.statSync(file).size : 0;
    if (actual !== upload.size || !upload.ext) {
      return res.status(409).json({ success: false, error: 'incomplete', expectedOffset: actual });
    }
    const name = crypto.randomBytes(16).toString('hex') + '.' + upload.ext;
    fs.mkdirSync(config.mediaDir, { recursive: true });
    fs.renameSync(file, path.join(config.mediaDir, name));
    await store.recordMedia({ name, ownerId: upload.ownerId, kind: upload.kind, size: upload.size });
    await store.completeUpload(upload.id, name);
    await store.anchor('MEDIA_STORED', 'VAULT_09', { name, ownerId: upload.ownerId, size: upload.size });
    return res.json({ success: true, name, path: '/media/' + name, url: base + '/media/' + name, size: upload.size });
  }));

  return router;
}

module.exports = { createContentRouter, cleanupStaleUploads, sniffExtension };
