'use strict';
/* © 2026 Zentora CLC. All rights reserved. Platform Core engineered by Zentora. */

const ID_RE = /^[A-Za-z0-9_-]{3,80}$/;
const MEDIA_EXT = 'mp4|mov|3gp|webm|mkv|jpg|png|webp';
const MEDIA_NAME_RE = new RegExp('^[a-f0-9]{32}\\.(?:' + MEDIA_EXT + ')$');
const MEDIA_PATH_RE = new RegExp('^/media/([a-f0-9]{32}\\.(?:' + MEDIA_EXT + '))$');
const VISIBILITIES = ['Public', 'Unlisted', 'Private'];

/** Always returns a string no longer than [max]. */
function str(value, max) {
  return String(value === null || value === undefined ? '' : value).slice(0, max);
}

/** Integer clamp. Anything that is not a number becomes [lo]. */
function clampInt(value, lo, hi) {
  const n = Math.floor(Number(value));
  if (!Number.isFinite(n)) return lo;
  return Math.min(hi, Math.max(lo, n));
}

function isHttpsUrl(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 1000) return false;
  try {
    const u = new URL(value);
    return u.protocol === 'https:' && u.hostname.length > 0;
  } catch (_e) {
    return false;
  }
}

/** Public base URL of this server, e.g. https://nexora-backend-xxxx.onrender.com (no trailing slash). */
function publicBase(req, config) {
  if (config.publicBaseUrl) return config.publicBaseUrl.replace(/\/+$/, '');
  return `${req.protocol}://${req.get('host')}`;
}

/** Files hosted by this server are stored as "/media/<name>" so they survive a domain change. */
function absolutize(url, base) {
  return typeof url === 'string' && url.startsWith('/media/') ? base + url : url;
}

/**
 * Resolves a media URL sent by the app.
 *  - a "/media/<name>" path (absolute or relative) that [ownerId] uploaded -> canonical "/media/<name>"
 *  - a "/media/<name>" path that is unknown or belongs to somebody else   -> null (rejected)
 *  - any other URL -> returned unchanged (validated by the caller)
 */
async function canonicalizeMediaUrl(url, ownerId, store) {
  let pathname = url;
  try {
    pathname = new URL(url).pathname;
  } catch (_e) {
    /* a bare "/media/<name>" path is not a parsable absolute URL: use it as is */
  }
  const m = MEDIA_PATH_RE.exec(pathname);
  if (!m) return url;
  const media = await store.findMedia(m[1]);
  return media && media.ownerId === ownerId ? '/media/' + m[1] : null;
}

function creatorLevel(subscribers, views) {
  if (subscribers >= 100000 || views >= 1000000) return 'Diamond Streamer';
  if (subscribers >= 1000 || views >= 10000) return 'Gold Creator';
  return 'Rising Creator';
}

/** Shape the Android app parses (see ServerVideo in AccountBackend.kt). Extra fields are ignored by older apps. */
function toVideoItem(v, base) {
  return {
    id: v.id,
    localUri: absolutize(v.videoUrl, base),
    title: v.title,
    description: v.description,
    category: v.category,
    tags: v.tags,
    timestamp: v.createdAt,
    duration: v.duration,
    viewCount: v.views,
    chapterMarkersJson: v.chapterMarkersJson,
    thumbnailUri: absolutize(v.thumbnailUrl, base),
    authorChannelId: 'ch_' + v.ownerId,
    collabChannelId: v.collabChannelId,
    isPremiere: v.isPremiere,
    premiereScheduledTimeMs: v.premiereScheduledTimeMs,
    likeCount: v.likes,
    dislikeCount: v.dislikes,
    shareCount: v.shares,
    sparkCount: v.sparks,
    ownerNexoraId: v.ownerId,
    channelName: v.channelName || '',
    channelAvatarUri: absolutize(v.channelAvatar || '', base),
    visibility: v.visibility
  };
}

/** Wraps an async route so a thrown error becomes a retryable 503 instead of a hung request. */
function guard(handler) {
  return async (req, res) => {
    try {
      await handler(req, res);
    } catch (e) {
      console.error('[nexora]', req.method, req.path, e && e.stack ? e.stack : e);
      if (!res.headersSent) res.status(503).json({ success: false, error: 'unavailable' });
    }
  };
}

module.exports = {
  ID_RE,
  MEDIA_NAME_RE,
  MEDIA_PATH_RE,
  VISIBILITIES,
  str,
  clampInt,
  isHttpsUrl,
  publicBase,
  absolutize,
  canonicalizeMediaUrl,
  creatorLevel,
  toVideoItem,
  guard
};
