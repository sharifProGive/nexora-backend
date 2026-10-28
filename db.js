'use strict';
/* © 2026 Zentora CLC. All rights reserved. Platform Core engineered by Zentora. */
/**
 * Self-hosted storage: one SQLite file (Node's built-in node:sqlite, no native add-on, no external service).
 * Put the file on a persistent disk (NEXORA_DATA_DIR) or it is lost whenever the host wipes its filesystem.
 */
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { DatabaseSync } = require('node:sqlite');
const { MEDIA_PATH_RE } = require('./util');
const { VAULTS, SHARD_FIRST, SHARD_COUNT, shardVaultFor, vaultCode, LEDGER_VAULT } = require('./vaults');

const SCHEMA_V1 = `
CREATE TABLE users (
  sub TEXT PRIMARY KEY,
  nexora_id TEXT NOT NULL UNIQUE,
  email TEXT NOT NULL DEFAULT '',
  username TEXT NOT NULL DEFAULT '',
  handle TEXT NOT NULL DEFAULT '',
  avatar_uri TEXT NOT NULL DEFAULT '',
  phone TEXT NOT NULL DEFAULT '',
  billing TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL
);
CREATE TABLE videos (
  id TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL,
  title TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  category TEXT NOT NULL DEFAULT 'General',
  tags TEXT NOT NULL DEFAULT '',
  video_url TEXT NOT NULL,
  thumbnail_url TEXT NOT NULL DEFAULT '',
  duration INTEGER NOT NULL DEFAULT 0,
  visibility TEXT NOT NULL DEFAULT 'Public',
  chapter_markers_json TEXT NOT NULL DEFAULT '[]',
  collab_channel_id TEXT,
  is_premiere INTEGER NOT NULL DEFAULT 0,
  premiere_scheduled_ms INTEGER,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  views INTEGER NOT NULL DEFAULT 0,
  likes INTEGER NOT NULL DEFAULT 0,
  sparks INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_videos_owner ON videos(owner_id, created_at DESC);
CREATE INDEX idx_videos_feed ON videos(visibility, created_at DESC);
CREATE TABLE video_likes (
  video_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (video_id, user_id)
);
CREATE INDEX idx_likes_user ON video_likes(user_id, created_at DESC);
CREATE TABLE comments (
  comment_id TEXT PRIMARY KEY,
  video_id TEXT NOT NULL,
  owner_id TEXT NOT NULL,
  author_name TEXT NOT NULL DEFAULT '',
  body TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  like_count INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_comments_video ON comments(video_id, created_at DESC);
CREATE TABLE media (
  name TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  size INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX idx_media_owner ON media(owner_id);
CREATE TABLE uploads (
  id TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  size INTEGER NOT NULL,
  ext TEXT,
  final_name TEXT,
  created_at INTEGER NOT NULL
);
CREATE INDEX idx_uploads_owner ON uploads(owner_id);
CREATE TABLE ads (
  ad_id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  sponsor_name TEXT NOT NULL,
  ad_media_url TEXT NOT NULL,
  click_through_url TEXT NOT NULL,
  skippable_after_seconds INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  impressions INTEGER NOT NULL DEFAULT 0,
  clicks INTEGER NOT NULL DEFAULT 0,
  skips INTEGER NOT NULL DEFAULT 0,
  completes INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE ledger (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  tx_id TEXT NOT NULL UNIQUE,
  source_vault TEXT NOT NULL,
  event_type TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  payload TEXT NOT NULL,
  prev_hash TEXT NOT NULL,
  vault_hash TEXT NOT NULL
);
`;

const SCHEMA_V2 = `
ALTER TABLE videos ADD COLUMN dislikes INTEGER NOT NULL DEFAULT 0;
ALTER TABLE videos ADD COLUMN shares INTEGER NOT NULL DEFAULT 0;
ALTER TABLE comments ADD COLUMN shares INTEGER NOT NULL DEFAULT 0;
CREATE TABLE video_dislikes (
  video_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (video_id, user_id)
);
CREATE INDEX idx_dislikes_user ON video_dislikes(user_id, created_at DESC);
CREATE TABLE video_shares (
  share_id INTEGER PRIMARY KEY AUTOINCREMENT,
  video_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  channel TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL
);
CREATE INDEX idx_vshares_video ON video_shares(video_id);
CREATE TABLE comment_shares (
  share_id INTEGER PRIMARY KEY AUTOINCREMENT,
  comment_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  channel TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL
);
CREATE INDEX idx_cshares_comment ON comment_shares(comment_id);
CREATE TABLE video_sparks (
  spark_id INTEGER PRIMARY KEY AUTOINCREMENT,
  video_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  amount INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX idx_sparks_video ON video_sparks(video_id);
CREATE TABLE shard_events (
  event_id INTEGER PRIMARY KEY AUTOINCREMENT,
  vault_no INTEGER NOT NULL,
  video_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  amount INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL
);
CREATE INDEX idx_shard_vault ON shard_events(vault_no, created_at DESC);
CREATE INDEX idx_shard_video ON shard_events(video_id);
CREATE TABLE vault_stats (
  vault_no INTEGER PRIMARY KEY,
  ops INTEGER NOT NULL DEFAULT 0,
  errors INTEGER NOT NULL DEFAULT 0,
  last_op_at INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_videos_premiere ON videos(is_premiere, premiere_scheduled_ms);
`;

const MIGRATIONS = [SCHEMA_V1, SCHEMA_V2];
const SCHEMA_VERSION = MIGRATIONS.length;

const GENESIS_HASH = '0'.repeat(64);

const VIDEO_SELECT = `
  SELECT v.*, COALESCE(NULLIF(u.username, ''), u.handle) AS channel_name, u.avatar_uri AS channel_avatar
  FROM videos v LEFT JOIN users u ON u.nexora_id = v.owner_id`;

function userFromRow(r) {
  if (!r) return null;
  return {
    sub: r.sub,
    nexoraId: r.nexora_id,
    email: r.email,
    username: r.username,
    handle: r.handle,
    avatarUri: r.avatar_uri,
    createdAt: r.created_at
  };
}

function videoFromRow(r) {
  if (!r) return null;
  return {
    id: r.id,
    ownerId: r.owner_id,
    title: r.title,
    description: r.description,
    category: r.category,
    tags: r.tags,
    videoUrl: r.video_url,
    thumbnailUrl: r.thumbnail_url,
    duration: r.duration,
    visibility: r.visibility,
    chapterMarkersJson: r.chapter_markers_json,
    collabChannelId: r.collab_channel_id === undefined ? null : r.collab_channel_id,
    isPremiere: r.is_premiere === 1,
    premiereScheduledTimeMs: r.premiere_scheduled_ms === undefined ? null : r.premiere_scheduled_ms,
    createdAt: r.created_at,
    updatedAt: r.updated_at,
    views: r.views,
    likes: r.likes,
    dislikes: r.dislikes,
    shares: r.shares,
    sparks: r.sparks,
    channelName: r.channel_name === undefined ? '' : r.channel_name,
    channelAvatar: r.channel_avatar === undefined ? '' : r.channel_avatar
  };
}

function adFromRow(r) {
  if (!r) return null;
  return {
    adId: r.ad_id,
    title: r.title,
    sponsorName: r.sponsor_name,
    adMediaUrl: r.ad_media_url,
    clickThroughUrl: r.click_through_url,
    skippableAfterSeconds: r.skippable_after_seconds,
    metrics: { impressions: r.impressions, clicks: r.clicks, skips: r.skips, completes: r.completes }
  };
}

function createSqliteStore({ dbPath }) {
  if (dbPath !== ':memory:') fs.mkdirSync(path.dirname(dbPath), { recursive: true });
  const db = new DatabaseSync(dbPath);
  db.exec('PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL; PRAGMA busy_timeout = 5000;');

  const version = db.prepare('PRAGMA user_version').get().user_version;
  if (version > SCHEMA_VERSION) {
    throw new Error(`Database schema v${version} is newer than this server (v${SCHEMA_VERSION}). Refusing to start.`);
  }
  for (let v = version; v < SCHEMA_VERSION; v += 1) {
    db.exec('BEGIN');
    try {
      db.exec(MIGRATIONS[v]);
      db.exec(`PRAGMA user_version = ${v + 1}`);
      db.exec('COMMIT');
    } catch (e) {
      db.exec('ROLLBACK');
      throw e;
    }
  }

  const cache = new Map();
  const stmt = (sql) => {
    let s = cache.get(sql);
    if (!s) {
      s = db.prepare(sql);
      cache.set(sql, s);
    }
    return s;
  };

  let depth = 0;
  function transaction(fn) {
    if (depth > 0) return fn();
    db.exec('BEGIN IMMEDIATE');
    depth += 1;
    try {
      const result = fn();
      db.exec('COMMIT');
      return result;
    } catch (e) {
      try { db.exec('ROLLBACK'); } catch (_e) { /* connection already rolled back */ }
      throw e;
    } finally {
      depth -= 1;
    }
  }

  // ------------------------------------------------------------------ users
  function findUserBySub(sub) {
    return userFromRow(stmt('SELECT * FROM users WHERE sub = ?').get(sub));
  }

  function findUserByNexoraId(nexoraId) {
    return userFromRow(stmt('SELECT * FROM users WHERE nexora_id = ?').get(nexoraId));
  }

  function createUserIfAbsent(sub, rec) {
    return transaction(() => {
      const existing = stmt('SELECT * FROM users WHERE sub = ?').get(sub);
      if (existing) {
        stmt('UPDATE users SET last_seen_at = ? WHERE sub = ?').run(Date.now(), sub);
        return { user: userFromRow(existing), created: false };
      }
      const now = Date.now();
      stmt(
        'INSERT INTO users (sub, nexora_id, email, username, handle, avatar_uri, created_at, last_seen_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
      ).run(sub, rec.nexoraId, rec.email || '', rec.username || '', rec.handle || '', rec.avatarUri || '', now, now);
      return { user: userFromRow(stmt('SELECT * FROM users WHERE sub = ?').get(sub)), created: true };
    });
  }

  function touchUser(sub) {
    stmt('UPDATE users SET last_seen_at = ? WHERE sub = ?').run(Date.now(), sub);
  }

  function updateProfile(nexoraId, p) {
    stmt('UPDATE users SET username = ?, handle = ?, avatar_uri = ? WHERE nexora_id = ?').run(p.username, p.handle, p.avatarUri, nexoraId);
    return findUserByNexoraId(nexoraId);
  }

  function getPrivate(nexoraId) {
    const r = stmt('SELECT phone, billing FROM users WHERE nexora_id = ?').get(nexoraId);
    return r ? { phoneNumber: r.phone, billingInfo: r.billing } : null;
  }

  function savePrivate(nexoraId, data) {
    stmt('UPDATE users SET phone = ?, billing = ? WHERE nexora_id = ?').run(data.phoneNumber || '', data.billingInfo || '', nexoraId);
  }

  // ------------------------------------------------------------------ videos
  function upsertVideo(v) {
    return transaction(() => {
      const existing = stmt('SELECT owner_id FROM videos WHERE id = ?').get(v.id);
      const now = Date.now();
      if (existing && existing.owner_id !== v.ownerId) return { ok: false, created: false };
      if (!existing) {
        stmt(
          `INSERT INTO videos (id, owner_id, title, description, category, tags, video_url, thumbnail_url, duration, visibility,
             chapter_markers_json, collab_channel_id, is_premiere, premiere_scheduled_ms, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        ).run(
          v.id, v.ownerId, v.title, v.description, v.category, v.tags, v.videoUrl, v.thumbnailUrl, v.duration,
          v.visibility || 'Public', v.chapterMarkersJson, v.collabChannelId === undefined ? null : v.collabChannelId,
          v.isPremiere ? 1 : 0, v.premiereScheduledTimeMs === undefined ? null : v.premiereScheduledTimeMs, v.createdAt, now
        );
        return { ok: true, created: true };
      }
      stmt(
        `UPDATE videos SET title = ?, description = ?, category = ?, tags = ?, video_url = ?, thumbnail_url = ?, duration = ?,
           visibility = COALESCE(?, visibility), chapter_markers_json = ?, collab_channel_id = ?, is_premiere = ?,
           premiere_scheduled_ms = ?, updated_at = ?
         WHERE id = ?`
      ).run(
        v.title, v.description, v.category, v.tags, v.videoUrl, v.thumbnailUrl, v.duration,
        v.visibility === undefined ? null : v.visibility, v.chapterMarkersJson,
        v.collabChannelId === undefined ? null : v.collabChannelId, v.isPremiere ? 1 : 0,
        v.premiereScheduledTimeMs === undefined ? null : v.premiereScheduledTimeMs, now, v.id
      );
      return { ok: true, created: false };
    });
  }

  function getVideo(id) {
    return videoFromRow(stmt(`${VIDEO_SELECT} WHERE v.id = ?`).get(id));
  }

  function listVideosByOwner(ownerId, limit) {
    return stmt(`${VIDEO_SELECT} WHERE v.owner_id = ? ORDER BY v.created_at DESC LIMIT ?`).all(ownerId, limit).map(videoFromRow);
  }

  function listFeed({ limit, before }) {
    if (before) {
      return stmt(`${VIDEO_SELECT} WHERE v.visibility = 'Public' AND v.created_at < ? ORDER BY v.created_at DESC LIMIT ?`)
        .all(before, limit).map(videoFromRow);
    }
    return stmt(`${VIDEO_SELECT} WHERE v.visibility = 'Public' ORDER BY v.created_at DESC LIMIT ?`).all(limit).map(videoFromRow);
  }

  function searchVideos(query, limit) {
    const like = '%' + query.replace(/[\\%_]/g, '\\$&') + '%';
    return stmt(
      `${VIDEO_SELECT} WHERE v.visibility = 'Public'
         AND (v.title LIKE ? ESCAPE '\\' OR v.tags LIKE ? ESCAPE '\\' OR v.description LIKE ? ESCAPE '\\')
       ORDER BY v.created_at DESC LIMIT ?`
    ).all(like, like, like, limit).map(videoFromRow);
  }

  /** Returns the orphaned media file names (no other video uses them) so the caller can delete the files. */
  function deleteVideo(id, ownerId) {
    return transaction(() => {
      const row = stmt('SELECT * FROM videos WHERE id = ?').get(id);
      if (!row) return { ok: true, removed: false, orphanMedia: [] };
      if (row.owner_id !== ownerId) return { ok: false, removed: false, orphanMedia: [] };
      stmt('DELETE FROM video_likes WHERE video_id = ?').run(id);
      stmt('DELETE FROM video_dislikes WHERE video_id = ?').run(id);
      stmt('DELETE FROM video_shares WHERE video_id = ?').run(id);
      stmt('DELETE FROM video_sparks WHERE video_id = ?').run(id);
      stmt('DELETE FROM shard_events WHERE video_id = ?').run(id);
      stmt('DELETE FROM comment_shares WHERE comment_id IN (SELECT comment_id FROM comments WHERE video_id = ?)').run(id);
      stmt('DELETE FROM comments WHERE video_id = ?').run(id);
      stmt('DELETE FROM videos WHERE id = ?').run(id);
      const orphanMedia = [];
      for (const url of [row.video_url, row.thumbnail_url]) {
        const m = MEDIA_PATH_RE.exec(url || '');
        if (!m) continue;
        const stillUsed = stmt('SELECT 1 AS used FROM videos WHERE video_url = ? OR thumbnail_url = ? LIMIT 1').get(url, url);
        if (!stillUsed) {
          stmt('DELETE FROM media WHERE name = ?').run(m[1]);
          orphanMedia.push(m[1]);
        }
      }
      return { ok: true, removed: true, orphanMedia };
    });
  }

  /**
   * Vault 01 write path. Every effective change is also appended to the expansion shard (vault 11..34) chosen by the
   * video id, in the same transaction.
   *   views   0..1      +1 view
   *   like    -1..1     +1 adds this account's like (idempotent, removes its dislike), -1 removes it
   *   dislike -1..1     same for dislikes (removes its like)
   *   sparks  0..1000   sparks sent, recorded with the sender
   *   share   null | { channel }   one share of the video
   * Returns null if the video is unknown.
   */
  function addVideoDelta(videoId, userId, delta) {
    return transaction(() => {
      const row = stmt('SELECT id FROM videos WHERE id = ?').get(videoId);
      if (!row) return null;
      const now = Date.now();
      const shard = shardVaultFor(videoId);
      const event = (kind, amount) => {
        stmt('INSERT INTO shard_events (vault_no, video_id, user_id, kind, amount, created_at) VALUES (?, ?, ?, ?, ?, ?)')
          .run(shard, videoId, userId, kind, amount, now);
      };
      const dropLike = () => {
        const r = stmt('DELETE FROM video_likes WHERE video_id = ? AND user_id = ?').run(videoId, userId);
        if (r.changes > 0) {
          stmt('UPDATE videos SET likes = MAX(0, likes - 1) WHERE id = ?').run(videoId);
          event('unlike', 1);
        }
      };
      const dropDislike = () => {
        const r = stmt('DELETE FROM video_dislikes WHERE video_id = ? AND user_id = ?').run(videoId, userId);
        if (r.changes > 0) {
          stmt('UPDATE videos SET dislikes = MAX(0, dislikes - 1) WHERE id = ?').run(videoId);
          event('undislike', 1);
        }
      };
      if (delta.views > 0) {
        stmt('UPDATE videos SET views = views + ? WHERE id = ?').run(delta.views, videoId);
        event('view', delta.views);
      }
      if (delta.like > 0) {
        const r = stmt('INSERT OR IGNORE INTO video_likes (video_id, user_id, created_at) VALUES (?, ?, ?)').run(videoId, userId, now);
        if (r.changes > 0) {
          stmt('UPDATE videos SET likes = likes + 1 WHERE id = ?').run(videoId);
          event('like', 1);
        }
        dropDislike();
      } else if (delta.like < 0) {
        dropLike();
      }
      if (delta.dislike > 0) {
        const r = stmt('INSERT OR IGNORE INTO video_dislikes (video_id, user_id, created_at) VALUES (?, ?, ?)').run(videoId, userId, now);
        if (r.changes > 0) {
          stmt('UPDATE videos SET dislikes = dislikes + 1 WHERE id = ?').run(videoId);
          event('dislike', 1);
        }
        dropLike();
      } else if (delta.dislike < 0) {
        dropDislike();
      }
      if (delta.share) {
        stmt('INSERT INTO video_shares (video_id, user_id, channel, created_at) VALUES (?, ?, ?, ?)').run(videoId, userId, delta.share.channel || '', now);
        stmt('UPDATE videos SET shares = shares + 1 WHERE id = ?').run(videoId);
        event('share', 1);
      }
      if (delta.sparks > 0) {
        stmt('INSERT INTO video_sparks (video_id, user_id, amount, created_at) VALUES (?, ?, ?, ?)').run(videoId, userId, delta.sparks, now);
        stmt('UPDATE videos SET sparks = sparks + ? WHERE id = ?').run(delta.sparks, videoId);
        event('spark', delta.sparks);
      }
      const out = stmt('SELECT views, likes, dislikes, shares, sparks FROM videos WHERE id = ?').get(videoId);
      return { views: out.views, likes: out.likes, dislikes: out.dislikes, shares: out.shares, sparks: out.sparks };
    });
  }

  function likedVideoIds(userId, limit) {
    return stmt('SELECT video_id FROM video_likes WHERE user_id = ? ORDER BY created_at DESC LIMIT ?').all(userId, limit).map((r) => r.video_id);
  }

  function dislikedVideoIds(userId, limit) {
    return stmt('SELECT video_id FROM video_dislikes WHERE user_id = ? ORDER BY created_at DESC LIMIT ?').all(userId, limit).map((r) => r.video_id);
  }

  // ------------------------------------------------------------------ vault 06 channels, vault 10 premieres
  function getChannel(nexoraId) {
    const u = stmt('SELECT * FROM users WHERE nexora_id = ?').get(nexoraId);
    if (!u) return null;
    const t = stmt(
      `SELECT COUNT(*) AS videos, COALESCE(SUM(views), 0) AS views, COALESCE(SUM(likes), 0) AS likes
       FROM videos WHERE owner_id = ? AND visibility = 'Public'`
    ).get(nexoraId);
    return {
      nexoraId: u.nexora_id,
      username: u.username,
      handle: u.handle,
      avatarUri: u.avatar_uri,
      joinedAt: u.created_at,
      videoCount: t.videos,
      totalViews: t.views,
      totalLikes: t.likes
    };
  }

  function listPublicVideosByOwner(ownerId, limit) {
    return stmt(`${VIDEO_SELECT} WHERE v.owner_id = ? AND v.visibility = 'Public' ORDER BY v.created_at DESC LIMIT ?`).all(ownerId, limit).map(videoFromRow);
  }

  function listPremieres(sinceMs, limit) {
    return stmt(
      `${VIDEO_SELECT} WHERE v.is_premiere = 1 AND v.visibility = 'Public' AND v.premiere_scheduled_ms IS NOT NULL
         AND v.premiere_scheduled_ms >= ? ORDER BY v.premiere_scheduled_ms ASC LIMIT ?`
    ).all(sinceMs, limit).map(videoFromRow);
  }

  // ------------------------------------------------------------------ comments
  function upsertComment(c) {
    return transaction(() => {
      const existing = stmt('SELECT owner_id FROM comments WHERE comment_id = ?').get(c.commentId);
      if (existing) return { ok: existing.owner_id === c.ownerId };
      stmt(
        'INSERT INTO comments (comment_id, video_id, owner_id, author_name, body, created_at, like_count) VALUES (?, ?, ?, ?, ?, ?, 0)'
      ).run(c.commentId, c.videoId, c.ownerId, c.authorName, c.text, c.timestamp);
      return { ok: true };
    });
  }

  function listComments(videoId, limit) {
    return stmt('SELECT * FROM comments WHERE video_id = ? ORDER BY created_at DESC LIMIT ?').all(videoId, limit).map((r) => ({
      commentId: r.comment_id,
      videoId: r.video_id,
      authorName: r.author_name,
      text: r.body,
      timestamp: r.created_at,
      likeCount: r.like_count,
      shareCount: r.shares
    }));
  }

  /** Vault 01 comment-shares sub-vault. Returns the new share count, or null if the comment is unknown. */
  function shareComment(commentId, userId, channel) {
    return transaction(() => {
      const row = stmt('SELECT video_id FROM comments WHERE comment_id = ?').get(commentId);
      if (!row) return null;
      stmt('INSERT INTO comment_shares (comment_id, user_id, channel, created_at) VALUES (?, ?, ?, ?)').run(commentId, userId, channel || '', Date.now());
      stmt('UPDATE comments SET shares = shares + 1 WHERE comment_id = ?').run(commentId);
      stmt('INSERT INTO shard_events (vault_no, video_id, user_id, kind, amount, created_at) VALUES (?, ?, ?, ?, 1, ?)')
        .run(shardVaultFor(row.video_id), row.video_id, userId, 'comment-share', Date.now());
      return { videoId: row.video_id, shares: stmt('SELECT shares FROM comments WHERE comment_id = ?').get(commentId).shares };
    });
  }

  function getComment(commentId) {
    const r = stmt('SELECT * FROM comments WHERE comment_id = ?').get(commentId);
    return r ? { commentId: r.comment_id, videoId: r.video_id, ownerId: r.owner_id } : null;
  }

  // ------------------------------------------------------------------ media + resumable upload sessions
  function recordMedia(m) {
    stmt('INSERT OR REPLACE INTO media (name, owner_id, kind, size, created_at) VALUES (?, ?, ?, ?, ?)').run(m.name, m.ownerId, m.kind, m.size, Date.now());
  }

  function findMedia(name) {
    const r = stmt('SELECT * FROM media WHERE name = ?').get(name);
    return r ? { name: r.name, ownerId: r.owner_id, kind: r.kind, size: r.size, createdAt: r.created_at } : null;
  }

  function deleteMediaRows(names) {
    for (const n of names) stmt('DELETE FROM media WHERE name = ?').run(n);
  }

  /** Bytes already stored plus bytes reserved by unfinished uploads. */
  function storageUsed(ownerId) {
    const a = stmt('SELECT COALESCE(SUM(size), 0) AS n FROM media WHERE owner_id = ?').get(ownerId).n;
    const b = stmt('SELECT COALESCE(SUM(size), 0) AS n FROM uploads WHERE owner_id = ? AND final_name IS NULL').get(ownerId).n;
    return a + b;
  }

  function createUpload(u) {
    stmt('INSERT INTO uploads (id, owner_id, kind, size, ext, final_name, created_at) VALUES (?, ?, ?, ?, NULL, NULL, ?)').run(u.id, u.ownerId, u.kind, u.size, Date.now());
  }

  function getUpload(id) {
    const r = stmt('SELECT * FROM uploads WHERE id = ?').get(id);
    return r ? { id: r.id, ownerId: r.owner_id, kind: r.kind, size: r.size, ext: r.ext, finalName: r.final_name, createdAt: r.created_at } : null;
  }

  function countOpenUploads(ownerId) {
    return stmt('SELECT COUNT(*) AS n FROM uploads WHERE owner_id = ? AND final_name IS NULL').get(ownerId).n;
  }

  function setUploadExt(id, ext) {
    stmt('UPDATE uploads SET ext = ? WHERE id = ?').run(ext, id);
  }

  function completeUpload(id, finalName) {
    stmt('UPDATE uploads SET final_name = ? WHERE id = ?').run(finalName, id);
  }

  function deleteUpload(id) {
    stmt('DELETE FROM uploads WHERE id = ?').run(id);
  }

  function listStaleUploads(olderThanMs) {
    return stmt('SELECT id FROM uploads WHERE created_at < ?').all(olderThanMs).map((r) => r.id);
  }

  // ------------------------------------------------------------------ vault 02: ads & campaigns
  function createAd(ad) {
    stmt(
      'INSERT INTO ads (ad_id, title, sponsor_name, ad_media_url, click_through_url, skippable_after_seconds, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)'
    ).run(ad.adId, ad.title, ad.sponsorName, ad.adMediaUrl, ad.clickThroughUrl, ad.skippableAfterSeconds, Date.now());
  }

  function pickRandomAd() {
    return transaction(() => {
      const row = stmt('SELECT * FROM ads ORDER BY RANDOM() LIMIT 1').get();
      if (!row) return null;
      stmt('UPDATE ads SET impressions = impressions + 1 WHERE ad_id = ?').run(row.ad_id);
      return adFromRow(stmt('SELECT * FROM ads WHERE ad_id = ?').get(row.ad_id));
    });
  }

  function trackAd(adId, action) {
    const column = { click: 'clicks', skip: 'skips', complete: 'completes' }[action];
    if (!column) return null;
    const r = stmt(`UPDATE ads SET ${column} = ${column} + 1 WHERE ad_id = ?`).run(adId);
    if (r.changes === 0) return null;
    return adFromRow(stmt('SELECT * FROM ads WHERE ad_id = ?').get(adId)).metrics;
  }

  // ------------------------------------------------------------------ vault 35: hash-chained master ledger
  function anchor(eventType, sourceVault, payload) {
    return transaction(() => {
      const head = stmt('SELECT vault_hash FROM ledger ORDER BY seq DESC LIMIT 1').get();
      const prevHash = head ? head.vault_hash : GENESIS_HASH;
      const createdAt = Date.now();
      const payloadJson = JSON.stringify(payload);
      const vaultHash = crypto
        .createHash('sha256')
        .update([prevHash, eventType, sourceVault, createdAt, payloadJson].join('|'))
        .digest('hex');
      const txId = 'ZT-MASTER-' + crypto.randomBytes(8).toString('hex').toUpperCase();
      stmt(
        'INSERT INTO ledger (tx_id, source_vault, event_type, created_at, payload, prev_hash, vault_hash) VALUES (?, ?, ?, ?, ?, ?, ?)'
      ).run(txId, sourceVault, eventType, createdAt, payloadJson, prevHash, vaultHash);
      return { txId, vaultHash, prevHash, eventType, sourceVault, createdAt };
    });
  }

  function verifyLedger() {
    let prev = GENESIS_HASH;
    for (const r of stmt('SELECT * FROM ledger ORDER BY seq ASC').all()) {
      const expected = crypto
        .createHash('sha256')
        .update([prev, r.event_type, r.source_vault, r.created_at, r.payload].join('|'))
        .digest('hex');
      if (r.prev_hash !== prev || r.vault_hash !== expected) return false;
      prev = r.vault_hash;
    }
    return true;
  }

  function counts() {
    const n = (sql) => stmt(sql).get().n;
    const head = stmt('SELECT vault_hash FROM ledger ORDER BY seq DESC LIMIT 1').get();
    return {
      users: n('SELECT COUNT(*) AS n FROM users'),
      videos: n('SELECT COUNT(*) AS n FROM videos'),
      media: n('SELECT COUNT(*) AS n FROM media'),
      ads: n('SELECT COUNT(*) AS n FROM ads'),
      ledgerBlocks: n('SELECT COUNT(*) AS n FROM ledger'),
      ledgerHead: head ? head.vault_hash : ''
    };
  }

  // ------------------------------------------------------------------ per-vault statistics and records
  function addVaultStats(entries) {
    transaction(() => {
      for (const e of entries) {
        stmt(
          `INSERT INTO vault_stats (vault_no, ops, errors, last_op_at) VALUES (?, ?, ?, ?)
           ON CONFLICT(vault_no) DO UPDATE SET ops = ops + excluded.ops, errors = errors + excluded.errors,
             last_op_at = MAX(last_op_at, excluded.last_op_at)`
        ).run(e.no, e.ops, e.errors, e.lastOpAt);
      }
    });
  }

  function getVaultStats() {
    const out = new Map();
    for (const r of stmt('SELECT * FROM vault_stats').all()) out.set(r.vault_no, { ops: r.ops, errors: r.errors, lastOpAt: r.last_op_at });
    return out;
  }

  /** What each vault holds right now. Vault 35 reports the ledger. The digest of this object secures the vault. */
  function vaultRecords() {
    const n = (sql) => stmt(sql).get().n;
    const vid = stmt('SELECT COALESCE(SUM(views), 0) AS views, COALESCE(SUM(likes), 0) AS likes, COALESCE(SUM(dislikes), 0) AS dislikes, COALESCE(SUM(sparks), 0) AS sparks, COALESCE(SUM(shares), 0) AS shares FROM videos').get();
    const ad = stmt('SELECT COUNT(*) AS campaigns, COALESCE(SUM(impressions), 0) AS impressions, COALESCE(SUM(clicks), 0) AS clicks, COALESCE(SUM(skips), 0) AS skips, COALESCE(SUM(completes), 0) AS completes FROM ads').get();
    const records = {};
    records[1] = {
      views: vid.views, likes: vid.likes, dislikes: vid.dislikes, comments: n('SELECT COUNT(*) AS n FROM comments'),
      commentShares: n('SELECT COUNT(*) AS n FROM comment_shares'), videoShares: vid.shares, sparks: vid.sparks
    };
    records[2] = { campaigns: ad.campaigns, impressions: ad.impressions, clicks: ad.clicks, skips: ad.skips, completes: ad.completes };
    records[3] = { accounts: n('SELECT COUNT(*) AS n FROM users') };
    records[4] = { videos: n('SELECT COUNT(*) AS n FROM videos'), withThumbnail: n("SELECT COUNT(*) AS n FROM videos WHERE thumbnail_url <> ''") };
    records[5] = { accountsWithPhone: n("SELECT COUNT(*) AS n FROM users WHERE phone <> ''"), accountsWithBilling: n("SELECT COUNT(*) AS n FROM users WHERE billing <> ''") };
    records[6] = { channels: n('SELECT COUNT(*) AS n FROM users') };
    records[7] = { publicVideos: n("SELECT COUNT(*) AS n FROM videos WHERE visibility = 'Public'") };
    records[8] = { indexedVideos: n("SELECT COUNT(*) AS n FROM videos WHERE visibility = 'Public'") };
    records[9] = {
      mediaFiles: n('SELECT COUNT(*) AS n FROM media'), mediaBytes: n('SELECT COALESCE(SUM(size), 0) AS n FROM media'),
      openUploads: n('SELECT COUNT(*) AS n FROM uploads WHERE final_name IS NULL')
    };
    records[10] = { premieres: n('SELECT COUNT(*) AS n FROM videos WHERE is_premiere = 1') };
    for (let no = SHARD_FIRST; no < SHARD_FIRST + SHARD_COUNT; no += 1) records[no] = { events: 0 };
    for (const r of stmt('SELECT vault_no, COUNT(*) AS c FROM shard_events GROUP BY vault_no').all()) {
      if (records[r.vault_no]) records[r.vault_no] = { events: r.c };
    }
    const head = stmt('SELECT vault_hash FROM ledger ORDER BY seq DESC LIMIT 1').get();
    records[LEDGER_VAULT] = { blocks: n('SELECT COUNT(*) AS n FROM ledger'), head: head ? head.vault_hash : '' };
    return records;
  }

  /**
   * Anchors one ledger block that carries the digest of every vault (1..34). Changing any record in any vault
   * afterwards changes that vault's digest in the next checkpoint, and the chain makes the old digests unforgeable.
   */
  function checkpointVaults() {
    const records = vaultRecords();
    const digests = {};
    for (const v of VAULTS) {
      if (v.no === LEDGER_VAULT) continue;
      digests[vaultCode(v.no)] = crypto.createHash('sha256').update(JSON.stringify(records[v.no])).digest('hex');
    }
    return anchor('VAULT_CHECKPOINT', vaultCode(LEDGER_VAULT), { digests });
  }

  function close() {
    db.close();
  }

  return {
    kind: 'sqlite',
    path: dbPath,
    findUserBySub, findUserByNexoraId, createUserIfAbsent, touchUser, updateProfile, getPrivate, savePrivate,
    upsertVideo, getVideo, listVideosByOwner, listPublicVideosByOwner, listFeed, searchVideos, deleteVideo, addVideoDelta, likedVideoIds, dislikedVideoIds,
    getChannel, listPremieres,
    upsertComment, listComments, shareComment, getComment,
    recordMedia, findMedia, deleteMediaRows, storageUsed, createUpload, getUpload, countOpenUploads, setUploadExt, completeUpload, deleteUpload, listStaleUploads,
    createAd, pickRandomAd, trackAd,
    anchor, verifyLedger, counts, addVaultStats, getVaultStats, vaultRecords, checkpointVaults, close
  };
}

module.exports = { createSqliteStore, MIGRATIONS };
