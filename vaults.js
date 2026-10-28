'use strict';
/* © 2026 Zentora CLC. All rights reserved. Platform Core engineered by Zentora. */
/**
 * The 35 Nexora vaults.
 *
 * A vault is a domain boundary: it owns a set of tables (its sub-vaults), its own operation counters and its own
 * record digest, and every vault is secured by Vault 35, the SHA-256 hash-chained master ledger.
 * All 35 vaults live in ONE SQLite database so related data is never fragmented across files, and so one
 * transaction can span several vaults (for example a like touches Vault 01 and its expansion shard).
 *
 *   01 Social Engagement        views, likes, dislikes, comments, comment-shares, video-shares, sparks
 *   02 Ads & Campaigns          ad media, sponsor info, click-through URL, impressions, clicks, skips, completes
 *   03 Google Login & Identity  Google sub mapping, nexoraId HMAC derivation, profiles, session tokens
 *   04 Video Stream & Metadata  video streams, metadata, titles, descriptions, thumbnails
 *   05 Private Data             phone number and billing details (owner only)
 *   06 Channels                 channel profiles and creator levels
 *   07 Feed Engine              public feed pages
 *   08 Search Index             title, tag and description search
 *   09 Resumable Media          upload sessions, chunk store, finalized media, storage quota
 *   10 Premiere & Live          premiere schedule and live window
 *   11-34 Expansion Shards      24 high-load shards; every engagement event of a video is appended to the shard
 *                               selected by a stable hash of the video id, so heavy videos do not share one hot table
 *   35 Grand Master Ledger      hash-chained immutable ledger, checkpoints, chain verifier
 */
const crypto = require('crypto');

const VAULT_COUNT = 35;
const SHARD_FIRST = 11;
const SHARD_LAST = 34;
const SHARD_COUNT = SHARD_LAST - SHARD_FIRST + 1;
const LEDGER_VAULT = 35;

const CORE_VAULTS = [
  {
    no: 1,
    key: 'engagement',
    name: 'Unified Social Engagement Vault',
    subVaults: ['views', 'likes', 'dislikes', 'comments', 'comment-shares', 'video-shares', 'sparks']
  },
  {
    no: 2,
    key: 'ads',
    name: 'Unified Ads & Campaign Vault',
    subVaults: ['ad-media', 'sponsor-info', 'click-through-url', 'impressions', 'clicks', 'skips', 'completes']
  },
  {
    no: 3,
    key: 'identity',
    name: 'Unified Google Login & Identity Vault',
    subVaults: ['google-sub-mapping', 'nexora-id-hmac-derivation', 'profiles', 'session-tokens']
  },
  {
    no: 4,
    key: 'video',
    name: 'Unified Video Stream & Metadata Vault',
    subVaults: ['video-streams', 'metadata', 'titles-descriptions', 'thumbnails']
  },
  { no: 5, key: 'private', name: 'Private Data Vault', subVaults: ['phone-number', 'billing-info'] },
  { no: 6, key: 'channels', name: 'Channel Vault', subVaults: ['channel-profiles', 'creator-levels'] },
  { no: 7, key: 'feed', name: 'Feed Engine Vault', subVaults: ['public-feed', 'cursor-pages'] },
  { no: 8, key: 'search', name: 'Search Index Vault', subVaults: ['title-index', 'tag-index', 'description-index'] },
  {
    no: 9,
    key: 'media',
    name: 'Resumable Media Upload Vault',
    subVaults: ['upload-sessions', 'chunk-store', 'finalized-media', 'storage-quota']
  },
  { no: 10, key: 'premiere', name: 'Premiere & Live Vault', subVaults: ['premiere-schedule', 'live-window'] }
];

function buildVaults() {
  const vaults = CORE_VAULTS.map((v) => ({ ...v, cluster: 'core' }));
  for (let no = SHARD_FIRST; no <= SHARD_LAST; no += 1) {
    const index = no - SHARD_FIRST + 1;
    vaults.push({
      no,
      key: 'shard-' + String(index).padStart(2, '0'),
      name: 'Expansion Shard Cluster ' + String(index).padStart(2, '0'),
      cluster: 'expansion',
      subVaults: ['engagement-event-shard']
    });
  }
  vaults.push({
    no: LEDGER_VAULT,
    key: 'ledger',
    name: 'Supreme Grand Master Ledger Vault',
    cluster: 'ledger',
    subVaults: ['sha256-hash-chain', 'vault-checkpoints', 'chain-verifier']
  });
  return vaults;
}

const VAULTS = Object.freeze(buildVaults());

if (VAULTS.length !== VAULT_COUNT) throw new Error('vault table must contain exactly ' + VAULT_COUNT + ' vaults');

function vaultByNo(no) {
  return VAULTS[no - 1] || null;
}

/** "VAULT_01" ... "VAULT_35": the name written into the master ledger. */
function vaultCode(no) {
  return 'VAULT_' + String(no).padStart(2, '0');
}

/** Stable expansion shard (11..34) for a resource id. The same id always lands on the same shard. */
function shardVaultFor(resourceId) {
  const digest = crypto.createHash('sha256').update('nexora-shard-v1:' + String(resourceId)).digest();
  return SHARD_FIRST + (digest.readUInt32BE(0) % SHARD_COUNT);
}

/**
 * Routing table: which vault serves a request. First match wins, so specific paths come before general ones.
 * [method or '*', RegExp for the path, vault number, auth class]
 * auth class: 'public' | 'session' | 'google' | 'admin' | 'mixed' (public read, session write)
 */
const ROUTES = [
  ['GET', /^\/api\/v1\/account\/get-profile$/, 3, 'google'],
  ['POST', /^\/api\/v1\/account\/register$/, 3, 'google'],
  ['*', /^\/api\/v1\/account\/(?:get-private|save-private)$/, 5, 'session'],
  ['*', /^\/api\/v1\/account\/(?:restore|save-profile)$/, 3, 'session'],
  ['GET', /^\/api\/v1\/feed$/, 7, 'public'],
  ['GET', /^\/api\/v1\/videos\/search$/, 8, 'public'],
  ['POST', /^\/api\/v1\/videos\/interact$/, 1, 'session'],
  ['POST', /^\/api\/v1\/videos\/(?:publish|delete)$/, 4, 'session'],
  ['POST', /^\/api\/v1\/comments\/(?:post|share)$/, 1, 'session'],
  ['GET', /^\/api\/v1\/comments$/, 1, 'public'],
  ['*', /^\/api\/v1\/media\/(?:limits|start|status\/[^/]+|chunk\/[^/]+|finish\/[^/]+)$/, 9, 'session'],
  ['GET', /^\/api\/v1\/ads\/next$/, 2, 'public'],
  ['POST', /^\/api\/v1\/ads\/track$/, 2, 'public'],
  ['POST', /^\/api\/v1\/ads\/admin$/, 2, 'admin'],
  ['GET', /^\/admin$/, 2, 'admin'],
  ['GET', /^\/api\/v1\/channels\/[^/]+(?:\/videos)?$/, 6, 'public'],
  ['GET', /^\/api\/v1\/premieres$/, 10, 'public'],
  ['GET', /^\/api\/v1\/(?:vaults\/audit|vaults\/\d+|mesh\/status)$/, LEDGER_VAULT, 'public'],
  ['POST', /^\/api\/v1\/vaults\/checkpoint$/, LEDGER_VAULT, 'admin'],
  ['GET', /^\/media\/[A-Za-z0-9._-]+$/, 9, 'public']
];

/** Returns { vault, authClass } or null when no vault serves the path (404 later). */
function routeFor(method, pathname) {
  for (const [m, re, vault, authClass] of ROUTES) {
    if ((m === '*' || m === method || (method === 'HEAD' && m === 'GET')) && re.test(pathname)) {
      return { vault, authClass };
    }
  }
  return null;
}

module.exports = {
  VAULTS,
  VAULT_COUNT,
  SHARD_FIRST,
  SHARD_LAST,
  SHARD_COUNT,
  LEDGER_VAULT,
  vaultByNo,
  vaultCode,
  shardVaultFor,
  routeFor
};
