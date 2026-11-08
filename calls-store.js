'use strict';
/* © 2026 Zentora CLC. All rights reserved. Platform Core engineered by Zentora. */
/**
 * Vault 35, sub-vault "friend-calls": voice and video calls between friends.
 *
 * The audio and video never touch this server: the two phones talk to each other with WebRTC. The server only carries
 * the small "signaling" messages the phones need to find each other (offer, answer, ICE candidates) and keeps the
 * state of the call (ringing, active, ended). A call lives in memory while it is running, because it is short-lived
 * and a server restart must end it anyway; every finished call is written to the table call_log.
 *
 * State machine: ringing -> active -> ended, or ringing -> ended. Ended is final.
 *   ringing  the caller started the call; the callee's phone is ringing (at most RING_MS)
 *   active   the callee answered
 *   ended    reason: ended (hung up) | declined | missed (nobody answered) | lost (a phone stopped answering) | failed
 *
 * One account is in at most one call at a time. Every change of a call raises its "rev"; a phone that polls with the
 * rev it has seen gets an answer only when something is newer, so nothing is lost between two polls.
 */

const RING_MS = 40 * 1000;
const LOST_AFTER_MS = 45 * 1000;
const KEEP_ENDED_MS = 2 * 60 * 1000;
const MAX_SESSIONS = 100000;
const MAX_SIGNALS_PER_CALL = 600;
const MAX_SIGNAL_CHARS = 8000;
const SIGNAL_TYPES = new Set(['offer', 'answer', 'candidate']);
const CLIENT_END_REASONS = new Set(['ended', 'failed']);

const SCHEMA_V5 = `
CREATE TABLE call_log (
  call_id TEXT PRIMARY KEY,
  caller_id TEXT NOT NULL,
  callee_id TEXT NOT NULL,
  video INTEGER NOT NULL,
  outcome TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  answered_at INTEGER NOT NULL DEFAULT 0,
  ended_at INTEGER NOT NULL
);
CREATE INDEX idx_calllog_caller ON call_log(caller_id, ended_at DESC);
CREATE INDEX idx_calllog_callee ON call_log(callee_id, ended_at DESC);
`;

/**
 * @param {{ stmt: Function, pairKey: Function, now?: () => number, newId?: () => string }} deps
 */
function createCallStore({ stmt, pairKey, now = Date.now, newId = () => require('node:crypto').randomBytes(12).toString('base64url') }) {
  /** @type {Map<string, any>} */
  const sessions = new Map();
  /** account -> id of the call it is in right now (ringing or active) */
  const current = new Map();

  function areFriends(a, b) {
    return !!stmt("SELECT 1 AS x FROM friend_links WHERE pair_key = ? AND status = 'accepted'").get(pairKey(a, b));
  }

  function sessionOf(userId, callId) {
    if (typeof callId !== 'string') return null;
    const s = sessions.get(callId);
    if (!s || (s.callerId !== userId && s.calleeId !== userId)) return null;
    return s;
  }

  function currentSession(userId) {
    const id = current.get(userId);
    return id ? sessions.get(id) || null : null;
  }

  function view(s, me) {
    const outgoing = s.callerId === me;
    return {
      id: s.id,
      peerId: outgoing ? s.calleeId : s.callerId,
      outgoing,
      video: s.video,
      state: s.state,
      endReason: s.endReason,
      createdAt: s.createdAt,
      answeredAt: s.answeredAt,
      rev: s.rev
    };
  }

  function finish(s, reason) {
    if (s.state === 'ended') return false;
    const t = now();
    const answered = s.answeredAt > 0;
    s.state = 'ended';
    s.endReason = reason;
    s.endedAt = t;
    s.rev += 1;
    if (current.get(s.callerId) === s.id) current.delete(s.callerId);
    if (current.get(s.calleeId) === s.id) current.delete(s.calleeId);
    let outcome;
    if (reason === 'declined') outcome = 'declined';
    else if (reason === 'missed') outcome = 'missed';
    else if (reason === 'lost') outcome = answered ? 'lost' : 'missed';
    else if (reason === 'failed') outcome = 'failed';
    else outcome = answered ? 'completed' : 'cancelled';
    stmt(
      `INSERT OR IGNORE INTO call_log (call_id, caller_id, callee_id, video, outcome, created_at, answered_at, ended_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(s.id, s.callerId, s.calleeId, s.video ? 1 : 0, outcome, s.createdAt, s.answeredAt, t);
    return true;
  }

  /**
   * Starts a call from [callerId] to the friend [calleeId].
   * Returns { result: 'started' | 'self' | 'not_friends' | 'busy' | 'peer_busy' | 'overloaded', call? }
   */
  function start(callerId, calleeId, video) {
    if (callerId === calleeId) return { result: 'self' };
    if (!areFriends(callerId, calleeId)) return { result: 'not_friends' };
    if (currentSession(callerId)) return { result: 'busy' };
    if (currentSession(calleeId)) return { result: 'peer_busy' };
    if (sessions.size >= MAX_SESSIONS) return { result: 'overloaded' };
    const t = now();
    const s = {
      id: newId(), callerId, calleeId, video: !!video, state: 'ringing',
      createdAt: t, answeredAt: 0, endedAt: 0, endReason: '', rev: 1,
      signals: [], seen: { [callerId]: t, [calleeId]: 0 }
    };
    sessions.set(s.id, s);
    current.set(callerId, s.id);
    current.set(calleeId, s.id);
    return { result: 'started', call: view(s, callerId) };
  }

  /** The callee picks up. Returns { result: 'ok' | 'not_found' | 'bad_state', call? } */
  function answer(userId, callId) {
    const s = sessionOf(userId, callId);
    if (!s || s.calleeId !== userId) return { result: 'not_found' };
    if (s.state === 'active') return { result: 'ok', call: view(s, userId) };
    if (s.state !== 'ringing') return { result: 'bad_state' };
    s.state = 'active';
    s.answeredAt = now();
    s.seen[userId] = s.answeredAt;
    s.rev += 1;
    return { result: 'ok', call: view(s, userId) };
  }

  /** The callee refuses. Repeating it is harmless. */
  function decline(userId, callId) {
    const s = sessionOf(userId, callId);
    if (!s || s.calleeId !== userId) return { result: 'not_found' };
    if (s.state === 'active') return { result: 'bad_state' };
    finish(s, 'declined');
    return { result: 'ok', call: view(s, userId) };
  }

  /** Either side hangs up (or cancels while ringing). Repeating it is harmless. */
  function end(userId, callId, reason) {
    const s = sessionOf(userId, callId);
    if (!s) return { result: 'not_found' };
    finish(s, CLIENT_END_REASONS.has(reason) ? reason : 'ended');
    return { result: 'ok', call: view(s, userId) };
  }

  /**
   * Stores one signaling message for the other phone. offer: caller only; answer: callee only, after answering;
   * candidate: both. Returns { result: 'ok' | 'not_found' | 'bad_state' | 'invalid' | 'too_many', peerId? }
   */
  function signal(userId, callId, type, data) {
    if (!SIGNAL_TYPES.has(type) || typeof data !== 'string' || data.length === 0 || data.length > MAX_SIGNAL_CHARS) {
      return { result: 'invalid' };
    }
    const s = sessionOf(userId, callId);
    if (!s) return { result: 'not_found' };
    if (s.state === 'ended') return { result: 'bad_state' };
    if (type === 'offer' && s.callerId !== userId) return { result: 'invalid' };
    if (type === 'answer' && (s.calleeId !== userId || s.state !== 'active')) return { result: 'bad_state' };
    if (s.signals.length >= MAX_SIGNALS_PER_CALL) return { result: 'too_many' };
    s.signals.push({ n: s.signals.length + 1, to: userId === s.callerId ? s.calleeId : s.callerId, type, data });
    s.seen[userId] = now();
    s.rev += 1;
    return { result: 'ok', peerId: userId === s.callerId ? s.calleeId : s.callerId };
  }

  /**
   * What the phone [userId] should be told. Without [callId] it asks "am I being called or in a call?"; with it, "has
   * this call changed since [rev]?" and also receives the signaling messages after [after].
   * Returns { status: 'none' | 'gone' | 'unchanged' | 'changed', call?, signals?, cursor? }
   */
  function check(userId, callId, rev, after) {
    if (!callId) {
      const s = currentSession(userId);
      if (!s) return { status: 'none' };
      s.seen[userId] = now();
      return { status: 'changed', call: view(s, userId), signals: [], cursor: 0 };
    }
    const s = sessionOf(userId, callId);
    if (!s) return { status: 'gone' };
    if (s.state !== 'ended') s.seen[userId] = now();
    if (s.rev <= rev) return { status: 'unchanged' };
    const signals = s.signals.filter((x) => x.to === userId && x.n > after).map((x) => ({ n: x.n, type: x.type, data: x.data }));
    return { status: 'changed', call: view(s, userId), signals, cursor: signals.length ? signals[signals.length - 1].n : after };
  }

  /**
   * Ends calls nobody answers and calls whose phones went silent, and forgets old ended calls.
   * Returns the calls that were ended now, so the caller can wake the two phones.
   */
  function sweep() {
    const t = now();
    const ended = [];
    for (const s of Array.from(sessions.values())) {
      if (s.state === 'ended') {
        if (t - s.endedAt > KEEP_ENDED_MS) sessions.delete(s.id);
        continue;
      }
      if (s.state === 'ringing' && t - s.createdAt > RING_MS) {
        if (finish(s, 'missed')) ended.push(s);
      } else if (t - s.seen[s.callerId] > LOST_AFTER_MS || (s.state === 'active' && t - s.seen[s.calleeId] > LOST_AFTER_MS)) {
        if (finish(s, 'lost')) ended.push(s);
      }
    }
    return ended;
  }

  function callCount() {
    return stmt('SELECT COUNT(*) AS n FROM call_log').get().n;
  }

  function liveCount() {
    return current.size / 2;
  }

  return { start, answer, decline, end, signal, check, sweep, callCount, liveCount };
}

module.exports = { createCallStore, SCHEMA_V5, RING_MS, LOST_AFTER_MS, MAX_SIGNAL_CHARS };
