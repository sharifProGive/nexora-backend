'use strict';
/* © 2026 Zentora CLC. All rights reserved. Platform Core engineered by Zentora. */
/**
 * Vault 35, sub-vault "friend-chat": storage for private messages between friends.
 *
 * One append-only event log (chat_events) serves every device of every account:
 *   kind 'message'  sender_id -> recipient_id, body, client_id (the sender's own id, makes a retry harmless)
 *   kind 'read'     sender_id (the reader) -> recipient_id (the author); ref_seq = newest message the reader has seen
 * A device remembers the highest seq it has processed and asks for everything after it, so a new phone restores the
 * whole history with the same call that delivers a new message. Only the newest read event per direction is kept.
 *
 * Later sub-vaults (file sending, calling) add new event kinds to this same log. 'kind' has no CHECK constraint for
 * that reason; the kinds are validated here.
 */

const MAX_BODY_CHARS = 4000;
const CLIENT_ID_RE = /^[A-Za-z0-9_-]{8,64}$/;

const SCHEMA_V4 = `
CREATE TABLE chat_events (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  kind TEXT NOT NULL,
  pair_key TEXT NOT NULL,
  sender_id TEXT NOT NULL,
  recipient_id TEXT NOT NULL,
  client_id TEXT NOT NULL DEFAULT '',
  body TEXT NOT NULL DEFAULT '',
  ref_seq INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);
CREATE INDEX idx_chat_recipient ON chat_events(recipient_id, seq);
CREATE INDEX idx_chat_sender ON chat_events(sender_id, seq);
CREATE UNIQUE INDEX idx_chat_client ON chat_events(sender_id, client_id) WHERE kind = 'message';
CREATE INDEX idx_chat_pair_messages ON chat_events(recipient_id, sender_id, seq) WHERE kind = 'message';
CREATE INDEX idx_chat_pair_reads ON chat_events(sender_id, recipient_id, seq) WHERE kind = 'read';
`;

function createChatStore({ stmt, transaction, pairKey }) {
  /** The event as the account [me] sees it. */
  function toEvent(r, me) {
    const fromMe = r.sender_id === me;
    const base = {
      seq: r.seq,
      kind: r.kind,
      peerId: fromMe ? r.recipient_id : r.sender_id,
      fromMe,
      createdAt: r.created_at
    };
    if (r.kind === 'read') return { ...base, upTo: r.ref_seq };
    return { ...base, clientId: r.client_id, body: r.body };
  }

  function areFriends(a, b) {
    return !!stmt("SELECT 1 AS x FROM friend_links WHERE pair_key = ? AND status = 'accepted'").get(pairKey(a, b));
  }

  /**
   * Stores one message. [clientId] is chosen by the sending device: sending the same message again (a retry after a
   * lost response) returns the stored one instead of a second copy.
   * Returns { result: 'sent' | 'duplicate' | 'self' | 'not_friends' | 'invalid', event? }
   */
  function sendChat(senderId, recipientId, clientId, body) {
    if (senderId === recipientId) return { result: 'self' };
    if (typeof clientId !== 'string' || !CLIENT_ID_RE.test(clientId)) return { result: 'invalid' };
    if (typeof body !== 'string') return { result: 'invalid' };
    const text = body.trim();
    if (text.length === 0 || text.length > MAX_BODY_CHARS) return { result: 'invalid' };
    return transaction(() => {
      const existing = stmt("SELECT * FROM chat_events WHERE kind = 'message' AND sender_id = ? AND client_id = ?").get(senderId, clientId);
      if (existing) return { result: 'duplicate', event: toEvent(existing, senderId) };
      if (!areFriends(senderId, recipientId)) return { result: 'not_friends' };
      const now = Date.now();
      const info = stmt(
        `INSERT INTO chat_events (kind, pair_key, sender_id, recipient_id, client_id, body, created_at)
         VALUES ('message', ?, ?, ?, ?, ?, ?)`
      ).run(pairKey(senderId, recipientId), senderId, recipientId, clientId, text, now);
      const row = stmt('SELECT * FROM chat_events WHERE seq = ?').get(Number(info.lastInsertRowid));
      return { result: 'sent', event: toEvent(row, senderId) };
    });
  }

  /**
   * Records that [readerId] has read everything [peerId] sent up to [upToSeq]. The value is clamped to a message that
   * really exists, so a receipt cannot be forged. Returns { upTo, changed } or null when there is nothing to mark.
   */
  function markChatRead(readerId, peerId, upToSeq) {
    return transaction(() => {
      const top = stmt(
        "SELECT MAX(seq) AS s FROM chat_events WHERE kind = 'message' AND recipient_id = ? AND sender_id = ? AND seq <= ?"
      ).get(readerId, peerId, upToSeq).s;
      if (!top) return null;
      const prev = stmt(
        "SELECT MAX(ref_seq) AS r FROM chat_events WHERE kind = 'read' AND sender_id = ? AND recipient_id = ?"
      ).get(readerId, peerId).r;
      if (prev && prev >= top) return { upTo: prev, changed: false };
      stmt("DELETE FROM chat_events WHERE kind = 'read' AND sender_id = ? AND recipient_id = ?").run(readerId, peerId);
      stmt(
        `INSERT INTO chat_events (kind, pair_key, sender_id, recipient_id, ref_seq, created_at)
         VALUES ('read', ?, ?, ?, ?, ?)`
      ).run(pairKey(readerId, peerId), readerId, peerId, top, Date.now());
      return { upTo: top, changed: true };
    });
  }

  /**
   * Up to [limit] events after [after] that involve [userId] (sent or received), oldest first, and the people they
   * refer to. Two index range scans merged by seq: the cost depends on the page size, not on the size of the log.
   */
  function chatSync(userId, after, limit) {
    const received = stmt('SELECT * FROM chat_events WHERE recipient_id = ? AND seq > ? ORDER BY seq ASC LIMIT ?').all(userId, after, limit);
    const sent = stmt('SELECT * FROM chat_events WHERE sender_id = ? AND seq > ? ORDER BY seq ASC LIMIT ?').all(userId, after, limit);
    const rows = received.concat(sent).sort((a, b) => a.seq - b.seq).slice(0, limit);
    const events = rows.map((r) => toEvent(r, userId));
    const peerIds = Array.from(new Set(events.map((e) => e.peerId)));
    const people = peerIds.length === 0
      ? []
      : stmt(
        `SELECT nexora_id, username, handle, avatar_uri FROM users
         WHERE nexora_id IN (SELECT value FROM json_each(?))`
      ).all(JSON.stringify(peerIds)).map((u) => ({
        nexoraId: u.nexora_id, username: u.username, handle: u.handle, avatarUri: u.avatar_uri
      }));
    return { events, people, more: rows.length === limit };
  }

  /** Newest event number in the whole log (a constant-time read). */
  function chatHead() {
    return stmt('SELECT COALESCE(MAX(seq), 0) AS s FROM chat_events').get().s;
  }

  return { sendChat, markChatRead, chatSync, chatHead };
}

module.exports = { createChatStore, SCHEMA_V4, MAX_BODY_CHARS };
