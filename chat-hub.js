'use strict';
/* © 2026 Zentora CLC. All rights reserved. Platform Core engineered by Zentora. */
/**
 * Wake-up hub for the chat long poll (Vault 35, sub-vault "friend-chat").
 *
 * A device that has nothing new parks its request here for up to ~25 seconds. When a message arrives for that
 * account, notify() releases the parked requests so they answer at once. There is no third party involved: it is the
 * same HTTPS connection the app already uses.
 *
 * The hub lives in the memory of ONE server process. With several server instances a message would only wake the
 * devices parked on the instance that received it; the others would see it at their next poll (at most the wait time
 * later). Moving to several instances therefore needs a shared channel (for example Redis pub/sub) behind notify().
 */

/**
 * @param {{ maxPerUser?: number, maxTotal?: number }} [limits]
 */
function createChatHub({ maxPerUser = 3, maxTotal = 20000 } = {}) {
  /** @type {Map<string, Set<{ release: (reason: string) => void }>>} */
  const parked = new Map();
  let total = 0;

  function remove(userId, entry) {
    const set = parked.get(userId);
    if (!set || !set.delete(entry)) return false;
    total -= 1;
    if (set.size === 0) parked.delete(userId);
    return true;
  }

  /**
   * Parks the caller. Returns { promise, cancel }. The promise resolves with 'event' (notify), 'timeout',
   * 'replaced' (the account already had [maxPerUser] parked requests; the oldest is released) or 'full'
   * (the server is holding [maxTotal] requests already; answered immediately, nothing parked).
   */
  function park(userId, timeoutMs) {
    if (total >= maxTotal) {
      return { promise: Promise.resolve('full'), cancel: () => {} };
    }
    let entry;
    let timer;
    const promise = new Promise((resolve) => {
      entry = {
        release: (reason) => {
          clearTimeout(timer);
          if (remove(userId, entry)) resolve(reason);
        }
      };
      timer = setTimeout(() => entry.release('timeout'), timeoutMs);
      timer.unref();
      let set = parked.get(userId);
      if (!set) {
        set = new Set();
        parked.set(userId, set);
      }
      set.add(entry);
      total += 1;
      if (set.size > maxPerUser) {
        const oldest = set.values().next().value;
        oldest.release('replaced');
      }
    });
    return { promise, cancel: () => entry.release('cancelled') };
  }

  /** Releases every parked request of [userId]. */
  function notify(userId) {
    const set = parked.get(userId);
    if (!set) return;
    for (const entry of Array.from(set)) entry.release('event');
  }

  return { park, notify, size: () => total };
}

module.exports = { createChatHub };
