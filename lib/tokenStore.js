// In-memory store keyed by a random session id. Fine for personal/testing use.
// Before this goes public, swap this for a real database (Postgres/SQLite/etc)
// so sessions survive server restarts and multiple users don't collide.

import crypto from 'crypto';

const sessions = new Map();

export function createSession(){
  const id = crypto.randomBytes(16).toString('hex');
  sessions.set(id, {});
  return id;
}

export function getSession(id){
  return sessions.get(id) || null;
}

export function updateSession(id, patch){
  const existing = sessions.get(id) || {};
  sessions.set(id, {...existing, ...patch});
  return sessions.get(id);
}
