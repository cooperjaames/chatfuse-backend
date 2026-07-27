import crypto from 'crypto';
import { db } from './db.js';

const getStmt = db.prepare('SELECT data FROM sessions WHERE id = ?');
const insertStmt = db.prepare('INSERT INTO sessions (id, data) VALUES (?, ?)');
const updateStmt = db.prepare('UPDATE sessions SET data = ? WHERE id = ?');
const insertAuthStmt = db.prepare('INSERT INTO sessions (id, data, user_id) VALUES (?, ?, ?)');
const getUserIdStmt = db.prepare('SELECT user_id FROM sessions WHERE id = ?');
const deleteStmt = db.prepare('DELETE FROM sessions WHERE id = ?');

export function createSession(){
  const id = crypto.randomBytes(16).toString('hex');
  insertStmt.run(id, '{}');
  return id;
}

export function getSession(id){
  const row = getStmt.get(id);
  return row ? JSON.parse(row.data) : null;
}

export function updateSession(id, patch){
  const existing = getSession(id) || {};
  const merged = { ...existing, ...patch };
  updateStmt.run(JSON.stringify(merged), id);
  return merged;
}

// Auth tokens for logged-in dashboard users. Separate concept from the
// anonymous OAuth sessions above, but stored in the same table since the
// shape (random id -> row) is identical; the user_id column is what makes
// a row an "auth token" versus an anonymous OAuth session.
export function createAuthToken(userId){
  const id = crypto.randomBytes(24).toString('hex');
  insertAuthStmt.run(id, '{}', userId);
  return id;
}

export function getUserIdForToken(token){
  const row = getUserIdStmt.get(token);
  return row ? row.user_id : null;
}

export function deleteAuthToken(token){
  deleteStmt.run(token);
}
