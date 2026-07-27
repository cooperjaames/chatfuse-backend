import crypto from 'crypto';
import { db } from './db.js';

const getStmt = db.prepare('SELECT data FROM sessions WHERE id = ?');
const insertStmt = db.prepare('INSERT INTO sessions (id, data) VALUES (?, ?)');
const updateStmt = db.prepare('UPDATE sessions SET data = ? WHERE id = ?');

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
