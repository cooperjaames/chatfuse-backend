// Persistent SQLite storage. Replaces the old in-memory Map so sessions
// survive server restarts/redeploys.
//
// IMPORTANT (Railway-specific): Railway's filesystem is wiped on every
// redeploy unless you attach a Volume. Add a Volume to this service in the
// Railway dashboard, mount it at e.g. /data, and set the env var:
//   DB_PATH=/data/chatfuse.db
// Without that, this "persistent" database resets every time you deploy —
// same problem as before, just hidden.

import Database from 'better-sqlite3';
import fs from 'fs';
import path from 'path';

const DB_PATH = process.env.DB_PATH || './data/chatfuse.db';
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });

export const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    data TEXT NOT NULL DEFAULT '{}',
    user_id TEXT,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    stripe_customer_id TEXT,
    subscription_status TEXT NOT NULL DEFAULT 'free',
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS connections (
    user_id TEXT NOT NULL,
    platform TEXT NOT NULL,
    access_token TEXT,
    refresh_token TEXT,
    platform_user_id TEXT,
    platform_login TEXT,
    updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
    PRIMARY KEY (user_id, platform)
  );
`);
