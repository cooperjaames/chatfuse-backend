import crypto from 'crypto';
import bcrypt from 'bcrypt';
import { db } from './db.js';

const insertUser = db.prepare(
  'INSERT INTO users (id, email, password_hash) VALUES (?, ?, ?)'
);
const findByEmail = db.prepare('SELECT * FROM users WHERE email = ?');
const findById = db.prepare('SELECT * FROM users WHERE id = ?');
const setStripeCustomer = db.prepare(
  'UPDATE users SET stripe_customer_id = ? WHERE id = ?'
);
const setSubStatus = db.prepare(
  'UPDATE users SET subscription_status = ? WHERE stripe_customer_id = ?'
);

export async function createUser(email, password) {
  const existing = findByEmail.get(email);
  if (existing) throw new Error('An account with this email already exists');
  const id = crypto.randomBytes(12).toString('hex');
  const password_hash = await bcrypt.hash(password, 10);
  insertUser.run(id, email, password_hash);
  return { id, email, subscription_status: 'free' };
}

export async function verifyUser(email, password) {
  const user = findByEmail.get(email);
  if (!user) return null;
  const ok = await bcrypt.compare(password, user.password_hash);
  return ok ? user : null;
}

export function getUserById(id) {
  return findById.get(id);
}

export function linkStripeCustomer(userId, stripeCustomerId) {
  setStripeCustomer.run(stripeCustomerId, userId);
}

export function updateSubscriptionByStripeCustomer(stripeCustomerId, status) {
  setSubStatus.run(status, stripeCustomerId);
}

export function publicUser(user) {
  return {
    id: user.id,
    email: user.email,
    subscription_status: user.subscription_status
  };
}

const upsertConnection = db.prepare(`
  INSERT INTO connections (user_id, platform, access_token, refresh_token, expires_at, platform_user_id, platform_login, updated_at)
  VALUES (?, ?, ?, ?, ?, ?, ?, unixepoch())
  ON CONFLICT(user_id, platform) DO UPDATE SET
    access_token=excluded.access_token, refresh_token=excluded.refresh_token, expires_at=excluded.expires_at,
    platform_user_id=excluded.platform_user_id, platform_login=excluded.platform_login,
    updated_at=unixepoch()
`);
const getConnections = db.prepare('SELECT * FROM connections WHERE user_id = ?');

export function linkPlatformConnection(userId, platform, { accessToken, refreshToken, expiresAt, platformUserId, platformLogin }) {
  upsertConnection.run(userId, platform, accessToken, refreshToken || null, expiresAt || null, platformUserId || null, platformLogin || null);
}

const updateTokensStmt = db.prepare(`
  UPDATE connections SET access_token = ?, refresh_token = ?, expires_at = ?, updated_at = unixepoch()
  WHERE user_id = ? AND platform = ?
`);

// Used when refreshing an expiring access token — keeps platform_user_id/login untouched.
export function updateConnectionTokens(userId, platform, { accessToken, refreshToken, expiresAt }) {
  updateTokensStmt.run(accessToken, refreshToken || null, expiresAt || null, userId, platform);
}

export function getConnectionsForUser(userId) {
  const rows = getConnections.all(userId);
  const out = {};
  for (const r of rows) out[r.platform] = r;
  return out;
}

const deleteConnectionStmt = db.prepare('DELETE FROM connections WHERE user_id = ? AND platform = ?');
export function deletePlatformConnection(userId, platform) {
  deleteConnectionStmt.run(userId, platform);
}
