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
