import express from 'express';
import fetch from 'node-fetch';
import cors from 'cors';
import Stripe from 'stripe';
import 'dotenv/config';
import { createSession, getSession, updateSession, createAuthToken, getUserIdForToken, deleteAuthToken } from './lib/tokenStore.js';
import { createUser, verifyUser, getUserById, publicUser, linkStripeCustomer, updateSubscriptionByStripeCustomer } from './lib/users.js';

const app = express();
app.use(cors());

const {
  TWITCH_CLIENT_ID, TWITCH_CLIENT_SECRET, TWITCH_REDIRECT_URI,
  GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REDIRECT_URI,
  YOUTUBE_API_KEY, APP_SCHEME, PORT,
  STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET, STRIPE_PRICE_ID, DASHBOARD_URL
} = process.env;

const stripe = STRIPE_SECRET_KEY ? new Stripe(STRIPE_SECRET_KEY) : null;

// Stripe webhook MUST come before express.json() below — Stripe verifies
// the request signature against the raw, unparsed body. If express.json()
// runs first, the body is already consumed/parsed and signature checks fail.
app.post('/billing/webhook', express.raw({ type: 'application/json' }), (req, res) => {
  if (!stripe) return res.status(500).send('Stripe not configured');
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], STRIPE_WEBHOOK_SECRET);
  } catch (e) {
    console.error('Stripe webhook signature check failed', e.message);
    return res.status(400).send(`Webhook Error: ${e.message}`);
  }

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    if (session.client_reference_id && session.customer) {
      linkStripeCustomer(session.client_reference_id, session.customer);
      updateSubscriptionByStripeCustomer(session.customer, 'active');
    }
  }
  if (event.type === 'customer.subscription.updated' || event.type === 'customer.subscription.deleted') {
    const sub = event.data.object;
    const status = sub.status === 'active' || sub.status === 'trialing' ? 'active' : 'free';
    updateSubscriptionByStripeCustomer(sub.customer, status);
  }

  res.json({ received: true });
});

app.use(express.json());

// ---------- Session bootstrap ----------
// The app calls this once on first launch and stores the session id locally.
app.post('/session/new', (req, res) => {
  res.json({ session: createSession() });
});

app.get('/session/:id', (req, res) => {
  const s = getSession(req.params.id);
  if (!s) return res.status(404).json({ error: 'not found' });
  res.json({
    twitchConnected: !!s.twitchToken,
    twitchLogin: s.twitchLogin || null,
    twitchUserId: s.twitchUserId || null,
    youtubeConnected: !!s.googleToken,
    youtubeChannelId: s.youtubeChannelId || null
  });
});

// ---------- ChatFuse accounts (for the paid dashboard) ----------
function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  const userId = token && getUserIdForToken(token);
  if (!userId) return res.status(401).json({ error: 'Not logged in' });
  const user = getUserById(userId);
  if (!user) return res.status(401).json({ error: 'Not logged in' });
  req.user = user;
  next();
}

app.post('/auth/signup', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Email and password are required' });
  if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });
  try {
    const user = await createUser(email.toLowerCase().trim(), password);
    const token = createAuthToken(user.id);
    res.json({ token, user: publicUser(user) });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Email and password are required' });
  const user = await verifyUser(email.toLowerCase().trim(), password);
  if (!user) return res.status(401).json({ error: 'Incorrect email or password' });
  const token = createAuthToken(user.id);
  res.json({ token, user: publicUser(user) });
});

app.post('/auth/logout', requireAuth, (req, res) => {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.slice(7);
  deleteAuthToken(token);
  res.json({ ok: true });
});

app.get('/auth/me', requireAuth, (req, res) => {
  res.json({ user: publicUser(req.user) });
});

// ---------- Stripe billing ----------
app.post('/billing/checkout', requireAuth, async (req, res) => {
  if (!stripe) return res.status(500).json({ error: 'Billing is not configured yet' });
  try {
    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      line_items: [{ price: STRIPE_PRICE_ID, quantity: 1 }],
      customer_email: req.user.email,
      client_reference_id: req.user.id,
      success_url: `${DASHBOARD_URL}/dashboard?checkout=success`,
      cancel_url: `${DASHBOARD_URL}/upgrade?checkout=cancelled`
    });
    res.json({ url: session.url });
  } catch (e) {
    console.error('Stripe checkout creation failed', e);
    res.status(500).json({ error: 'Could not start checkout' });
  }
});

app.post('/billing/portal', requireAuth, async (req, res) => {
  if (!stripe) return res.status(500).json({ error: 'Billing is not configured yet' });
  if (!req.user.stripe_customer_id) return res.status(400).json({ error: 'No subscription on file' });
  try {
    const session = await stripe.billingPortal.sessions.create({
      customer: req.user.stripe_customer_id,
      return_url: `${DASHBOARD_URL}/dashboard`
    });
    res.json({ url: session.url });
  } catch (e) {
    console.error('Stripe portal creation failed', e);
    res.status(500).json({ error: 'Could not open billing portal' });
  }
});

// ---------- Twitch OAuth ----------
app.get('/auth/twitch/login', (req, res) => {
  const session = req.query.session;
  const mobileRedirect = req.query.redirect_uri;
  if (!session || !getSession(session)) return res.status(400).send('Invalid session');
  updateSession(session, { mobileRedirect });
  const params = new URLSearchParams({
    client_id: TWITCH_CLIENT_ID,
    redirect_uri: TWITCH_REDIRECT_URI,
    response_type: 'code',
    scope: 'user:write:chat user:read:chat',
    state: session
  });
  res.redirect(`https://id.twitch.tv/oauth2/authorize?${params}`);
});

app.get('/auth/twitch/callback', async (req, res) => {
  const { code, state: session } = req.query;
  if (!session || !getSession(session)) return res.status(400).send('Invalid session');
  try {
    const tokenRes = await fetch('https://id.twitch.tv/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: TWITCH_CLIENT_ID,
        client_secret: TWITCH_CLIENT_SECRET,
        code,
        grant_type: 'authorization_code',
        redirect_uri: TWITCH_REDIRECT_URI
      })
    });
    const tokenData = await tokenRes.json();
    if (!tokenData.access_token) throw new Error(JSON.stringify(tokenData));

    const userRes = await fetch('https://api.twitch.tv/helix/users', {
      headers: { 'Client-ID': TWITCH_CLIENT_ID, 'Authorization': `Bearer ${tokenData.access_token}` }
    });
    const userData = await userRes.json();
    const user = userData.data && userData.data[0];

    updateSession(session, {
      twitchToken: tokenData.access_token,
      twitchRefresh: tokenData.refresh_token,
      twitchUserId: user ? user.id : null,
      twitchLogin: user ? user.login : null
    });
    res.redirect(`${updateSession(session, {}).mobileRedirect}?platform=twitch&status=success`);
  } catch (e) {
    console.error('Twitch OAuth failed', e);
    const s = getSession(session);
    res.redirect(`${s && s.mobileRedirect}?platform=twitch&status=error`);
  }
});

// ---------- YouTube (Google) OAuth ----------
app.get('/auth/youtube/login', (req, res) => {
  const session = req.query.session;
  const mobileRedirect = req.query.redirect_uri;
  if (!session || !getSession(session)) return res.status(400).send('Invalid session');
  updateSession(session, { mobileRedirect });
  const params = new URLSearchParams({
    client_id: GOOGLE_CLIENT_ID,
    redirect_uri: GOOGLE_REDIRECT_URI,
    response_type: 'code',
    access_type: 'offline',
    prompt: 'consent',
    scope: 'https://www.googleapis.com/auth/youtube.force-ssl',
    state: session
  });
  res.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params}`);
});

app.get('/auth/youtube/callback', async (req, res) => {
  const { code, state: session } = req.query;
  if (!session || !getSession(session)) return res.status(400).send('Invalid session');
  try {
    const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: GOOGLE_CLIENT_ID,
        client_secret: GOOGLE_CLIENT_SECRET,
        code,
        grant_type: 'authorization_code',
        redirect_uri: GOOGLE_REDIRECT_URI
      })
    });
    const tokenData = await tokenRes.json();
    if (!tokenData.access_token) throw new Error(JSON.stringify(tokenData));

    const chRes = await fetch('https://www.googleapis.com/youtube/v3/channels?part=id&mine=true', {
      headers: { 'Authorization': `Bearer ${tokenData.access_token}` }
    });
    const chData = await chRes.json();
    const channelId = chData.items && chData.items[0] && chData.items[0].id;

    updateSession(session, {
      googleToken: tokenData.access_token,
      googleRefresh: tokenData.refresh_token,
      youtubeChannelId: channelId || null
    });
    res.redirect(`${updateSession(session, {}).mobileRedirect}?platform=youtube&status=success`);
  } catch (e) {
    console.error('YouTube OAuth failed', e);
    const s = getSession(session);
    res.redirect(`${s && s.mobileRedirect}?platform=youtube&status=error`);
  }
});

// ---------- Read-only YouTube chat proxy (no login needed to read, only API key) ----------
app.get('/youtube/messages', async (req, res) => {
  const { videoId, pageToken } = req.query;
  try {
    const vr = await fetch(`https://www.googleapis.com/youtube/v3/videos?part=liveStreamingDetails,snippet&id=${videoId}&key=${YOUTUBE_API_KEY}`);
    const vd = await vr.json();
    const item = vd.items && vd.items[0];
    const liveChatId = item && item.liveStreamingDetails && item.liveStreamingDetails.activeLiveChatId;
    if (!liveChatId) return res.json({ items: [], liveChatId: null });
    const r = await fetch(`https://www.googleapis.com/youtube/v3/liveChat/messages?liveChatId=${liveChatId}&part=snippet,authorDetails&key=${YOUTUBE_API_KEY}${pageToken ? '&pageToken=' + pageToken : ''}`);
    const d = await r.json();
    res.json({ ...d, liveChatId });
  } catch (e) {
    res.status(500).json({ error: 'youtube fetch failed' });
  }
});

// ---------- Unified send: one message out to Twitch + YouTube ----------
app.post('/send', async (req, res) => {
  const { session, message, youtubeLiveChatId } = req.body;
  const s = getSession(session);
  if (!s) return res.status(400).json({ error: 'invalid session' });

  const results = {};

  if (s.twitchToken && s.twitchUserId) {
    try {
      const r = await fetch('https://api.twitch.tv/helix/chat/messages', {
        method: 'POST',
        headers: {
          'Client-ID': TWITCH_CLIENT_ID,
          'Authorization': `Bearer ${s.twitchToken}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          broadcaster_id: s.twitchUserId,
          sender_id: s.twitchUserId,
          message
        })
      });
      results.twitch = r.ok ? 'sent' : await r.text();
    } catch (e) { results.twitch = 'error: ' + e.message; }
  }

  if (s.googleToken && youtubeLiveChatId) {
    try {
      const r = await fetch('https://www.googleapis.com/youtube/v3/liveChat/messages?part=snippet', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${s.googleToken}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          snippet: {
            liveChatId: youtubeLiveChatId,
            type: 'textMessageEvent',
            textMessageDetails: { messageText: message }
          }
        })
      });
      results.youtube = r.ok ? 'sent' : await r.text();
    } catch (e) { results.youtube = 'error: ' + e.message; }
  }

  res.json({ results });
});

app.get('/health', (req, res) => res.send('ok'));

app.listen(PORT || 3000, () => console.log(`ChatFuse backend running on port ${PORT || 3000}`));
