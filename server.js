import express from 'express';
import fetch from 'node-fetch';
import cors from 'cors';
import Stripe from 'stripe';
import crypto from 'crypto';
import 'dotenv/config';
import { createSession, getSession, updateSession, createAuthToken, getUserIdForToken, deleteAuthToken } from './lib/tokenStore.js';
import { createUser, verifyUser, getUserById, publicUser, linkStripeCustomer, updateSubscriptionByStripeCustomer, linkPlatformConnection, getConnectionsForUser } from './lib/users.js';

const app = express();
app.use(cors());

const {
  TWITCH_CLIENT_ID, TWITCH_CLIENT_SECRET, TWITCH_REDIRECT_URI,
  GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REDIRECT_URI,
  KICK_CLIENT_ID, KICK_CLIENT_SECRET, KICK_REDIRECT_URI,
  YOUTUBE_API_KEY, APP_SCHEME, PORT,
  STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET, STRIPE_PRICE_ID, DASHBOARD_URL
} = process.env;

const stripe = STRIPE_SECRET_KEY ? new Stripe(STRIPE_SECRET_KEY, { apiVersion: '2025-03-31.basil' }) : null;

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

// Starts an OAuth session tagged with the logged-in dashboard user, so when
// the existing Twitch/YouTube callback routes finish, they know to also save
// the resulting tokens against this account (not just an anonymous session).
app.post('/dashboard/connect-session', requireAuth, (req, res) => {
  const session = createSession();
  updateSession(session, { dashboardUserId: req.user.id });
  res.json({ session });
});

app.get('/dashboard/data', requireAuth, async (req, res) => {
  const conns = getConnectionsForUser(req.user.id);
  const out = { twitch: { connected: false }, youtube: { connected: false }, kick: { connected: false } };

  if (conns.twitch) {
    out.twitch.connected = true;
    out.twitch.login = conns.twitch.platform_login;
    try {
      const r = await fetch(`https://api.twitch.tv/helix/streams?user_id=${conns.twitch.platform_user_id}`, {
        headers: { 'Client-ID': TWITCH_CLIENT_ID, 'Authorization': `Bearer ${conns.twitch.access_token}` }
      });
      const d = await r.json();
      const stream = d.data && d.data[0];
      out.twitch.live = !!stream;
      out.twitch.viewers = stream ? stream.viewer_count : 0;
      out.twitch.title = stream ? stream.title : null;
      out.twitch.game = stream ? stream.game_name : null;
      out.twitch.startedAt = stream ? stream.started_at : null;
    } catch (e) { out.twitch.error = 'Could not reach Twitch'; }
  }

  if (conns.youtube) {
    out.youtube.connected = true;
    try {
      const br = await fetch('https://www.googleapis.com/youtube/v3/liveBroadcasts?part=snippet&broadcastStatus=active&broadcastType=all', {
        headers: { 'Authorization': `Bearer ${conns.youtube.access_token}` }
      });
      const bd = await br.json();
      const broadcast = bd.items && bd.items[0];
      out.youtube.live = !!broadcast;
      if (broadcast) {
        out.youtube.title = broadcast.snippet.title;
        const vr = await fetch(`https://www.googleapis.com/youtube/v3/videos?part=liveStreamingDetails&id=${broadcast.id}&key=${YOUTUBE_API_KEY}`);
        const vd = await vr.json();
        const details = vd.items && vd.items[0] && vd.items[0].liveStreamingDetails;
        out.youtube.viewers = details ? parseInt(details.concurrentViewers || '0', 10) : 0;
        out.youtube.startedAt = details ? details.actualStartTime : null;
      } else {
        out.youtube.viewers = 0;
      }
    } catch (e) { out.youtube.error = 'Could not reach YouTube'; }
  }

  if (conns.kick) {
    out.kick.connected = true;
    out.kick.login = conns.kick.platform_login;
    try {
      const r = await fetch(`https://api.kick.com/public/v1/livestreams?broadcaster_user_id=${conns.kick.platform_user_id}`, {
        headers: { 'Authorization': `Bearer ${conns.kick.access_token}` }
      });
      const d = await r.json();
      const stream = d.data && d.data[0];
      out.kick.live = !!stream;
      out.kick.viewers = stream ? stream.viewer_count : 0;
      out.kick.title = stream ? stream.stream_title : null;
      out.kick.game = stream && stream.category ? stream.category.name : null;
      out.kick.startedAt = stream ? stream.started_at : null;
    } catch (e) { out.kick.error = 'Could not reach Kick'; }
  }

  out.totalViewers = (out.twitch.viewers || 0) + (out.youtube.viewers || 0) + (out.kick.viewers || 0);
  res.json(out);
});

app.post('/dashboard/stream-info', requireAuth, async (req, res) => {
  const conns = getConnectionsForUser(req.user.id);
  const { twitch, youtube, kick } = req.body || {};
  const results = {};

  if (twitch && conns.twitch) {
    try {
      const patch = {};
      if (twitch.title) patch.title = twitch.title;
      if (twitch.category) {
        const gr = await fetch(`https://api.twitch.tv/helix/games?name=${encodeURIComponent(twitch.category)}`, {
          headers: { 'Client-ID': TWITCH_CLIENT_ID, 'Authorization': `Bearer ${conns.twitch.access_token}` }
        });
        const gd = await gr.json();
        const game = gd.data && gd.data[0];
        if (!game) { results.twitch = 'category not found'; }
        else patch.game_id = game.id;
      }
      if (results.twitch !== 'category not found') {
        const r = await fetch(`https://api.twitch.tv/helix/channels?broadcaster_id=${conns.twitch.platform_user_id}`, {
          method: 'PATCH',
          headers: { 'Client-ID': TWITCH_CLIENT_ID, 'Authorization': `Bearer ${conns.twitch.access_token}`, 'Content-Type': 'application/json' },
          body: JSON.stringify(patch)
        });
        results.twitch = r.ok ? 'updated' : await r.text();
      }
    } catch (e) { results.twitch = 'error: ' + e.message; }
  }

  if (youtube && conns.youtube && youtube.title) {
    try {
      const br = await fetch('https://www.googleapis.com/youtube/v3/liveBroadcasts?part=snippet&broadcastStatus=active&broadcastType=all', {
        headers: { 'Authorization': `Bearer ${conns.youtube.access_token}` }
      });
      const bd = await br.json();
      const broadcast = bd.items && bd.items[0];
      if (!broadcast) { results.youtube = 'not live'; }
      else {
        const snippet = { ...broadcast.snippet, title: youtube.title };
        const r = await fetch(`https://www.googleapis.com/youtube/v3/liveBroadcasts?part=snippet`, {
          method: 'PUT',
          headers: { 'Authorization': `Bearer ${conns.youtube.access_token}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ id: broadcast.id, snippet })
        });
        results.youtube = r.ok ? 'updated' : await r.text();
      }
    } catch (e) { results.youtube = 'error: ' + e.message; }
  }

  if (kick && conns.kick) {
    try {
      const patch = {};
      if (kick.title) patch.stream_title = kick.title;
      if (kick.category) {
        const cr = await fetch(`https://api.kick.com/public/v1/categories?search=${encodeURIComponent(kick.category)}`, {
          headers: { 'Authorization': `Bearer ${conns.kick.access_token}` }
        });
        const cd = await cr.json();
        const category = cd.data && cd.data[0];
        if (!category) { results.kick = 'category not found'; }
        else patch.category_id = category.id;
      }
      if (results.kick !== 'category not found') {
        const r = await fetch('https://api.kick.com/public/v1/channels', {
          method: 'PATCH',
          headers: { 'Authorization': `Bearer ${conns.kick.access_token}`, 'Content-Type': 'application/json' },
          body: JSON.stringify(patch)
        });
        results.kick = r.ok ? 'updated' : await r.text();
      }
    } catch (e) { results.kick = 'error: ' + e.message; }
  }

  res.json({ results });
});

app.get('/dashboard/youtube-chat', requireAuth, async (req, res) => {
  const conns = getConnectionsForUser(req.user.id);
  if (!conns.youtube) return res.status(400).json({ error: 'YouTube not connected' });
  try {
    const br = await fetch('https://www.googleapis.com/youtube/v3/liveBroadcasts?part=snippet&broadcastStatus=active&broadcastType=all', {
      headers: { 'Authorization': `Bearer ${conns.youtube.access_token}` }
    });
    const bd = await br.json();
    const broadcast = bd.items && bd.items[0];
    if (!broadcast) return res.json({ items: [], liveChatId: null });
    const liveChatId = broadcast.snippet.liveChatId;
    const { pageToken } = req.query;
    const r = await fetch(`https://www.googleapis.com/youtube/v3/liveChat/messages?liveChatId=${liveChatId}&part=snippet,authorDetails${pageToken ? '&pageToken=' + pageToken : ''}`, {
      headers: { 'Authorization': `Bearer ${conns.youtube.access_token}` }
    });
    const d = await r.json();
    res.json({ ...d, liveChatId });
  } catch (e) {
    res.status(500).json({ error: 'YouTube chat fetch failed' });
  }
});

app.post('/dashboard/send', requireAuth, async (req, res) => {
  const { message, platform } = req.body || {};
  if (!message || !message.trim()) return res.status(400).json({ error: 'Message is empty' });
  const conns = getConnectionsForUser(req.user.id);
  const targets = platform === 'all' ? ['twitch', 'youtube', 'kick'] : [platform];
  const results = {};

  for (const p of targets) {
    if (!conns[p]) { results[p] = 'not connected'; continue; }

    if (p === 'twitch') {
      try {
        const r = await fetch('https://api.twitch.tv/helix/chat/messages', {
          method: 'POST',
          headers: { 'Client-ID': TWITCH_CLIENT_ID, 'Authorization': `Bearer ${conns.twitch.access_token}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ broadcaster_id: conns.twitch.platform_user_id, sender_id: conns.twitch.platform_user_id, message })
        });
        results.twitch = r.ok ? 'sent' : await r.text();
      } catch (e) { results.twitch = 'error: ' + e.message; }
    }

    if (p === 'youtube') {
      try {
        const br = await fetch('https://www.googleapis.com/youtube/v3/liveBroadcasts?part=snippet&broadcastStatus=active&broadcastType=all', {
          headers: { 'Authorization': `Bearer ${conns.youtube.access_token}` }
        });
        const bd = await br.json();
        const broadcast = bd.items && bd.items[0];
        if (!broadcast) { results.youtube = 'not live'; continue; }
        const vr = await fetch(`https://www.googleapis.com/youtube/v3/videos?part=liveStreamingDetails&id=${broadcast.id}&key=${YOUTUBE_API_KEY}`);
        const vd = await vr.json();
        const liveChatId = vd.items && vd.items[0] && vd.items[0].liveStreamingDetails && vd.items[0].liveStreamingDetails.activeLiveChatId;
        if (!liveChatId) { results.youtube = 'no active chat'; continue; }
        const r = await fetch('https://www.googleapis.com/youtube/v3/liveChat/messages?part=snippet', {
          method: 'POST',
          headers: { 'Authorization': `Bearer ${conns.youtube.access_token}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ snippet: { liveChatId, type: 'textMessageEvent', textMessageDetails: { messageText: message } } })
        });
        results.youtube = r.ok ? 'sent' : await r.text();
      } catch (e) { results.youtube = 'error: ' + e.message; }
    }

    if (p === 'kick') {
      try {
        const r = await fetch('https://api.kick.com/public/v1/chat', {
          method: 'POST',
          headers: { 'Authorization': `Bearer ${conns.kick.access_token}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ broadcaster_user_id: Number(conns.kick.platform_user_id), content: message, type: 'user' })
        });
        results.kick = r.ok ? 'sent' : await r.text();
      } catch (e) { results.kick = 'error: ' + e.message; }
    }
  }

  res.json({ results });
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
      success_url: `${DASHBOARD_URL}/?checkout=success`,
      cancel_url: `${DASHBOARD_URL}/?checkout=cancelled`
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
      return_url: `${DASHBOARD_URL}/`
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
    scope: 'user:write:chat user:read:chat channel:manage:broadcast',
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
    const s = getSession(session);
    if (s.dashboardUserId && user) {
      linkPlatformConnection(s.dashboardUserId, 'twitch', {
        accessToken: tokenData.access_token,
        refreshToken: tokenData.refresh_token,
        platformUserId: user.id,
        platformLogin: user.login
      });
    }
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
    const s = getSession(session);
    if (s.dashboardUserId) {
      linkPlatformConnection(s.dashboardUserId, 'youtube', {
        accessToken: tokenData.access_token,
        refreshToken: tokenData.refresh_token,
        platformUserId: channelId || null,
        platformLogin: null
      });
    }
    res.redirect(`${updateSession(session, {}).mobileRedirect}?platform=youtube&status=success`);
  } catch (e) {
    console.error('YouTube OAuth failed', e);
    const s = getSession(session);
    res.redirect(`${s && s.mobileRedirect}?platform=youtube&status=error`);
  }
});

// ---------- Kick OAuth (requires PKCE) ----------
function base64url(buf){ return buf.toString('base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,''); }

app.get('/auth/kick/login', (req, res) => {
  const session = req.query.session;
  const mobileRedirect = req.query.redirect_uri;
  if (!session || !getSession(session)) return res.status(400).send('Invalid session');

  const codeVerifier = base64url(crypto.randomBytes(64));
  const codeChallenge = base64url(crypto.createHash('sha256').update(codeVerifier).digest());
  updateSession(session, { mobileRedirect, kickCodeVerifier: codeVerifier });

  const params = new URLSearchParams({
    response_type: 'code',
    client_id: KICK_CLIENT_ID,
    redirect_uri: KICK_REDIRECT_URI,
    scope: 'user:read channel:read chat:write',
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
    state: session
  });
  res.redirect(`https://id.kick.com/oauth/authorize?${params}`);
});

app.get('/auth/kick/callback', async (req, res) => {
  const { code, state: session } = req.query;
  if (!session || !getSession(session)) return res.status(400).send('Invalid session');
  try {
    const s = getSession(session);
    const tokenRes = await fetch('https://id.kick.com/oauth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: KICK_CLIENT_ID,
        client_secret: KICK_CLIENT_SECRET,
        redirect_uri: KICK_REDIRECT_URI,
        code_verifier: s.kickCodeVerifier,
        code
      })
    });
    const tokenData = await tokenRes.json();
    if (!tokenData.access_token) throw new Error(JSON.stringify(tokenData));

    const userRes = await fetch('https://api.kick.com/public/v1/users', {
      headers: { 'Authorization': `Bearer ${tokenData.access_token}` }
    });
    const userData = await userRes.json();
    const user = userData.data && userData.data[0];

    if (s.dashboardUserId && user) {
      linkPlatformConnection(s.dashboardUserId, 'kick', {
        accessToken: tokenData.access_token,
        refreshToken: tokenData.refresh_token,
        platformUserId: user.user_id || user.id,
        platformLogin: user.name || user.username
      });
    }
    res.redirect(`${updateSession(session, {}).mobileRedirect}?platform=kick&status=success`);
  } catch (e) {
    console.error('Kick OAuth failed', e);
    const s = getSession(session);
    res.redirect(`${s && s.mobileRedirect}?platform=kick&status=error`);
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
