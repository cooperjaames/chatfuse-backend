import fetch from 'node-fetch';

// Each platform's OAuth refresh_token grant. All three return a fresh
// access_token + expires_in; Twitch and Kick also rotate the refresh_token
// itself, Google normally does not (caller should keep the old one).

async function postForm(url, body) {
  const r = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(body)
  });
  const data = await r.json();
  if (!data.access_token) throw new Error(`${url} refresh failed: ${JSON.stringify(data)}`);
  return data;
}

export async function refreshTwitch({ refreshToken, clientId, clientSecret }) {
  const data = await postForm('https://id.twitch.tv/oauth2/token', {
    grant_type: 'refresh_token',
    refresh_token: refreshToken,
    client_id: clientId,
    client_secret: clientSecret
  });
  return { accessToken: data.access_token, refreshToken: data.refresh_token, expiresIn: data.expires_in };
}

export async function refreshGoogle({ refreshToken, clientId, clientSecret }) {
  const data = await postForm('https://oauth2.googleapis.com/token', {
    grant_type: 'refresh_token',
    refresh_token: refreshToken,
    client_id: clientId,
    client_secret: clientSecret
  });
  return { accessToken: data.access_token, refreshToken: data.refresh_token, expiresIn: data.expires_in };
}

export async function refreshKick({ refreshToken, clientId, clientSecret }) {
  const data = await postForm('https://id.kick.com/oauth/token', {
    grant_type: 'refresh_token',
    refresh_token: refreshToken,
    client_id: clientId,
    client_secret: clientSecret
  });
  return { accessToken: data.access_token, refreshToken: data.refresh_token, expiresIn: data.expires_in };
}
