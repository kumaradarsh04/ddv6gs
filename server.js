// server.js
// A minimal Express server that:
//   1. Serves the front-end (public/index.html)
//   2. Receives the Google ID token from the browser after sign-in
//   3. Verifies that token with Google's servers
//   4. Creates a simple session cookie so the user stays "logged in"
//
// Run with:  npm install && npm start

require('dotenv').config();
const express = require('express');
const cookieParser = require('cookie-parser');
const { OAuth2Client } = require('google-auth-library');

const app = express();
const PORT = process.env.PORT || 3000;
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;

if (!GOOGLE_CLIENT_ID) {
  console.warn(
    '\n[WARNING] GOOGLE_CLIENT_ID is not set. Copy .env.example to .env and fill it in.\n'
  );
}

const client = new OAuth2Client(GOOGLE_CLIENT_ID);

app.use(express.json());
app.use(cookieParser());
app.use(express.static('public'));

// In-memory "session store" for demo purposes only.
// In a real app, use a proper session store (Redis, a database, etc.)
const sessions = {};

function makeSessionId() {
  return (
    Math.random().toString(36).slice(2) + Date.now().toString(36)
  );
}

/**
 * POST /auth/google
 * Body: { credential: "<the ID token from Google Sign-In>" }
 *
 * This is the endpoint the front-end calls right after Google
 * hands it back an ID token. We verify the token server-side —
 * NEVER trust a token just because the browser says it's valid.
 */
app.post('/auth/google', async (req, res) => {
  const { credential } = req.body;

  if (!credential) {
    return res.status(400).json({ error: 'Missing credential' });
  }

  try {
    // Verify the token's signature, audience, issuer, and expiry.
    const ticket = await client.verifyIdToken({
      idToken: credential,
      audience: GOOGLE_CLIENT_ID,
    });

    const payload = ticket.getPayload();
    // payload contains: sub (Google user id), email, name, picture, etc.

    // Look up or create a user record here in a real app.
    const user = {
      googleId: payload.sub,
      email: payload.email,
      emailVerified: payload.email_verified,
      name: payload.name,
      picture: payload.picture,
    };

    // Create a simple session and store it in a cookie.
    const sessionId = makeSessionId();
    sessions[sessionId] = user;

    res.cookie('session_id', sessionId, {
      httpOnly: true,
      sameSite: 'lax',
      // secure: true, // enable this once you're serving over HTTPS
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    res.json({ success: true, user });
  } catch (err) {
    console.error('Token verification failed:', err.message);
    res.status(401).json({ error: 'Invalid Google token' });
  }
});

/**
 * GET /auth/me
 * Returns the currently logged-in user (based on the session cookie),
 * or 401 if there isn't one.
 */
app.get('/auth/me', (req, res) => {
  const sessionId = req.cookies.session_id;
  const user = sessions[sessionId];

  if (!user) {
    return res.status(401).json({ error: 'Not logged in' });
  }

  res.json({ user });
});

/**
 * POST /auth/logout
 * Clears the session.
 */
app.post('/auth/logout', (req, res) => {
  const sessionId = req.cookies.session_id;
  delete sessions[sessionId];
  res.clearCookie('session_id');
  res.json({ success: true });
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
