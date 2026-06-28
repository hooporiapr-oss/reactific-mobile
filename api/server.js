// Reactific API — Auth + Stripe + Leaderboards + Google OAuth + Classes
// Deploy on Render Web Service
// FIXES: display_mode now included in class creation, teaching endpoint, and dashboard

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Stripe = require('stripe');
const { OAuth2Client } = require('google-auth-library');

// ── Config ──────────────────────────────────────────────
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'change-me-in-production';
const DATABASE_URL = process.env.DATABASE_URL;
const STRIPE_SECRET = process.env.STRIPE_SECRET_KEY;
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET;
const STRIPE_PRICE_ID = process.env.STRIPE_PRICE_ID;
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;

const CLIENT_URL = process.env.CLIENT_URL || 'https://reactificgaming.com';
const COMPETE_URL = process.env.COMPETE_URL || `${CLIENT_URL}/compete/strobe-01-compete.html`;
const STRIPE_CANCEL_URL = process.env.STRIPE_CANCEL_URL || `${CLIENT_URL}/compete/com-01.html`;

// Always allow all three Reactific domains regardless of env variable
const REQUIRED_ORIGINS = [
  'https://gostardigital.com',
  'https://gostar.digital',
  'https://reactificgaming.com',
  'https://www.reactificgaming.com',
];
const ALLOWED_ORIGINS = [
  ...new Set([
    ...REQUIRED_ORIGINS,
    ...(process.env.ALLOWED_ORIGINS || '').split(',').map(o => o.trim()).filter(Boolean)
  ])
];

if (process.env.NODE_ENV === 'production' && JWT_SECRET === 'change-me-in-production') {
  console.warn('WARNING: JWT_SECRET is using the fallback value. Set JWT_SECRET in production.');
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: DATABASE_URL?.includes('render') ? { rejectUnauthorized: false } : false
});

const stripe = STRIPE_SECRET ? new Stripe(STRIPE_SECRET) : null;
const googleClient = GOOGLE_CLIENT_ID ? new OAuth2Client(GOOGLE_CLIENT_ID) : null;

const app = express();

// ── Middleware ───────────────────────────────────────────
app.use(helmet());

app.use(cors({
  origin(origin, callback) {
    if (!origin || ALLOWED_ORIGINS.includes(origin)) return callback(null, true);
    return callback(new Error(`CORS blocked origin: ${origin}`));
  },
  credentials: true
}));

app.post('/api/stripe/webhook', express.raw({ type: 'application/json' }), handleStripeWebhook);

app.use(express.json({ limit: '1mb' }));

const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 120 });
app.use('/api/', limiter);

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 30 });
app.use('/api/auth/', authLimiter);

// ── Helpers ─────────────────────────────────────────────
function normalizeSpeed(speed) {
  const value = String(speed || '').trim().toLowerCase();
  if (['slow', 'training', '5', '7', '60'].includes(value)) return 'slow';
  if (['med', 'medium', 'tempo', '3', '90'].includes(value)) return 'med';
  if (['fast', 'elite', '2', '120'].includes(value)) return 'fast';
  return null;
}

function makeToken(user) {
  return jwt.sign(
    {
      id: user.id,
      email: user.email,
      username: user.username,
      subscription_status: user.subscription_status,
      role: user.role || 'student',
      class_id: user.class_id || null
    },
    JWT_SECRET,
    { expiresIn: '30d' }
  );
}

async function getUserById(userId) {
  const result = await pool.query(
    `SELECT id, email, username, subscription_status, stripe_customer_id, role, class_id, created_at
     FROM users WHERE id = $1`,
    [userId]
  );
  return result.rows[0] || null;
}

async function userHasActiveSubscription(userId) {
  const user = await getUserById(userId);
  return !!user && user.subscription_status === 'active';
}

function generateClassCode() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let code = '';
  for (let i = 0; i < 6; i++) code += chars[Math.floor(Math.random() * chars.length)];
  return code;
}

// ── Auth Middleware ─────────────────────────────────────
function authRequired(req, res, next) {
  const header = req.headers.authorization;
  if (!header?.startsWith('Bearer ')) return res.status(401).json({ error: 'No token' });
  try {
    req.user = jwt.verify(header.slice(7), JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

async function subRequired(req, res, next) {
  try {
    const active = await userHasActiveSubscription(req.user.id);
    if (!active) return res.status(403).json({ error: 'STROBE Arena requires subscription' });
    next();
  } catch (err) {
    console.error('Subscription check error:', err);
    res.status(500).json({ error: 'Server error' });
  }
}

// ── AUTH ENDPOINTS ──────────────────────────────────────

// Register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, username, password, role } = req.body;
    const cleanEmail = String(email || '').toLowerCase().trim();
    const cleanUsername = String(username || '').trim();
    const cleanRole = role === 'teacher' ? 'teacher' : 'student';

    if (!cleanEmail || !cleanUsername || !password)
      return res.status(400).json({ error: 'Email, username, and password required' });
    if (!/^\S+@\S+\.\S+$/.test(cleanEmail))
      return res.status(400).json({ error: 'Valid email required' });
    if (cleanUsername.length < 3 || cleanUsername.length > 20)
      return res.status(400).json({ error: 'Username must be 3-20 characters' });
    if (password.length < 6)
      return res.status(400).json({ error: 'Password must be 6+ characters' });
    if (!/^[a-zA-Z0-9_]+$/.test(cleanUsername))
      return res.status(400).json({ error: 'Username: letters, numbers, underscores only' });

    const hash = await bcrypt.hash(password, 12);
    const result = await pool.query(
      `INSERT INTO users (email, username, password_hash, role)
       VALUES ($1, $2, $3, $4)
       RETURNING id, email, username, subscription_status, role, class_id, created_at`,
      [cleanEmail, cleanUsername, hash, cleanRole]
    );

    const user = result.rows[0];
    const token = makeToken(user);
    res.status(201).json({ user, token });
  } catch (err) {
    if (err.code === '23505') {
      const field = err.constraint?.includes('email') ? 'Email' : 'Username';
      return res.status(409).json({ error: `${field} already taken` });
    }
    console.error('Register error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const cleanEmail = String(email || '').toLowerCase().trim();

    if (!cleanEmail || !password)
      return res.status(400).json({ error: 'Email and password required' });

    const result = await pool.query(
      `SELECT id, email, username, password_hash, subscription_status, role, class_id
       FROM users WHERE email = $1`,
      [cleanEmail]
    );

    if (!result.rows.length) return res.status(401).json({ error: 'Invalid credentials' });

    const user = result.rows[0];
    if (!user.password_hash) return res.status(401).json({ error: 'Please sign in with Google' });

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

    const publicUser = {
      id: user.id, email: user.email, username: user.username,
      subscription_status: user.subscription_status,
      role: user.role, class_id: user.class_id
    };

    const token = makeToken(publicUser);
    res.json({ user: publicUser, token });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Google Sign In
app.post('/api/auth/google', async (req, res) => {
  if (!googleClient) return res.status(500).json({ error: 'Google auth not configured' });
  try {
    const { token } = req.body;
    if (!token) return res.status(400).json({ error: 'Token required' });

    const ticket = await googleClient.verifyIdToken({
      idToken: token,
      audience: GOOGLE_CLIENT_ID,
    });

    const payload = ticket.getPayload();
    const { sub: googleId, email, name, picture } = payload;

    let result = await pool.query(
      `SELECT id, email, username, subscription_status, role, class_id, google_id
       FROM users WHERE google_id = $1 OR email = $2`,
      [googleId, email]
    );

    let user;

    if (result.rows.length > 0) {
      user = result.rows[0];
      if (!user.google_id) {
        await pool.query(
          `UPDATE users SET google_id = $1, avatar_url = $2, updated_at = NOW() WHERE id = $3`,
          [googleId, picture, user.id]
        );
      }
    } else {
      const username = (name || email).replace(/\s+/g, '_').toLowerCase().replace(/[^a-z0-9_]/g, '').slice(0, 16) + '_' + Math.floor(Math.random() * 999);
      const newUser = await pool.query(
        `INSERT INTO users (email, username, google_id, avatar_url, role)
         VALUES ($1, $2, $3, $4, 'student')
         RETURNING id, email, username, subscription_status, role, class_id`,
        [email, username, googleId, picture]
      );
      user = newUser.rows[0];
    }

    const publicUser = {
      id: user.id,
      email: user.email,
      username: user.username,
      subscription_status: user.subscription_status,
      role: user.role,
      class_id: user.class_id,
      avatar_url: picture,
      needs_class: !user.class_id
    };

    const jwtToken = makeToken(publicUser);
    res.json({ user: publicUser, token: jwtToken });
  } catch (err) {
    console.error('Google auth error:', err);
    res.status(500).json({ error: 'Google authentication failed' });
  }
});

// Get current user
app.get('/api/auth/me', authRequired, async (req, res) => {
  try {
    const user = await getUserById(req.user.id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({
      user: {
        id: user.id, email: user.email, username: user.username,
        subscription_status: user.subscription_status,
        role: user.role, class_id: user.class_id, created_at: user.created_at
      }
    });
  } catch (err) {
    console.error('Me error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ── CLASS ENDPOINTS ─────────────────────────────────────

// Create class (teacher) — FIX: Now sets default display_mode to 'initials'
app.post('/api/classes/create', authRequired, async (req, res) => {
  try {
    const { name, school_id } = req.body;
    if (!name) return res.status(400).json({ error: 'Class name required' });

    let code, attempts = 0;
    do {
      code = generateClassCode();
      const exists = await pool.query('SELECT id FROM classes WHERE code = $1', [code]);
      if (!exists.rows.length) break;
      attempts++;
    } while (attempts < 10);

    const result = await pool.query(
      `INSERT INTO classes (teacher_id, school_id, name, code, display_mode)
       VALUES ($1, $2, $3, $4, 'initials')
       RETURNING id, name, code, display_mode, created_at`,
      [req.user.id, school_id || null, name, code]
    );

    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error('Create class error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Join class with code (student)
app.post('/api/classes/join', authRequired, async (req, res) => {
  try {
    const { code } = req.body;
    if (!code) return res.status(400).json({ error: 'Class code required' });

    const classResult = await pool.query(
      `SELECT id, name FROM classes WHERE code = $1`,
      [code.toUpperCase().trim()]
    );

    if (!classResult.rows.length)
      return res.status(404).json({ error: 'Class not found — check your code' });

    const cls = classResult.rows[0];

    await pool.query(
      `INSERT INTO class_students (class_id, user_id)
       VALUES ($1, $2) ON CONFLICT (class_id, user_id) DO NOTHING`,
      [cls.id, req.user.id]
    );

    await pool.query(
      `UPDATE users SET class_id = $1, updated_at = NOW() WHERE id = $2`,
      [cls.id, req.user.id]
    );

    res.json({ class: cls });
  } catch (err) {
    console.error('Join class error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Teacher dashboard — FIX: Now includes display_mode in response
app.get('/api/classes/:id/dashboard', authRequired, async (req, res) => {
  try {
    const classId = req.params.id;
    const cls = await pool.query(
      `SELECT id, name, code, display_mode FROM classes WHERE id = $1 AND teacher_id = $2`,
      [classId, req.user.id]
    );
    if (!cls.rows.length) return res.status(403).json({ error: 'Not authorized' });

    const students = await pool.query(
      `SELECT u.id, u.username, u.avatar_url,
        s.score, s.level, s.streak, s.court, s.speed, s.created_at as last_played
       FROM class_students cs
       JOIN users u ON u.id = cs.user_id
       LEFT JOIN LATERAL (
         SELECT score, level, streak, court, speed, created_at
         FROM scores WHERE user_id = u.id
         ORDER BY created_at DESC LIMIT 1
       ) s ON true
       WHERE cs.class_id = $1
       ORDER BY s.score DESC NULLS LAST`,
      [classId]
    );

    res.json({ class: cls.rows[0], students: students.rows });
  } catch (err) {
    console.error('Dashboard error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// My class (student)
app.get('/api/classes/mine', authRequired, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT c.id, c.name, c.code, u.username as teacher_name
       FROM users me
       JOIN classes c ON c.id = me.class_id
       JOIN users u ON u.id = c.teacher_id
       WHERE me.id = $1`,
      [req.user.id]
    );
    res.json({ class: result.rows[0] || null });
  } catch (err) {
    console.error('My class error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// My classes (teacher) — FIX: Now includes display_mode in response
app.get('/api/classes/teaching', authRequired, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT c.id, c.name, c.code, c.display_mode, c.created_at,
        COUNT(cs.user_id) as student_count
       FROM classes c
       LEFT JOIN class_students cs ON cs.class_id = c.id
       WHERE c.teacher_id = $1
       GROUP BY c.id
       ORDER BY c.created_at DESC`,
      [req.user.id]
    );
    res.json({ classes: result.rows });
  } catch (err) {
    console.error('Teaching classes error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ── SCORES ENDPOINT ─────────────────────────────────────
app.post('/api/scores', authRequired, async (req, res) => {
  try {
    const { court = 'full', speed, level, score, streak, tier, targets_found, time_remaining_ms } = req.body;
    const normalizedSpeed = normalizeSpeed(speed);

    if (!['half', 'full'].includes(court)) return res.status(400).json({ error: 'Invalid court' });
    if (!normalizedSpeed) return res.status(400).json({ error: 'Invalid speed' });

    const safeLevel = Math.max(1, Math.min(parseInt(level, 10) || 1, 10));
    const safeScore = Math.max(0, parseInt(score, 10) || 0);
    const safeStreak = Math.max(0, parseInt(streak, 10) || 0);
    const safeTier = Math.max(1, Math.min(parseInt(tier, 10) || 1, 10));
    const safeTargets = Math.max(0, parseInt(targets_found, 10) || 0);
    const safeTimeRemaining = Math.max(0, parseInt(time_remaining_ms, 10) || 0);

    if (court === 'full') {
      const active = await userHasActiveSubscription(req.user.id);
      if (!active) return res.status(403).json({ error: 'STROBE Arena requires subscription' });
    }

    const result = await pool.query(
      `INSERT INTO scores (user_id, court, speed, level, score, streak, tier, targets_found, time_remaining_ms)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
       RETURNING id, created_at`,
      [req.user.id, court, normalizedSpeed, safeLevel, safeScore, safeStreak, safeTier, safeTargets, safeTimeRemaining]
    );

    const rankResult = await pool.query(
      `SELECT COUNT(*) + 1 AS rank
       FROM (
         SELECT DISTINCT ON (user_id) user_id, score
         FROM scores WHERE court = $1 AND speed = $2
         ORDER BY user_id, score DESC, created_at ASC
       ) top WHERE top.score > $3`,
      [court, normalizedSpeed, safeScore]
    );

    res.status(201).json({
      id: result.rows[0].id,
      rank: parseInt(rankResult.rows[0].rank, 10),
      speed: normalizedSpeed,
      created_at: result.rows[0].created_at
    });
  } catch (err) {
    console.error('Score error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ── LEADERBOARD ENDPOINTS ───────────────────────────────
async function getLeaderboard(period, speedInput, limitInput) {
  const speed = normalizeSpeed(speedInput) || 'slow';
  const limit = Math.min(parseInt(limitInput, 10) || 50, 100);
  let timeFilter = '';
  if (period === 'daily') timeFilter = `AND s.created_at >= CURRENT_DATE`;
  if (period === 'weekly') timeFilter = `AND s.created_at >= date_trunc('week', CURRENT_DATE)`;

  const result = await pool.query(
    `SELECT DISTINCT ON (s.user_id)
       u.username, s.score, s.level, s.tier, s.streak, s.created_at
     FROM scores s
     JOIN users u ON u.id = s.user_id
     WHERE s.court = 'full' AND s.speed = $1 ${timeFilter}
     ORDER BY s.user_id, s.score DESC, s.created_at ASC`,
    [speed]
  );

  const entries = result.rows
    .sort((a, b) => b.score - a.score || new Date(a.created_at) - new Date(b.created_at))
    .slice(0, limit)
    .map((row, i) => ({ rank: i + 1, ...row }));

  return { speed, period, entries };
}

app.get('/api/leaderboard/alltime', async (req, res) => {
  try { res.json(await getLeaderboard('alltime', req.query.speed, req.query.limit)); }
  catch (err) { console.error('Leaderboard error:', err); res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/leaderboard/daily', async (req, res) => {
  try { res.json(await getLeaderboard('daily', req.query.speed, req.query.limit)); }
  catch (err) { console.error('Daily leaderboard error:', err); res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/leaderboard/weekly', async (req, res) => {
  try { res.json(await getLeaderboard('weekly', req.query.speed, req.query.limit)); }
  catch (err) { console.error('Weekly leaderboard error:', err); res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/leaderboard/myrank', authRequired, async (req, res) => {
  try {
    const speed = normalizeSpeed(req.query.speed) || 'slow';
    const best = await pool.query(
      `SELECT score, level, tier, streak, created_at FROM scores
       WHERE user_id = $1 AND court = 'full' AND speed = $2
       ORDER BY score DESC, created_at ASC LIMIT 1`,
      [req.user.id, speed]
    );
    if (!best.rows.length) return res.json({ rank: null, score: 0, speed });
    const userScore = best.rows[0].score;
    const rankResult = await pool.query(
      `SELECT COUNT(*) + 1 AS rank FROM (
         SELECT DISTINCT ON (user_id) user_id, score FROM scores
         WHERE court = 'full' AND speed = $1
         ORDER BY user_id, score DESC, created_at ASC
       ) top WHERE top.score > $2`,
      [speed, userScore]
    );
    res.json({ rank: parseInt(rankResult.rows[0].rank, 10), speed, ...best.rows[0] });
  } catch (err) {
    console.error('My rank error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ── STRIPE ENDPOINTS ────────────────────────────────────
app.post('/api/stripe/checkout', authRequired, async (req, res) => {
  if (!stripe) return res.status(500).json({ error: 'Stripe not configured' });
  if (!STRIPE_PRICE_ID) return res.status(500).json({ error: 'Stripe price not configured' });
  try {
    let customerId;
    const user = await pool.query(`SELECT stripe_customer_id, email FROM users WHERE id = $1`, [req.user.id]);
    if (!user.rows.length) return res.status(404).json({ error: 'User not found' });
    if (user.rows[0].stripe_customer_id) {
      customerId = user.rows[0].stripe_customer_id;
    } else {
      const customer = await stripe.customers.create({ email: user.rows[0].email, metadata: { user_id: req.user.id } });
      customerId = customer.id;
      await pool.query(`UPDATE users SET stripe_customer_id = $1, updated_at = NOW() WHERE id = $2`, [customerId, req.user.id]);
    }
    const session = await stripe.checkout.sessions.create({
      customer: customerId, payment_method_types: ['card'],
      line_items: [{ price: STRIPE_PRICE_ID, quantity: 1 }],
      mode: 'subscription',
      success_url: `${COMPETE_URL}?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: STRIPE_CANCEL_URL,
      metadata: { user_id: req.user.id }
    });
    res.json({ url: session.url });
  } catch (err) {
    console.error('Checkout error:', err);
    res.status(500).json({ error: 'Failed to create checkout' });
  }
});

app.post('/api/stripe/portal', authRequired, async (req, res) => {
  if (!stripe) return res.status(500).json({ error: 'Stripe not configured' });
  try {
    const user = await pool.query(`SELECT stripe_customer_id FROM users WHERE id = $1`, [req.user.id]);
    if (!user.rows[0]?.stripe_customer_id) return res.status(400).json({ error: 'No subscription found' });
    const session = await stripe.billingPortal.sessions.create({ customer: user.rows[0].stripe_customer_id, return_url: CLIENT_URL });
    res.json({ url: session.url });
  } catch (err) {
    console.error('Portal error:', err);
    res.status(500).json({ error: 'Failed to create portal session' });
  }
});

async function handleStripeWebhook(req, res) {
  if (!stripe) return res.status(500).send('Stripe not configured');
  if (!STRIPE_WEBHOOK_SECRET) return res.status(500).send('Stripe webhook secret not configured');
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error('Webhook signature error:', err.message);
    return res.status(400).send('Invalid signature');
  }
  try {
    switch (event.type) {
      case 'checkout.session.completed': {
        const session = event.data.object;
        if (session.metadata?.user_id) {
          await pool.query(
            `UPDATE users SET subscription_status = 'active', stripe_customer_id = $1, updated_at = NOW() WHERE id = $2`,
            [session.customer, session.metadata.user_id]
          );
        }
        break;
      }
      case 'customer.subscription.created':
      case 'customer.subscription.updated': {
        const sub = event.data.object;
        const status = sub.status === 'active' || sub.status === 'trialing' ? 'active' : 'inactive';
        await pool.query(`UPDATE users SET subscription_status = $1, updated_at = NOW() WHERE stripe_customer_id = $2`, [status, sub.customer]);
        break;
      }
      case 'customer.subscription.deleted': {
        const sub = event.data.object;
        await pool.query(`UPDATE users SET subscription_status = 'cancelled', updated_at = NOW() WHERE stripe_customer_id = $1`, [sub.customer]);
        break;
      }
    }
  } catch (err) {
    console.error('Webhook handler error:', err);
  }
  res.json({ received: true });
}

// ── Health check ────────────────────────────────────────
app.get('/api/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ status: 'ok', db: 'connected', stripe: !!stripe, google: !!googleClient, client_url: CLIENT_URL });
  } catch {
    res.status(500).json({ status: 'error', db: 'disconnected' });
  }
});

// ── CLASS MANAGEMENT ────────────────────────────────────

// DELETE /api/classes/:id — teacher deletes their own class
app.delete('/api/classes/:id', authRequired, async (req, res) => {
  try {
    const classId = parseInt(req.params.id, 10);
    const owns = await pool.query(`SELECT id FROM classes WHERE id = $1 AND teacher_id = $2`, [classId, req.user.id]);
    if (!owns.rows.length) return res.status(403).json({ error: 'Not your class' });
    await pool.query(`DELETE FROM class_students WHERE class_id = $1`, [classId]);
    await pool.query(`DELETE FROM classes WHERE id = $1`, [classId]);
    res.json({ deleted: true, class_id: classId });
  } catch (err) {
    console.error('Delete class error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// PATCH /api/classes/:id — teacher renames their class
app.patch('/api/classes/:id', authRequired, async (req, res) => {
  try {
    const classId = parseInt(req.params.id, 10);
    const { name } = req.body;
    if (!name || !name.trim()) return res.status(400).json({ error: 'Name required' });
    const owns = await pool.query(`SELECT id FROM classes WHERE id = $1 AND teacher_id = $2`, [classId, req.user.id]);
    if (!owns.rows.length) return res.status(403).json({ error: 'Not your class' });
    await pool.query(`UPDATE classes SET name = $1 WHERE id = $2`, [name.trim(), classId]);
    res.json({ updated: true, class_id: classId, name: name.trim() });
  } catch (err) {
    console.error('Rename class error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// DELETE /api/classes/:id/students/:userId — teacher removes a student from their class
app.delete('/api/classes/:id/students/:userId', authRequired, async (req, res) => {
  try {
    const classId = parseInt(req.params.id, 10);
    const userId = req.params.userId;
    const owns = await pool.query(`SELECT id FROM classes WHERE id = $1 AND teacher_id = $2`, [classId, req.user.id]);
    if (!owns.rows.length) return res.status(403).json({ error: 'Not your class' });
    await pool.query(`DELETE FROM class_students WHERE class_id = $1 AND user_id = $2`, [classId, userId]);
    await pool.query(`UPDATE users SET class_id = NULL WHERE id = $1 AND class_id = $2`, [userId, classId]);
    res.json({ removed: true, user_id: userId, class_id: classId });
  } catch (err) {
    console.error('Remove student error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ── GAME LEADERBOARD SYSTEM ──────────────────────────────
// Six games, three time windows each, class-gated.
// game_id must be one of these six — anything else is rejected.
const VALID_GAMES = ['reaction', 'numhunt', 'recovery', 'pattern', 'sequence', 'focus'];

function isValidGame(g) {
  return VALID_GAMES.includes(String(g || '').toLowerCase());
}

// Build the display name for a leaderboard row
// Defaults to initials — safest for school displays
// Teacher can override to 'full_name' or 'username' per class
function displayName(row) {
  if (row.display_mode === 'username') return row.username;
  if (row.display_mode === 'full_name') {
    if (row.first_name) {
      const full = [row.first_name, row.last_name].filter(Boolean).join(' ').trim();
      return full || row.username;
    }
    return row.username;
  }
  // Default: initials (first name + last initial)
  if (row.first_name) {
    const first = row.first_name.trim();
    const lastInitial = (row.last_name || '').trim().charAt(0).toUpperCase();
    return lastInitial ? `${first} ${lastInitial}.` : first;
  }
  return row.username;
}

// POST /api/scores/game — submit a score for one of the six games
// Score only ranks (appears on any leaderboard) if the student is in a class.
// mode is 'practice' or 'compete' — informational only, doesn't change ranking logic.
app.post('/api/scores/game', authRequired, async (req, res) => {
  try {
    const { game_id, score, level, mode } = req.body;

    if (!isValidGame(game_id)) return res.status(400).json({ error: 'Invalid game_id' });

    const safeScore = Math.max(0, parseInt(score, 10) || 0);
    const safeLevel = Math.max(1, Math.min(parseInt(level, 10) || 1, 99));
    const safeMode = ['compete', 'progression'].includes(mode) ? mode : 'practice';

    // Pull the student's current class_id — null means score is saved but unranked
    const userResult = await pool.query(`SELECT class_id FROM users WHERE id = $1`, [req.user.id]);
    const classId = userResult.rows[0]?.class_id || null;

    const inserted = await pool.query(
      `INSERT INTO game_scores (user_id, class_id, game_id, score, level, mode)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING id, created_at`,
      [req.user.id, classId, String(game_id).toLowerCase(), safeScore, safeLevel, safeMode]
    );

    // Update global streak — counts any game played, once per calendar day
    const today = new Date().toISOString().slice(0, 10);
    const streakRow = await pool.query(`SELECT current_streak, best_streak, last_played_on FROM user_streaks WHERE user_id = $1`, [req.user.id]);

    if (!streakRow.rows.length) {
      await pool.query(
        `INSERT INTO user_streaks (user_id, current_streak, best_streak, last_played_on) VALUES ($1, 1, 1, $2)`,
        [req.user.id, today]
      );
    } else {
      const s = streakRow.rows[0];
      const lastPlayed = s.last_played_on ? new Date(s.last_played_on).toISOString().slice(0, 10) : null;
      if (lastPlayed !== today) {
        const yesterday = new Date(Date.now() - 86400000).toISOString().slice(0, 10);
        const newCurrent = lastPlayed === yesterday ? s.current_streak + 1 : 1;
        const newBest = Math.max(s.best_streak, newCurrent);
        await pool.query(
          `UPDATE user_streaks SET current_streak = $1, best_streak = $2, last_played_on = $3 WHERE user_id = $4`,
          [newCurrent, newBest, today, req.user.id]
        );
      }
    }

    // Ranked status — only true if student is in a class
    const ranked = classId !== null;
    let rank = null;
    if (ranked) {
      const rankResult = await pool.query(
        `SELECT COUNT(*) + 1 AS rank FROM (
           SELECT DISTINCT ON (user_id) user_id, score FROM game_scores
           WHERE game_id = $1 AND class_id IS NOT NULL
           ORDER BY user_id, score DESC, created_at ASC
         ) top WHERE top.score > $2`,
        [String(game_id).toLowerCase(), safeScore]
      );
      rank = parseInt(rankResult.rows[0].rank, 10);
    }

    res.status(201).json({
      id: inserted.rows[0].id,
      created_at: inserted.rows[0].created_at,
      ranked,
      rank
    });
  } catch (err) {
    console.error('Game score submit error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// GET /api/leaderboard/:game_id?window=today|week|alltime&class_id=X&limit=N
// Returns one game's leaderboard for one time window.
// class_id is optional — omit for school-wide, include to scope to one class.
async function getGameLeaderboard(gameId, windowParam, classIdParam, limitInput) {
  const limit = Math.min(parseInt(limitInput, 10) || 10, 100);
  let timeFilter = '';
  if (windowParam === 'today') timeFilter = `AND gs.created_at >= CURRENT_DATE`;
  if (windowParam === 'week') timeFilter = `AND gs.created_at >= date_trunc('week', CURRENT_DATE)`;

  let classFilter = '';
  const params = [gameId];
  if (classIdParam) {
    params.push(parseInt(classIdParam, 10));
    classFilter = `AND gs.class_id = $${params.length}`;
  }

  const result = await pool.query(
    `SELECT DISTINCT ON (gs.user_id)
       gs.user_id, gs.score, gs.level, gs.created_at,
       u.username, u.first_name, u.last_name,
       c.display_mode
     FROM game_scores gs
     JOIN users u ON u.id = gs.user_id
     LEFT JOIN classes c ON c.id = gs.class_id
     WHERE gs.game_id = $1 AND gs.class_id IS NOT NULL AND gs.score > 0 ${timeFilter} ${classFilter}
     ORDER BY gs.user_id, gs.score DESC, gs.created_at ASC`,
    params
  );

  const entries = result.rows
    .sort((a, b) => b.score - a.score || new Date(a.created_at) - new Date(b.created_at))
    .slice(0, limit)
    .map((row, i) => ({
      rank: i + 1,
      name: displayName(row),
      score: row.score,
      level: row.level
    }));

  return { game_id: gameId, window: windowParam, entries };
}

app.get('/api/leaderboard/:game_id', async (req, res) => {
  try {
    const gameId = String(req.params.game_id).toLowerCase();
    if (!isValidGame(gameId)) return res.status(400).json({ error: 'Invalid game_id' });

    const windowParam = ['today', 'week', 'alltime'].includes(req.query.window) ? req.query.window : 'alltime';
    const result = await getGameLeaderboard(gameId, windowParam, req.query.class_id, req.query.limit);
    res.json(result);
  } catch (err) {
    console.error('Game leaderboard error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// GET /api/scores/personal-best/:game_id — student's own best score on one game
app.get('/api/scores/personal-best/:game_id', authRequired, async (req, res) => {
  try {
    const gameId = String(req.params.game_id).toLowerCase();
    if (!isValidGame(gameId)) return res.status(400).json({ error: 'Invalid game_id' });

    const best = await pool.query(
      `SELECT score, level, created_at FROM game_scores
       WHERE user_id = $1 AND game_id = $2
       ORDER BY score DESC, created_at ASC LIMIT 1`,
      [req.user.id, gameId]
    );

    if (!best.rows.length) return res.json({ game_id: gameId, score: 0, level: 1, has_played: false });
    res.json({ game_id: gameId, ...best.rows[0], has_played: true });
  } catch (err) {
    console.error('Personal best error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// GET /api/streak/me — global streak, any game, once per day
app.get('/api/streak/me', authRequired, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT current_streak, best_streak, last_played_on FROM user_streaks WHERE user_id = $1`,
      [req.user.id]
    );
    if (!result.rows.length) return res.json({ current_streak: 0, best_streak: 0, last_played_on: null });
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Streak fetch error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// POST /api/classes/:id/display-mode — teacher sets how names show on leaderboards for their class
app.post('/api/classes/:id/display-mode', authRequired, async (req, res) => {
  try {
    const { display_mode } = req.body;
    if (!['username', 'initials', 'full_name'].includes(display_mode)) {
      return res.status(400).json({ error: 'display_mode must be username, initials, or full_name' });
    }
    const classId = parseInt(req.params.id, 10);

    const owns = await pool.query(`SELECT id FROM classes WHERE id = $1 AND teacher_id = $2`, [classId, req.user.id]);
    if (!owns.rows.length) return res.status(403).json({ error: 'Not your class' });

    await pool.query(`UPDATE classes SET display_mode = $1 WHERE id = $2`, [display_mode, classId]);
    res.json({ class_id: classId, display_mode });
  } catch (err) {
    console.error('Display mode update error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ── WebSocket Real-Time Leaderboard Updates ─────────────
const WebSocket = require('ws');
const http = require('http');
const server = http.createServer(app);
const wss = new WebSocket.Server({ server, path: '/api/leaderboard/subscribe' });

// Store active subscriptions: { gameId-window-classId: [ws1, ws2, ...] }
var activeSubscriptions = {};

wss.on('connection', function(ws) {
  var subscriptionKey = null;

  ws.on('message', function(data) {
    try {
      var msg = JSON.parse(data);

      if (msg.action === 'subscribe') {
        var gameId = String(msg.game_id || '').toLowerCase();
        var window = ['today', 'week', 'alltime'].includes(msg.window) ? msg.window : 'alltime';
        var classId = msg.class_id ? parseInt(msg.class_id, 10) : null;

        if (!VALID_GAMES.includes(gameId)) {
          ws.send(JSON.stringify({ type: 'error', message: 'Invalid game' }));
          return;
        }

        subscriptionKey = gameId + '-' + window + '-' + (classId || 'all');

        if (!activeSubscriptions[subscriptionKey]) {
          activeSubscriptions[subscriptionKey] = [];
        }

        activeSubscriptions[subscriptionKey].push(ws);
        ws.send(JSON.stringify({ type: 'subscribed', key: subscriptionKey }));
      }
    } catch (err) {
      console.error('WS message error:', err);
      ws.send(JSON.stringify({ type: 'error', message: 'Parse error' }));
    }
  });

  ws.on('close', function() {
    if (subscriptionKey && activeSubscriptions[subscriptionKey]) {
      var idx = activeSubscriptions[subscriptionKey].indexOf(ws);
      if (idx > -1) {
        activeSubscriptions[subscriptionKey].splice(idx, 1);
      }
      if (activeSubscriptions[subscriptionKey].length === 0) {
        delete activeSubscriptions[subscriptionKey];
      }
    }
  });

  ws.on('error', function(err) {
    console.error('WS error:', err);
  });
});

async function broadcastLeaderboardUpdate(gameId, window, classId) {
  var key = gameId + '-' + window + '-' + (classId || 'all');
  var subscribers = activeSubscriptions[key];

  if (!subscribers || !subscribers.length) return;

  try {
    var leaderboard = await getGameLeaderboard(gameId, window, classId, 8);
    var msg = JSON.stringify({
      type: 'leaderboard_update',
      game_id: gameId,
      window: window,
      entries: leaderboard.entries
    });

    subscribers.forEach(function(ws) {
      if (ws.readyState === ws.OPEN) {
        ws.send(msg);
      }
    });
  } catch (err) {
    console.error('Broadcast error:', err);
  }
}

var originalPostScoreHandler = null;
app._router.stack.forEach(function(layer) {
  if (layer.route && layer.route.path === '/api/scores/game' && layer.route.methods.post) {
    var handlers = layer.route.stack;
    if (handlers && handlers.length > 0) {
      originalPostScoreHandler = handlers[handlers.length - 1].handle;
      handlers[handlers.length - 1].handle = function(req, res) {
        var originalSend = res.send;
        res.send = function(data) {
          if (res.statusCode === 201) {
            try {
              var gameId = String(req.body.game_id || '').toLowerCase();
              pool.query('SELECT class_id FROM users WHERE id = $1', [req.user.id])
                .then(function(result) {
                  var classId = result.rows[0]?.class_id || null;
                  ['today', 'week', 'alltime'].forEach(function(w) {
                    broadcastLeaderboardUpdate(gameId, w, classId);
                    broadcastLeaderboardUpdate(gameId, w, null);
                  });
                })
                .catch(function(err) {
                  console.error('Broadcast class lookup error:', err);
                });
            } catch (e) {
              console.error('Broadcast hook error:', e);
            }
          }
          return originalSend.call(this, data);
        };
        return originalPostScoreHandler.call(this, req, res);
      };
    }
  }
});

// ── Start ───────────────────────────────────────────────
server.listen(PORT, () => console.log(`Reactific API with WebSocket running on port ${PORT}`));

// ── STUDENT LOGIN — email + class code ─────────────────
app.post('/api/auth/student-login', async (req, res) => {
  try {
    const { email, code } = req.body;
    const cleanEmail = String(email || '').toLowerCase().trim();
    const cleanCode = String(code || '').toUpperCase().trim();

    if (!cleanEmail || !cleanCode)
      return res.status(400).json({ error: 'Email and class code required' });
    if (!/^\S+@\S+\.\S+$/.test(cleanEmail))
      return res.status(400).json({ error: 'Valid email required' });
    if (cleanCode.length !== 6)
      return res.status(400).json({ error: 'Class code must be 6 letters' });

    // Find class by code
    const classResult = await pool.query(
      `SELECT id, name FROM classes WHERE code = $1`,
      [cleanCode]
    );
    if (!classResult.rows.length)
      return res.status(404).json({ error: 'Class code not found — check with your teacher' });

    const cls = classResult.rows[0];

    // Find or create student
    let userResult = await pool.query(
      `SELECT id, email, username, subscription_status, role, class_id FROM users WHERE email = $1`,
      [cleanEmail]
    );

    let user;
    if (userResult.rows.length > 0) {
      user = userResult.rows[0];
    } else {
      // Auto-create student account from email
      // Students log in via email + class code only — never via password —
      // so we generate a random, never-shared password hash just to satisfy the column constraint.
      const localPart = cleanEmail.split('@')[0]; // e.g. "john.burgos" from "john.burgos@school.org"

      // Parse first/last name from email — handles first.last format cleanly
      // Falls back gracefully if the pattern doesn't match
      let firstName = null, lastName = null;
      if (localPart.includes('.')) {
        const parts = localPart.split('.');
        firstName = parts[0].charAt(0).toUpperCase() + parts[0].slice(1).toLowerCase();
        lastName = parts.slice(1).join(' ').replace(/\b\w/g, c => c.toUpperCase());
      } else {
        // No dot — just capitalize the whole thing as first name
        firstName = localPart.charAt(0).toUpperCase() + localPart.slice(1).toLowerCase();
      }

      const username = localPart.replace(/[^a-zA-Z0-9_]/g, '_').slice(0, 20);
      const uniqueUsername = username + '_' + Math.floor(Math.random() * 999);
      const randomPassword = require('crypto').randomBytes(32).toString('hex');
      const passwordHash = await bcrypt.hash(randomPassword, 12);
      const newUser = await pool.query(
        `INSERT INTO users (email, username, password_hash, role, class_id, first_name, last_name)
         VALUES ($1, $2, $3, 'student', $4, $5, $6)
         RETURNING id, email, username, subscription_status, role, class_id, first_name, last_name`,
        [cleanEmail, uniqueUsername, passwordHash, cls.id, firstName, lastName]
      );
      user = newUser.rows[0];
    }

    // Join class if not already in it
    await pool.query(
      `INSERT INTO class_students (class_id, user_id)
       VALUES ($1, $2) ON CONFLICT (class_id, user_id) DO NOTHING`,
      [cls.id, user.id]
    );

    // Update class_id if needed
    if (user.class_id !== cls.id) {
      await pool.query(
        `UPDATE users SET class_id = $1, updated_at = NOW() WHERE id = $2`,
        [cls.id, user.id]
      );
      user.class_id = cls.id;
    }

    const publicUser = {
      id: user.id,
      email: user.email,
      username: user.username,
      subscription_status: user.subscription_status,
      role: 'student',
      class_id: cls.id,
      class_name: cls.name
    };

    const token = makeToken(publicUser);
    res.json({ user: publicUser, token });

  } catch (err) {
    if (err.code === '23505') {
      // Username collision — retry with different suffix
      return res.status(409).json({ error: 'Please try again' });
    }
    console.error('Student login error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});
