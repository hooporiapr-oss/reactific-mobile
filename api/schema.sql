-- Reactific Database Schema
-- Run this against your Render PostgreSQL instance
-- Product flow: Free 5x5 Practice → Login → Stripe → STROBE™ Arena 5x10 → Leaderboard

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ───────────────────────────────────────────────────────
-- USERS
-- ───────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),

  email VARCHAR(255) UNIQUE NOT NULL,
  username VARCHAR(30) UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL,

  -- Competition identity
  display_name VARCHAR(80),
  school_org VARCHAR(120),

  -- Stripe / subscription
  stripe_customer_id VARCHAR(255),
  subscription_status VARCHAR(20) DEFAULT 'free',

  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_stripe ON users(stripe_customer_id);
CREATE INDEX IF NOT EXISTS idx_users_school_org ON users(school_org);

-- ───────────────────────────────────────────────────────
-- SCORES — every completed competition round
-- ───────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS scores (
  id BIGSERIAL PRIMARY KEY,

  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

  -- court:
  -- half = free 5x5 practice if ever used
  -- full = premium STROBE Arena 5x10
  court VARCHAR(10) NOT NULL DEFAULT 'full',

  -- speed:
  -- slow = 60 BPM / longer clock
  -- med  = 90 BPM
  -- fast = 120 BPM / elite
  speed VARCHAR(10) NOT NULL,

  level INTEGER NOT NULL,
  score INTEGER NOT NULL,
  streak INTEGER NOT NULL DEFAULT 0,
  tier INTEGER NOT NULL DEFAULT 1,
  targets_found INTEGER NOT NULL DEFAULT 0,
  time_remaining_ms INTEGER DEFAULT 0,

  -- Future challenge support
  challenge_code VARCHAR(50) DEFAULT 'daily',
  challenge_name VARCHAR(120) DEFAULT 'Daily Challenge',

  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_scores_user ON scores(user_id);
CREATE INDEX IF NOT EXISTS idx_scores_created ON scores(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scores_leaderboard ON scores(court, speed, score DESC);
CREATE INDEX IF NOT EXISTS idx_scores_daily ON scores(created_at, score DESC);
CREATE INDEX IF NOT EXISTS idx_scores_challenge ON scores(challenge_code, speed, score DESC);

-- ───────────────────────────────────────────────────────
-- LEADERBOARD VIEWS
-- ───────────────────────────────────────────────────────

-- Best score per user per speed
CREATE OR REPLACE VIEW leaderboard_alltime AS
SELECT DISTINCT ON (s.user_id, s.speed)
  s.user_id,
  u.username,
  COALESCE(u.display_name, u.username) AS display_name,
  u.school_org,
  s.speed,
  s.score,
  s.level,
  s.tier,
  s.streak,
  s.targets_found,
  s.time_remaining_ms,
  s.challenge_code,
  s.challenge_name,
  s.created_at
FROM scores s
JOIN users u ON u.id = s.user_id
WHERE s.court = 'full'
ORDER BY s.user_id, s.speed, s.score DESC, s.created_at ASC;

-- Daily high scores
CREATE OR REPLACE VIEW leaderboard_daily AS
SELECT DISTINCT ON (s.user_id, s.speed)
  s.user_id,
  u.username,
  COALESCE(u.display_name, u.username) AS display_name,
  u.school_org,
  s.speed,
  s.score,
  s.level,
  s.tier,
  s.streak,
  s.targets_found,
  s.time_remaining_ms,
  s.challenge_code,
  s.challenge_name,
  s.created_at
FROM scores s
JOIN users u ON u.id = s.user_id
WHERE s.court = 'full'
  AND s.created_at >= CURRENT_DATE
ORDER BY s.user_id, s.speed, s.score DESC, s.created_at ASC;

-- Weekly high scores
CREATE OR REPLACE VIEW leaderboard_weekly AS
SELECT DISTINCT ON (s.user_id, s.speed)
  s.user_id,
  u.username,
  COALESCE(u.display_name, u.username) AS display_name,
  u.school_org,
  s.speed,
  s.score,
  s.level,
  s.tier,
  s.streak,
  s.targets_found,
  s.time_remaining_ms,
  s.challenge_code,
  s.challenge_name,
  s.created_at
FROM scores s
JOIN users u ON u.id = s.user_id
WHERE s.court = 'full'
  AND s.created_at >= date_trunc('week', CURRENT_DATE)
ORDER BY s.user_id, s.speed, s.score DESC, s.created_at ASC;
