-- Self-serve password reset: issue tokens by email, redeem via reset form.
-- Tokens are stored as SHA-256 hashes so a DB leak doesn't expose live tokens.

CREATE TABLE IF NOT EXISTS password_resets (
  id          SERIAL PRIMARY KEY,
  user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash  TEXT NOT NULL,
  expires_at  TIMESTAMPTZ NOT NULL,
  used_at     TIMESTAMPTZ,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_password_resets_token ON password_resets(token_hash);
CREATE INDEX IF NOT EXISTS idx_password_resets_user ON password_resets(user_id);

INSERT INTO schema_migrations (name) VALUES ('003_password_resets') ON CONFLICT DO NOTHING;
