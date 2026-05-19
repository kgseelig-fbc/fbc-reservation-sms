-- Web Push subscriptions for staff PWA alerts.
-- One row per (user, device/browser). endpoint is unique because that's how
-- the browser identifies the subscription on the push service.
CREATE TABLE IF NOT EXISTS push_subscriptions (
  id            SERIAL PRIMARY KEY,
  user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  franchise_id  INTEGER REFERENCES franchises(id) ON DELETE CASCADE,
  endpoint      TEXT NOT NULL UNIQUE,
  p256dh        TEXT NOT NULL,
  auth          TEXT NOT NULL,
  user_agent    TEXT,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_push_subs_user      ON push_subscriptions(user_id);
CREATE INDEX IF NOT EXISTS idx_push_subs_franchise ON push_subscriptions(franchise_id);
