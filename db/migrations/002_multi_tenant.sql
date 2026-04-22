-- Multi-tenant: add franchises, users, docks. Scope existing data by franchise_id.
-- Idempotent so it's safe to re-run. All existing rows are backfilled under
-- franchise_id = 1 ("FBC NE Florida") using the prior env-var Twilio credentials.

-- ---------- 1. Franchises ----------
CREATE TABLE IF NOT EXISTS franchises (
  id                            SERIAL PRIMARY KEY,
  slug                          TEXT UNIQUE NOT NULL,
  name                          TEXT NOT NULL,
  timezone                      TEXT NOT NULL DEFAULT 'America/New_York',
  twilio_account_sid            TEXT,
  twilio_auth_token             TEXT,
  twilio_phone_number           TEXT,
  twilio_messaging_service_sid  TEXT,
  base_url                      TEXT,
  logo_url                      TEXT,
  brand_color                   TEXT,
  created_at                    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_franchises_phone ON franchises(twilio_phone_number)
  WHERE twilio_phone_number IS NOT NULL;

-- ---------- 2. Users (replaces single ADMIN_PASSWORD) ----------
CREATE TABLE IF NOT EXISTS users (
  id             SERIAL PRIMARY KEY,
  email          TEXT UNIQUE NOT NULL,
  password_hash  TEXT NOT NULL,
  role           TEXT NOT NULL CHECK (role IN ('super_admin','franchise_admin','franchise_staff')),
  franchise_id   INTEGER REFERENCES franchises(id) ON DELETE CASCADE,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_login     TIMESTAMPTZ,
  CHECK (
    (role = 'super_admin' AND franchise_id IS NULL) OR
    (role <> 'super_admin' AND franchise_id IS NOT NULL)
  )
);
CREATE INDEX IF NOT EXISTS idx_users_franchise ON users(franchise_id);

-- ---------- 3. Docks (moved from hardcoded array) ----------
CREATE TABLE IF NOT EXISTS docks (
  id           TEXT PRIMARY KEY,
  franchise_id INTEGER NOT NULL REFERENCES franchises(id) ON DELETE CASCADE,
  name         TEXT NOT NULL,
  sort_order   INTEGER DEFAULT 0,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_docks_franchise ON docks(franchise_id);

-- ---------- 4. Seed the default franchise + docks ----------
-- Use id=1 so backfills below are deterministic. Force id=1 via ALTER SEQUENCE if needed.
INSERT INTO franchises (id, slug, name, timezone)
VALUES (1, 'fbc-ne-fl', 'FBC NE Florida', 'America/New_York')
ON CONFLICT (id) DO NOTHING;

-- Advance the sequence past 1 so future auto-generated IDs don't collide.
SELECT setval('franchises_id_seq', GREATEST((SELECT MAX(id) FROM franchises), 1));

INSERT INTO docks (id, franchise_id, name, sort_order) VALUES
  ('jax-beach',       1, 'Jacksonville Beach',              1),
  ('julington-east',  1, 'Julington Creek East',            2),
  ('julington-west',  1, 'Julington Creek West',            3),
  ('camachee-cove',   1, 'St. Augustine -- Camachee Cove',  4),
  ('shipyard',        1, 'St. Augustine -- Shipyard',       5)
ON CONFLICT (id) DO NOTHING;

-- ---------- 5. Add franchise_id columns to existing tables ----------
ALTER TABLE members         ADD COLUMN IF NOT EXISTS franchise_id INTEGER REFERENCES franchises(id) ON DELETE CASCADE;
ALTER TABLE import_batches  ADD COLUMN IF NOT EXISTS franchise_id INTEGER REFERENCES franchises(id) ON DELETE CASCADE;
ALTER TABLE reservations    ADD COLUMN IF NOT EXISTS franchise_id INTEGER REFERENCES franchises(id) ON DELETE CASCADE;
ALTER TABLE messages        ADD COLUMN IF NOT EXISTS franchise_id INTEGER REFERENCES franchises(id) ON DELETE CASCADE;

-- ---------- 6. Backfill existing rows under franchise 1 ----------
UPDATE members         SET franchise_id = 1 WHERE franchise_id IS NULL;
UPDATE import_batches  SET franchise_id = 1 WHERE franchise_id IS NULL;
UPDATE reservations    SET franchise_id = 1 WHERE franchise_id IS NULL;
UPDATE messages        SET franchise_id = 1 WHERE franchise_id IS NULL;

-- ---------- 7. Enforce NOT NULL (safe now that backfill is done) ----------
DO $$ BEGIN
  BEGIN ALTER TABLE members        ALTER COLUMN franchise_id SET NOT NULL; EXCEPTION WHEN OTHERS THEN NULL; END;
  BEGIN ALTER TABLE import_batches ALTER COLUMN franchise_id SET NOT NULL; EXCEPTION WHEN OTHERS THEN NULL; END;
  BEGIN ALTER TABLE reservations   ALTER COLUMN franchise_id SET NOT NULL; EXCEPTION WHEN OTHERS THEN NULL; END;
  BEGIN ALTER TABLE messages       ALTER COLUMN franchise_id SET NOT NULL; EXCEPTION WHEN OTHERS THEN NULL; END;
END $$;

-- ---------- 8. Change members PK: (phone) → (franchise_id, phone) ----------
-- A person may be a member of multiple franchises. Scope the unique constraint.
DO $$ BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'members_pkey' AND conrelid = 'members'::regclass
  ) THEN
    -- Only rebuild the PK if it isn't already the composite form.
    IF NOT EXISTS (
      SELECT 1
      FROM pg_index i
      JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey)
      WHERE i.indrelid = 'members'::regclass AND i.indisprimary
      GROUP BY i.indexrelid
      HAVING COUNT(*) = 2
    ) THEN
      ALTER TABLE members DROP CONSTRAINT members_pkey;
      ALTER TABLE members ADD PRIMARY KEY (franchise_id, phone);
    END IF;
  END IF;
END $$;

-- ---------- 9. Indexes for franchise-scoped queries ----------
CREATE INDEX IF NOT EXISTS idx_reservations_franchise_dock ON reservations(franchise_id, dock_id);
CREATE INDEX IF NOT EXISTS idx_messages_franchise_phone_time ON messages(franchise_id, phone, created_at);
CREATE INDEX IF NOT EXISTS idx_import_batches_franchise_dock ON import_batches(franchise_id, dock_id, imported_at DESC);

-- ---------- 10. Schema tracking ----------
CREATE TABLE IF NOT EXISTS schema_migrations (
  name       TEXT PRIMARY KEY,
  applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
INSERT INTO schema_migrations (name) VALUES ('002_multi_tenant') ON CONFLICT DO NOTHING;
