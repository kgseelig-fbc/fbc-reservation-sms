-- Google SSO + user approval workflow.
-- Google-only login: every new sign-in lands in status='pending' until a
-- super_admin approves them and assigns role + franchise. Existing users
-- are backfilled to status='approved' so nobody gets locked out.

-- ---------- 1. Add SSO + approval columns ----------
ALTER TABLE users ADD COLUMN IF NOT EXISTS google_id    TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS name         TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_url   TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS status       TEXT NOT NULL DEFAULT 'pending';
ALTER TABLE users ADD COLUMN IF NOT EXISTS approved_at  TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN IF NOT EXISTS approved_by  INTEGER REFERENCES users(id) ON DELETE SET NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_google_id ON users(google_id) WHERE google_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_users_status ON users(status);

-- ---------- 2. Status check ----------
DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'users_status_check' AND conrelid = 'users'::regclass
  ) THEN
    ALTER TABLE users ADD CONSTRAINT users_status_check
      CHECK (status IN ('pending','approved','rejected','disabled'));
  END IF;
END $$;

-- ---------- 3. Backfill: anyone who already exists is implicitly approved ----------
UPDATE users SET status = 'approved', approved_at = COALESCE(approved_at, NOW())
 WHERE status = 'pending';

-- ---------- 4. Allow Google-only users (no password) ----------
ALTER TABLE users ALTER COLUMN password_hash DROP NOT NULL;

-- ---------- 5. Replace the strict role/franchise CHECK ----------
-- Old rule required franchise_id for non-super_admin and forbade it for
-- super_admin. New rule: while pending, role/franchise may be NULL; once
-- approved, super_admin has no franchise and other roles must have one.
DO $$ BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'users_check' AND conrelid = 'users'::regclass
  ) THEN
    ALTER TABLE users DROP CONSTRAINT users_check;
  END IF;
END $$;

-- Make role nullable so pending Google sign-ins don't need a role yet.
DO $$ BEGIN
  BEGIN ALTER TABLE users ALTER COLUMN role DROP NOT NULL; EXCEPTION WHEN OTHERS THEN NULL; END;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'users_role_franchise_check' AND conrelid = 'users'::regclass
  ) THEN
    ALTER TABLE users ADD CONSTRAINT users_role_franchise_check CHECK (
      status <> 'approved'
      OR (role = 'super_admin' AND franchise_id IS NULL)
      OR (role IN ('franchise_admin','franchise_staff') AND franchise_id IS NOT NULL)
    );
  END IF;
END $$;

INSERT INTO schema_migrations (name) VALUES ('004_google_sso_and_approval') ON CONFLICT DO NOTHING;
