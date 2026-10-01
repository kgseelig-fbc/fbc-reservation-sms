-- On-demand "pull reservations for date X" requests. The app (admins) inserts
-- a pending row; a Mac worker polls these, runs the Salesforce pull for that
-- date, imports, and marks the row complete.
CREATE TABLE IF NOT EXISTS pull_requests (
  id            SERIAL PRIMARY KEY,
  franchise_id  INTEGER NOT NULL REFERENCES franchises(id) ON DELETE CASCADE,
  target_date   DATE NOT NULL,
  status        TEXT NOT NULL DEFAULT 'pending',   -- pending | done | error
  requested_by  INTEGER,
  requested_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  completed_at  TIMESTAMPTZ,
  result_count  INTEGER,
  error_detail  TEXT
);
CREATE INDEX IF NOT EXISTS idx_pull_requests_pending ON pull_requests(status) WHERE status = 'pending';
