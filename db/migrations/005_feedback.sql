-- User feedback / bug / enhancement reports.
-- Visible to admins under the Feedback tab; the submitter can view their own
-- submissions plus admin replies. Pinned rows surface as "known issues" to
-- everyone in the floating widget.

CREATE TABLE IF NOT EXISTS feedback (
  id              SERIAL PRIMARY KEY,
  franchise_id    INTEGER REFERENCES franchises(id) ON DELETE SET NULL,
  user_id         INTEGER REFERENCES users(id) ON DELETE SET NULL,
  user_email      TEXT,
  user_name       TEXT,
  category        TEXT NOT NULL CHECK (category IN ('bug','feedback','enhancement')),
  message         TEXT NOT NULL,
  page_url        TEXT,
  ctx_dock        TEXT,
  ctx_view        TEXT,
  user_agent      TEXT,
  status          TEXT NOT NULL DEFAULT 'new'
                  CHECK (status IN ('new','in_progress','resolved','wont_fix')),
  admin_reply     TEXT,
  admin_reply_at  TIMESTAMPTZ,
  is_known_issue  BOOLEAN NOT NULL DEFAULT FALSE,
  resolved_at     TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_feedback_created    ON feedback(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_feedback_status     ON feedback(status);
CREATE INDEX IF NOT EXISTS idx_feedback_user       ON feedback(user_id);
CREATE INDEX IF NOT EXISTS idx_feedback_known      ON feedback(is_known_issue) WHERE is_known_issue;

INSERT INTO schema_migrations (name) VALUES ('005_feedback') ON CONFLICT DO NOTHING;
