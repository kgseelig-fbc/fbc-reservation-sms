-- Per-reservation "skip the confirmation SMS" flag, plus a member-level
-- do-not-contact flag that auto-applies skip_reminder to future imports.
-- Both default to FALSE so existing data behaves unchanged.

ALTER TABLE reservations
  ADD COLUMN IF NOT EXISTS skip_reminder BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE members
  ADD COLUMN IF NOT EXISTS do_not_contact BOOLEAN NOT NULL DEFAULT FALSE;

CREATE INDEX IF NOT EXISTS idx_reservations_skip
  ON reservations(franchise_id, dock_id) WHERE skip_reminder = TRUE;
CREATE INDEX IF NOT EXISTS idx_members_dnc
  ON members(franchise_id) WHERE do_not_contact = TRUE;
