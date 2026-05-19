-- Optional dock scoping for franchise_staff users. When set, the user only
-- has access to that dock's reservations / conversations and only receives
-- push notifications for inbound SMS tied to a reservation at that dock.
-- super_admin and franchise_admin users always have dock_id = NULL (no scoping).
ALTER TABLE users
  ADD COLUMN IF NOT EXISTS dock_id TEXT REFERENCES docks(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_users_dock ON users(dock_id);
