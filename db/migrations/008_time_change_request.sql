-- Stores a customer-proposed arrival time pending staff review.
-- When NULL, no pending change. When set, the reservation's reservation_date
-- has NOT yet been updated — staff approve via the dashboard.
ALTER TABLE reservations
  ADD COLUMN IF NOT EXISTS pending_time_change TIMESTAMPTZ;
