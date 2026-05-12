-- Add return_time so imports can capture the FBC report's "Return Time" column
-- alongside the existing reservation_date (arrival).

ALTER TABLE reservations ADD COLUMN IF NOT EXISTS return_time TIMESTAMPTZ;

INSERT INTO schema_migrations (name) VALUES ('006_return_time') ON CONFLICT DO NOTHING;
