-- Extra contact + location columns captured from the FBC report.
-- The primary `phone` column (chosen at import via mobile-first fallback)
-- is still the SMS target; these are kept for reference and display.

ALTER TABLE reservations ADD COLUMN IF NOT EXISTS member_mobile      TEXT;
ALTER TABLE reservations ADD COLUMN IF NOT EXISTS contact_mobile     TEXT;
ALTER TABLE reservations ADD COLUMN IF NOT EXISTS contact_home_phone TEXT;
ALTER TABLE reservations ADD COLUMN IF NOT EXISTS contact_phone      TEXT;
ALTER TABLE reservations ADD COLUMN IF NOT EXISTS location_info      TEXT;

INSERT INTO schema_migrations (name) VALUES ('007_contact_columns') ON CONFLICT DO NOTHING;
