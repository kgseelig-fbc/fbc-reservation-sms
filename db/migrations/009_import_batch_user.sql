-- Track which user performed each Excel upload. Pre-existing batches will
-- show NULL (rendered as "Unknown" in the dashboard).
ALTER TABLE import_batches
  ADD COLUMN IF NOT EXISTS uploaded_by_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_import_batches_uploader ON import_batches(uploaded_by_user_id);
