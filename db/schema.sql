-- Members: one row per phone number (E.164). Stable identity across reservations.
CREATE TABLE IF NOT EXISTS members (
  phone       TEXT PRIMARY KEY,
  name        TEXT,
  email       TEXT,
  first_seen  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Import batches: every Excel upload creates a new batch (append-only).
CREATE TABLE IF NOT EXISTS import_batches (
  id           SERIAL PRIMARY KEY,
  dock_id      TEXT NOT NULL,
  imported_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  row_count    INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_import_batches_dock ON import_batches(dock_id, imported_at DESC);

-- Reservations: append-only history. A re-import creates a new batch of rows.
CREATE TABLE IF NOT EXISTS reservations (
  id                TEXT PRIMARY KEY,
  import_batch_id   INTEGER NOT NULL REFERENCES import_batches(id) ON DELETE CASCADE,
  source_id         TEXT,
  dock_id           TEXT NOT NULL,
  phone             TEXT,
  name              TEXT,
  email             TEXT,
  service           TEXT,
  reservation_date  TIMESTAMPTZ,
  guests            INTEGER DEFAULT 1,
  status            TEXT DEFAULT 'unconfirmed',
  channel           TEXT DEFAULT 'sms',
  notes             TEXT DEFAULT '',
  message_sent      BOOLEAN DEFAULT FALSE,
  message_time      TIMESTAMPTZ,
  time_updated      BOOLEAN DEFAULT FALSE,
  original_time     TIMESTAMPTZ,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_reservations_phone ON reservations(phone);
CREATE INDEX IF NOT EXISTS idx_reservations_dock_batch ON reservations(dock_id, import_batch_id);
CREATE INDEX IF NOT EXISTS idx_reservations_date ON reservations(reservation_date);

-- Messages: every SMS ever, inbound and outbound. Keyed by phone so a reply
-- that arrives days later still joins the same conversation thread.
CREATE TABLE IF NOT EXISTS messages (
  id              SERIAL PRIMARY KEY,
  phone           TEXT NOT NULL,
  reservation_id  TEXT REFERENCES reservations(id) ON DELETE SET NULL,
  dock_id         TEXT,
  direction       TEXT NOT NULL CHECK (direction IN ('in','out')),
  body            TEXT NOT NULL,
  twilio_sid      TEXT UNIQUE,
  twilio_status   TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_messages_phone_time ON messages(phone, created_at);
CREATE INDEX IF NOT EXISTS idx_messages_reservation ON messages(reservation_id);
