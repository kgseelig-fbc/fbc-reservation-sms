-- Marks reservations whose start time changed via SMS (member stayed within
-- their window = auto, or staff approved an out-of-window change) and needs
-- to be pushed back to Salesforce (B25__Start__c). A Mac cron reads these,
-- updates SF by source_id (the SF reservation Id), then clears the flag.
ALTER TABLE reservations ADD COLUMN IF NOT EXISTS needs_sf_push BOOLEAN NOT NULL DEFAULT FALSE;
CREATE INDEX IF NOT EXISTS idx_reservations_needs_sf_push ON reservations(needs_sf_push) WHERE needs_sf_push;
