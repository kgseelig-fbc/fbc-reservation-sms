-- Track which staff user sent each outbound SMS. Inbound rows (direction='in')
-- always have this NULL — those come from the member, not staff.
ALTER TABLE messages
  ADD COLUMN IF NOT EXISTS sent_by_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_messages_sent_by ON messages(sent_by_user_id);
