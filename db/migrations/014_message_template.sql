-- Editable per-franchise confirmation message template. NULL = use the
-- built-in default (buildDefaultSmsBody in server.js). Supports placeholders:
-- {first_name} {name} {boat} {date} {time} {return_time} {dock}
ALTER TABLE franchises ADD COLUMN IF NOT EXISTS message_template TEXT;
