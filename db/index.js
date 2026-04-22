const fs = require("fs");
const path = require("path");
const { Pool } = require("pg");

const connectionString = process.env.DATABASE_URL;
const isProduction = process.env.NODE_ENV === "production";

if (!connectionString) {
  console.warn("DATABASE_URL is not set — the server will fail on first DB query.");
}

const pool = new Pool({
  connectionString,
  ssl: isProduction && !/localhost|127\.0\.0\.1/.test(connectionString || "")
    ? { rejectUnauthorized: false }
    : false,
  max: 10,
});

pool.on("error", (err) => {
  console.error("Postgres pool error:", err.message);
});

// Run every migration file in db/migrations/ in filename order. Each file is
// expected to be idempotent (CREATE TABLE IF NOT EXISTS, guarded ALTERs, etc).
async function initSchema() {
  const dir = path.join(__dirname, "migrations");
  const files = fs.readdirSync(dir).filter((f) => f.endsWith(".sql")).sort();
  for (const f of files) {
    const sql = fs.readFileSync(path.join(dir, f), "utf8");
    await pool.query(sql);
    console.log(`Migration applied: ${f}`);
  }

  // One-time backfill of the default franchise's Twilio credentials from the
  // legacy env vars. Only runs if the franchise row has no credentials yet,
  // so removing the env vars later is safe.
  const envSid = process.env.TWILIO_ACCOUNT_SID;
  const envToken = process.env.TWILIO_AUTH_TOKEN;
  const envPhone = process.env.TWILIO_PHONE_NUMBER;
  const envMsg = process.env.TWILIO_MESSAGING_SERVICE_SID;
  const envBase = (process.env.BASE_URL || "").replace(/\/+$/, "") || null;

  if (envSid && envToken) {
    await pool.query(
      `UPDATE franchises
       SET twilio_account_sid           = COALESCE(twilio_account_sid, $1),
           twilio_auth_token            = COALESCE(twilio_auth_token, $2),
           twilio_phone_number          = COALESCE(twilio_phone_number, $3),
           twilio_messaging_service_sid = COALESCE(twilio_messaging_service_sid, $4),
           base_url                     = COALESCE(base_url, $5)
       WHERE id = 1`,
      [envSid, envToken, envPhone || null, envMsg || null, envBase]
    );
  }

  console.log("Postgres schema + seed ready.");
}

function query(text, params) {
  return pool.query(text, params);
}

async function withTx(fn) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const result = await fn(client);
    await client.query("COMMIT");
    return result;
  } catch (err) {
    await client.query("ROLLBACK");
    throw err;
  } finally {
    client.release();
  }
}

module.exports = { pool, query, withTx, initSchema };
