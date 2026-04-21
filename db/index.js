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

async function initSchema() {
  const sql = fs.readFileSync(path.join(__dirname, "schema.sql"), "utf8");
  await pool.query(sql);
  console.log("Postgres schema ready.");
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
