#!/usr/bin/env node
// Remove ALL data (reservations, messages, member record) for a single phone
// number within a franchise. Use to clear test numbers. Idempotent.
// Usage: node scripts/purge-phone.js <last10digits> [franchiseId=1]
require("dotenv").config();
const db = require("../db");

(async () => {
  const tail = (process.argv[2] || "").replace(/\D/g, "").slice(-10);
  const fid = Number(process.argv[3] || 1);
  if (tail.length !== 10) { console.error("Need a 10-digit phone."); process.exit(1); }
  const norm = `RIGHT(REGEXP_REPLACE(phone, '\\D', '', 'g'), 10) = $2`;
  const r = await db.query(`DELETE FROM reservations WHERE franchise_id=$1 AND ${norm}`, [fid, tail]);
  const m = await db.query(`DELETE FROM messages     WHERE franchise_id=$1 AND ${norm}`, [fid, tail]);
  const u = await db.query(`DELETE FROM members      WHERE franchise_id=$1 AND ${norm}`, [fid, tail]);
  console.log(`Purged ${tail}: reservations=${r.rowCount}, messages=${m.rowCount}, members=${u.rowCount}`);
  await db.pool.end();
})().catch((e) => { console.error(e.message); process.exit(1); });
