#!/usr/bin/env node
// One-time bootstrap: pre-approve a super-admin by Google email.
// The user signs in with Google as usual; on first login, their account
// gets linked to this row instead of landing in 'pending'.
// Usage: node scripts/init-super-admin.js

require("dotenv").config();
const db = require("../db");
const { required } = require("./_prompt");

(async () => {
  try {
    await db.initSchema();

    const { rows } = await db.query(
      `SELECT id, email, status FROM users WHERE role = 'super_admin' AND status = 'approved' LIMIT 1`
    );
    if (rows.length > 0) {
      console.log(`A super-admin already exists: ${rows[0].email} (id=${rows[0].id}).`);
      console.log("Use the Users tab in the dashboard to add or promote more.");
      process.exit(0);
    }

    const email = (await required("Super-admin Google email: ")).toLowerCase();

    // If a row already exists for this email (e.g. from a prior setup), promote it.
    // Otherwise insert a fresh approved super_admin with no franchise.
    const existing = await db.query(`SELECT id FROM users WHERE email = $1`, [email]);
    if (existing.rows.length > 0) {
      await db.query(
        `UPDATE users
            SET role = 'super_admin', franchise_id = NULL,
                status = 'approved', approved_at = NOW()
          WHERE id = $1`,
        [existing.rows[0].id]
      );
    } else {
      await db.query(
        `INSERT INTO users (email, role, status, approved_at)
         VALUES ($1, 'super_admin', 'approved', NOW())`,
        [email]
      );
    }
    console.log(`Super-admin pre-approved: ${email}`);
    console.log("Sign in with Google using that email to activate the account.");
  } catch (err) {
    console.error("Failed:", err.message);
    process.exit(1);
  } finally {
    await db.pool.end();
  }
})();
