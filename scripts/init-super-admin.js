#!/usr/bin/env node
// One-time bootstrap: create the first super-admin user.
// Usage: node scripts/init-super-admin.js

require("dotenv").config();
const bcrypt = require("bcryptjs");
const db = require("../db");
const { required } = require("./_prompt");

(async () => {
  try {
    await db.initSchema();

    const { rows } = await db.query(`SELECT id, email FROM users WHERE role = 'super_admin' LIMIT 1`);
    if (rows.length > 0) {
      console.log(`A super-admin already exists: ${rows[0].email} (id=${rows[0].id}).`);
      console.log("Use scripts/create-user.js to add more.");
      process.exit(0);
    }

    const email = (await required("Super-admin email: ")).toLowerCase();
    const password = await required("Password: ", { mask: true });
    if (password.length < 8) {
      console.error("Password must be at least 8 characters.");
      process.exit(1);
    }
    const hash = await bcrypt.hash(password, 12);

    await db.query(
      `INSERT INTO users (email, password_hash, role) VALUES ($1, $2, 'super_admin')`,
      [email, hash]
    );
    console.log(`Super-admin created: ${email}`);
  } catch (err) {
    console.error("Failed:", err.message);
    process.exit(1);
  } finally {
    await db.pool.end();
  }
})();
