#!/usr/bin/env node
// Create a user. Role 'super_admin' has no franchise; 'franchise_admin' and
// 'franchise_staff' must belong to a franchise.
// Usage: node scripts/create-user.js

require("dotenv").config();
const bcrypt = require("bcryptjs");
const db = require("../db");
const { required, prompt } = require("./_prompt");

(async () => {
  try {
    const email = (await required("Email: ")).toLowerCase();

    console.log("Roles: super_admin, franchise_admin, franchise_staff");
    const role = await required("Role: ");
    if (!["super_admin", "franchise_admin", "franchise_staff"].includes(role)) {
      console.error("Invalid role."); process.exit(1);
    }

    let franchiseId = null;
    if (role !== "super_admin") {
      const { rows: franchises } = await db.query(`SELECT id, slug, name FROM franchises ORDER BY id`);
      if (franchises.length === 0) {
        console.error("No franchises exist. Run scripts/create-franchise.js first."); process.exit(1);
      }
      console.log("Franchises:");
      franchises.forEach((f) => console.log(`  ${f.slug}\t${f.name}`));
      const slug = await required("Franchise slug: ");
      const franchise = franchises.find((f) => f.slug === slug);
      if (!franchise) { console.error("Not found."); process.exit(1); }
      franchiseId = franchise.id;
    }

    const password = await required("Password: ", { mask: true });
    if (password.length < 8) { console.error("Password must be at least 8 characters."); process.exit(1); }
    const hash = await bcrypt.hash(password, 12);

    await db.query(
      `INSERT INTO users (email, password_hash, role, franchise_id) VALUES ($1,$2,$3,$4)`,
      [email, hash, role, franchiseId]
    );
    console.log(`User created: ${email} (${role}${franchiseId ? `, franchise_id=${franchiseId}` : ""})`);
  } catch (err) {
    if (err.code === "23505") console.error("That email is already registered.");
    else console.error("Failed:", err.message);
    process.exit(1);
  } finally {
    await db.pool.end();
  }
})();
