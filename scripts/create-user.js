#!/usr/bin/env node
// Pre-approve a user by Google email. They'll sign in with Google and the
// existing row gets linked. super_admin has no franchise; franchise_admin
// and franchise_staff must belong to one.
// Usage: node scripts/create-user.js

require("dotenv").config();
const db = require("../db");
const { required } = require("./_prompt");

(async () => {
  try {
    const email = (await required("Email (Google): ")).toLowerCase();

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

    const existing = await db.query(`SELECT id FROM users WHERE email = $1`, [email]);
    if (existing.rows.length > 0) {
      await db.query(
        `UPDATE users
            SET role = $1, franchise_id = $2, status = 'approved', approved_at = NOW()
          WHERE id = $3`,
        [role, franchiseId, existing.rows[0].id]
      );
      console.log(`User updated: ${email} (${role}${franchiseId ? `, franchise_id=${franchiseId}` : ""})`);
    } else {
      await db.query(
        `INSERT INTO users (email, role, franchise_id, status, approved_at)
         VALUES ($1, $2, $3, 'approved', NOW())`,
        [email, role, franchiseId]
      );
      console.log(`User created: ${email} (${role}${franchiseId ? `, franchise_id=${franchiseId}` : ""})`);
    }
    console.log("They sign in with Google using this email — no password needed.");
  } catch (err) {
    if (err.code === "23505") console.error("That email is already registered.");
    else console.error("Failed:", err.message);
    process.exit(1);
  } finally {
    await db.pool.end();
  }
})();
