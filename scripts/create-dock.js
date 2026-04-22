#!/usr/bin/env node
// Add a dock to a franchise.
// Usage: node scripts/create-dock.js

require("dotenv").config();
const db = require("../db");
const { required, prompt } = require("./_prompt");

(async () => {
  try {
    const { rows: franchises } = await db.query(`SELECT id, slug, name FROM franchises ORDER BY id`);
    if (franchises.length === 0) {
      console.error("No franchises exist. Run scripts/create-franchise.js first.");
      process.exit(1);
    }
    console.log("Franchises:");
    franchises.forEach((f) => console.log(`  ${f.slug}\t${f.name}`));

    const slug = await required("Franchise slug: ");
    const franchise = franchises.find((f) => f.slug === slug);
    if (!franchise) { console.error("Not found."); process.exit(1); }

    const dockId = (await required("Dock id (url-safe, e.g. 'tampa-bay'): ")).toLowerCase();
    const name = await required("Dock display name: ");
    const sortInput = await prompt("Sort order [0]: ");
    const sortOrder = parseInt(sortInput) || 0;

    await db.query(
      `INSERT INTO docks (id, franchise_id, name, sort_order) VALUES ($1,$2,$3,$4)`,
      [dockId, franchise.id, name, sortOrder]
    );
    console.log(`Dock created: ${name} (${dockId}) under ${franchise.name}`);
  } catch (err) {
    console.error("Failed:", err.message);
    process.exit(1);
  } finally {
    await db.pool.end();
  }
})();
