#!/usr/bin/env node
// Create a new franchise (tenant). Prompts for slug, name, timezone, and
// Twilio credentials. Twilio fields are optional — a franchise can exist
// before its Twilio account is ready (SMS features will be disabled until
// credentials are filled in).
// Usage: node scripts/create-franchise.js

require("dotenv").config();
const db = require("../db");
const { prompt, required } = require("./_prompt");

(async () => {
  try {
    const slug = (await required("Slug (url-safe, e.g. 'fbc-tampa'): ")).toLowerCase();
    const name = await required("Display name: ");
    const timezone = (await prompt("Timezone [America/New_York]: ")) || "America/New_York";
    const twilio_account_sid = (await prompt("Twilio Account SID (blank to skip): ")) || null;
    const twilio_auth_token = twilio_account_sid
      ? await required("Twilio Auth Token: ", { mask: true })
      : null;
    const twilio_phone_number = (await prompt("Twilio phone number (E.164, e.g. +19045551212): ")) || null;
    const twilio_messaging_service_sid = (await prompt("Twilio Messaging Service SID (optional): ")) || null;
    const base_url = (await prompt("Public base URL for webhooks (optional): ")) || null;
    const logo_url = (await prompt("Logo URL (optional): ")) || null;
    const brand_color = (await prompt("Brand color hex (optional): ")) || null;

    const { rows } = await db.query(
      `INSERT INTO franchises
       (slug, name, timezone, twilio_account_sid, twilio_auth_token,
        twilio_phone_number, twilio_messaging_service_sid, base_url, logo_url, brand_color)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
       RETURNING id`,
      [slug, name, timezone, twilio_account_sid, twilio_auth_token,
       twilio_phone_number, twilio_messaging_service_sid, base_url, logo_url, brand_color]
    );
    console.log(`Franchise created: ${name} (id=${rows[0].id}, slug=${slug})`);
    console.log("Next steps:");
    console.log(`  node scripts/create-dock.js       # add docks`);
    console.log(`  node scripts/create-user.js       # add a franchise admin`);
  } catch (err) {
    console.error("Failed:", err.message);
    process.exit(1);
  } finally {
    await db.pool.end();
  }
})();
