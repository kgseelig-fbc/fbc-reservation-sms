// One-off diagnostic: dump a specific import batch's reservations, or the
// most recent batch when no id is supplied.
// Usage:
//   railway run --service=Postgres node scripts/_inspect_last_batch.js
//   railway run --service=Postgres node scripts/_inspect_last_batch.js 1
const { Client } = require("pg");

(async () => {
  const url = process.env.DATABASE_PUBLIC_URL || process.env.DATABASE_URL;
  const client = new Client({ connectionString: url, ssl: { rejectUnauthorized: false } });
  await client.connect();

  const requestedBatch = process.argv[2] ? parseInt(process.argv[2], 10) : null;

  const { rows: batches } = await client.query(
    `SELECT id, franchise_id, dock_id, row_count, imported_at
     FROM import_batches ORDER BY imported_at DESC LIMIT 5`
  );
  console.log("=== 5 most recent import batches ===");
  console.table(batches);
  if (batches.length === 0) { await client.end(); return; }

  const targetId = requestedBatch ?? batches[0].id;
  const target = batches.find((b) => b.id === targetId) || batches[0];

  const { rows: reservations } = await client.query(
    `SELECT id, dock_id, name, phone, member_mobile, contact_mobile,
            contact_phone, contact_home_phone, status, message_sent,
            created_at
     FROM reservations
     WHERE import_batch_id = $1
     ORDER BY created_at ASC`,
    [target.id]
  );
  console.log(`\n=== Batch ${target.id} (dock=${target.dock_id}, ${reservations.length} rows) ===`);
  console.table(reservations.map((r) => ({
    id: r.id,
    name: r.name,
    phone: r.phone || "(empty)",
    member_mobile: r.member_mobile || "",
    contact_mobile: r.contact_mobile || "",
    contact_phone: r.contact_phone || "",
    contact_home: r.contact_home_phone || "",
    status: r.status,
    msg_sent: r.message_sent,
  })));

  const empty = reservations.filter((r) => !r.phone).length;
  const sent = reservations.filter((r) => r.message_sent).length;
  console.log(`\nSummary: ${reservations.length} total, ${empty} with empty phone, ${sent} marked message_sent`);

  await client.end();
})().catch((err) => {
  console.error("Query failed:", err.message);
  process.exit(1);
});
