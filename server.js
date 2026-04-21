// -----------------------------------------------------------------
//  Reservation SMS Confirmation Server
//  Express + Twilio integration for two-way SMS confirmations
//  Postgres-backed: append-only reservations, phone-keyed conversations
// -----------------------------------------------------------------

require("dotenv").config();
const express = require("express");
const cors = require("cors");
const twilio = require("twilio");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const session = require("express-session");
const crypto = require("crypto");
const path = require("path");
const db = require("./db");

const app = express();
app.set("trust proxy", 1);
const PORT = process.env.PORT || 3001;
const isProduction = process.env.NODE_ENV === "production";

// --- Admin Password ---
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "fbc-admin-2024";

// --- Twilio Client ---
const accountSid = process.env.TWILIO_ACCOUNT_SID;
const authToken = process.env.TWILIO_AUTH_TOKEN;
const twilioPhone = process.env.TWILIO_PHONE_NUMBER;
const messagingServiceSid = process.env.TWILIO_MESSAGING_SERVICE_SID;
const baseUrl = (process.env.BASE_URL || "").replace(/\/+$/, "");
const client = twilio(accountSid, authToken);

// --- Phone Number Normalization (E.164) ---
function normalizePhone(phone) {
  if (!phone) return "";
  let digits = phone.replace(/\D/g, "");
  if (digits.length === 10) return `+1${digits}`;
  if (digits.length === 11 && digits.startsWith("1")) return `+${digits}`;
  if (phone.startsWith("+")) return phone.replace(/[^\d+]/g, "");
  return `+${digits}`;
}

function last10(phone) {
  return (phone || "").replace(/\D/g, "").slice(-10);
}

// --- Middleware ---
app.use(helmet({ contentSecurityPolicy: false }));

const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many requests, please try again later" },
});
app.use(globalLimiter);

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many login attempts, please try again later" },
});

const allowedOrigins = process.env.CORS_ORIGINS
  ? process.env.CORS_ORIGINS.split(",").map((s) => s.trim())
  : [];

app.use(cors({
  origin: allowedOrigins.length > 0
    ? (origin, callback) => {
        if (!origin || allowedOrigins.includes(origin)) callback(null, true);
        else callback(new Error("Not allowed by CORS"));
      }
    : false,
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
  credentials: true,
}));

app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true, limit: "1mb" }));

app.use(session({
  secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex"),
  resave: false,
  saveUninitialized: false,
  name: "fbc.rsms.sid",
  cookie: {
    httpOnly: true,
    secure: isProduction,
    sameSite: "strict",
    maxAge: 8 * 60 * 60 * 1000,
  },
}));

function requireAuth(req, res, next) {
  if (req.session && req.session.authenticated) return next();
  return res.status(401).json({ error: "Authentication required" });
}

// --- Auth ---
app.post("/api/login", loginLimiter, (req, res) => {
  const { password } = req.body;
  if (!password) return res.status(400).json({ error: "Password is required" });
  if (password === ADMIN_PASSWORD) {
    req.session.authenticated = true;
    req.session.loginTime = new Date().toISOString();
    return res.json({ success: true });
  }
  return res.status(401).json({ error: "Invalid password" });
});

app.post("/api/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) return res.status(500).json({ error: "Failed to logout" });
    res.clearCookie("fbc.rsms.sid");
    return res.json({ success: true });
  });
});

app.get("/api/session", (req, res) => {
  res.json({ authenticated: !!(req.session && req.session.authenticated) });
});

// --- Twilio Webhook Validation ---
const twilioWebhookValidation = twilio.webhook({ validate: isProduction });

// Root
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// --- Dock Locations ---
const DOCKS = [
  { id: "jax-beach", name: "Jacksonville Beach" },
  { id: "julington-east", name: "Julington Creek East" },
  { id: "julington-west", name: "Julington Creek West" },
  { id: "camachee-cove", name: "St. Augustine -- Camachee Cove" },
  { id: "shipyard", name: "St. Augustine -- Shipyard" },
];
const DOCK_IDS = new Set(DOCKS.map((d) => d.id));

app.get("/api/docks", requireAuth, (req, res) => {
  res.json({ docks: DOCKS });
});

// --- Member upsert helper ---
async function upsertMember(dbClient, phone, name, email) {
  if (!phone) return;
  await dbClient.query(
    `INSERT INTO members (phone, name, email)
     VALUES ($1, $2, $3)
     ON CONFLICT (phone) DO UPDATE
       SET name = COALESCE(EXCLUDED.name, members.name),
           email = COALESCE(NULLIF(EXCLUDED.email, ''), members.email),
           last_seen = NOW()`,
    [phone, name || null, email || null]
  );
}

// --- Find the most recent reservation for a phone (for inbound routing) ---
async function findReservationByPhone(phone) {
  const tail = last10(phone);
  if (!tail) return null;
  const { rows } = await db.query(
    `SELECT * FROM reservations
     WHERE RIGHT(REGEXP_REPLACE(phone, '\\D', '', 'g'), 10) = $1
     ORDER BY reservation_date DESC NULLS LAST, created_at DESC
     LIMIT 1`,
    [tail]
  );
  return rows[0] || null;
}

// --- Reservation row shape (for dashboard compatibility) ---
function rowToReservation(r) {
  return {
    id: r.id,
    name: r.name || "",
    email: r.email || "",
    phone: r.phone || "",
    service: r.service || "Reservation",
    date: r.reservation_date,
    guests: r.guests || 1,
    status: r.status || "unconfirmed",
    channel: r.channel || "sms",
    notes: r.notes || "",
    messageSent: !!r.message_sent,
    messageTime: r.message_time,
    timeUpdated: !!r.time_updated,
    originalTime: r.original_time,
    dock: r.dock_id,
    sourceId: r.source_id,
  };
}

// --- GET /api/reservations?dock=:id — active (latest batch) for a dock, with per-phone conversation attached ---
app.get("/api/reservations", requireAuth, async (req, res) => {
  const dockId = req.query.dock;
  if (!dockId || !DOCK_IDS.has(dockId)) {
    return res.status(400).json({ error: "Invalid or missing dock parameter", docks: [...DOCK_IDS] });
  }
  try {
    const { rows: reservations } = await db.query(
      `SELECT r.* FROM reservations r
       WHERE r.dock_id = $1
         AND r.import_batch_id = (
           SELECT MAX(id) FROM import_batches WHERE dock_id = $1
         )
       ORDER BY r.reservation_date ASC NULLS LAST`,
      [dockId]
    );

    // Fetch all messages for the phones on this dock in one query
    const phones = [...new Set(reservations.map((r) => r.phone).filter(Boolean))];
    let messagesByPhone = {};
    if (phones.length > 0) {
      const { rows: messages } = await db.query(
        `SELECT * FROM messages
         WHERE phone = ANY($1::text[])
         ORDER BY created_at ASC`,
        [phones]
      );
      for (const m of messages) {
        if (!messagesByPhone[m.phone]) messagesByPhone[m.phone] = [];
        messagesByPhone[m.phone].push({
          from: m.direction === "out" ? "system" : "member",
          text: m.body,
          time: m.created_at,
          twilioSid: m.twilio_sid,
          twilioStatus: m.twilio_status,
          reservationId: m.reservation_id,
        });
      }
    }

    const enriched = reservations.map((r) => ({
      ...rowToReservation(r),
      smsLog: messagesByPhone[r.phone] || [],
    }));
    res.json({ reservations: enriched, dock: dockId });
  } catch (err) {
    console.error("GET /api/reservations error:", err);
    res.status(500).json({ error: "Database error" });
  }
});

// --- POST /api/reservations/import?dock=:id — append-only ---
app.post("/api/reservations/import", requireAuth, async (req, res) => {
  const dockId = req.query.dock || req.body.dock;
  if (!dockId || !DOCK_IDS.has(dockId)) {
    return res.status(400).json({ error: "Invalid or missing dock parameter" });
  }
  const { data } = req.body;
  if (!Array.isArray(data) || data.length === 0) {
    return res.status(400).json({ error: "No reservation data provided" });
  }

  try {
    const result = await db.withTx(async (c) => {
      const { rows: [batch] } = await c.query(
        `INSERT INTO import_batches (dock_id, row_count) VALUES ($1, $2) RETURNING id`,
        [dockId, data.length]
      );
      const batchId = batch.id;
      const prefix = dockId.toUpperCase().slice(0, 3);

      for (let i = 0; i < data.length; i++) {
        const r = data[i];
        const sourceId = r.id || `${prefix}-${String(i + 1).padStart(3, "0")}`;
        const reservationId = `${prefix}-B${batchId}-${String(i + 1).padStart(3, "0")}`;
        const normalizedPhone = r.phone ? normalizePhone(r.phone) : "";

        if (normalizedPhone) {
          await upsertMember(c, normalizedPhone, r.name, r.email);
        }

        await c.query(
          `INSERT INTO reservations
           (id, import_batch_id, source_id, dock_id, phone, name, email, service,
            reservation_date, guests, status, channel, notes)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
          [
            reservationId,
            batchId,
            sourceId,
            dockId,
            normalizedPhone,
            r.name || `Guest ${i + 1}`,
            r.email || "",
            r.service || "Reservation",
            r.date || null,
            r.guests || 1,
            r.status || "unconfirmed",
            r.channel || "sms",
            r.notes || "",
          ]
        );
      }
      return { batchId, count: data.length };
    });

    res.json({ success: true, count: result.count, batchId: result.batchId, dock: dockId });
  } catch (err) {
    console.error("Import error:", err);
    res.status(500).json({ error: "Import failed", details: err.message });
  }
});

// --- POST /api/reservations/:id/status — update status ---
app.post("/api/reservations/:id/status", requireAuth, async (req, res) => {
  const { id } = req.params;
  const { status } = req.body;
  try {
    const { rows } = await db.query(
      `UPDATE reservations SET status = $1 WHERE id = $2 RETURNING *`,
      [status, id]
    );
    if (rows.length === 0) return res.status(404).json({ error: "Reservation not found" });
    res.json({ success: true, reservation: rowToReservation(rows[0]) });
  } catch (err) {
    console.error("Status update error:", err);
    res.status(500).json({ error: "Database error" });
  }
});

// --- SMS Sending ---
function buildSmsBody(reservation) {
  const dateObj = new Date(reservation.reservation_date || reservation.date);
  const dateStr = dateObj.toLocaleDateString("en-US", {
    weekday: "long", month: "long", day: "numeric",
  });
  const timeStr = dateObj.toLocaleTimeString("en-US", {
    hour: "numeric", minute: "2-digit",
  });
  const name = reservation.name || "there";
  return (
    `Hi ${name.split(" ")[0]}! ` +
    `This is a reminder about your upcoming ${reservation.service || "reservation"} ` +
    `on ${dateStr} at ${timeStr} for ${reservation.guests || 1} guest(s).\n\n` +
    `Reply:\n` +
    `• CONFIRM to confirm\n` +
    `• CANCEL to cancel\n` +
    `• TIME [new time] to update arrival (e.g. TIME 7:30 PM)`
  );
}

async function sendAndLogSms(reservationRow, customBody) {
  if (!reservationRow.phone) throw new Error("No phone number on file");
  const toPhone = normalizePhone(reservationRow.phone);
  if (!toPhone || toPhone.length < 10) throw new Error("Invalid phone number format");

  const body = customBody || buildSmsBody(reservationRow);

  const message = await client.messages.create({
    body,
    ...(messagingServiceSid ? { messagingServiceSid } : { from: twilioPhone }),
    to: toPhone,
    statusCallback: baseUrl ? `${baseUrl}/api/sms/status` : undefined,
  });

  await db.withTx(async (c) => {
    await c.query(
      `INSERT INTO messages (phone, reservation_id, dock_id, direction, body, twilio_sid, twilio_status)
       VALUES ($1, $2, $3, 'out', $4, $5, $6)`,
      [toPhone, reservationRow.id, reservationRow.dock_id, body, message.sid, message.status]
    );
    await c.query(
      `UPDATE reservations
       SET message_sent = TRUE,
           message_time = NOW(),
           status = CASE WHEN status = 'unconfirmed' THEN 'pending' ELSE status END
       WHERE id = $1`,
      [reservationRow.id]
    );
    await upsertMember(c, toPhone, reservationRow.name, reservationRow.email);
  });

  return message;
}

// POST /api/sms/send/:id
app.post("/api/sms/send/:id", requireAuth, async (req, res) => {
  const { id } = req.params;
  const { customBody } = req.body || {};
  try {
    const { rows } = await db.query(`SELECT * FROM reservations WHERE id = $1`, [id]);
    if (rows.length === 0) return res.status(404).json({ error: "Reservation not found" });
    const message = await sendAndLogSms(rows[0], customBody);
    const { rows: updated } = await db.query(`SELECT * FROM reservations WHERE id = $1`, [id]);
    res.json({ success: true, messageSid: message.sid, reservation: rowToReservation(updated[0]) });
  } catch (err) {
    console.error("Send SMS error:", err.message);
    res.status(500).json({ error: "Failed to send SMS", details: err.message });
  }
});

// POST /api/sms/send-bulk
app.post("/api/sms/send-bulk", requireAuth, async (req, res) => {
  const { ids, dock: dockId } = req.body;
  if (!dockId || !DOCK_IDS.has(dockId)) {
    return res.status(400).json({ error: "Invalid or missing dock parameter" });
  }

  let targets;
  try {
    if (ids === "all") {
      const { rows } = await db.query(
        `SELECT * FROM reservations
         WHERE dock_id = $1
           AND import_batch_id = (SELECT MAX(id) FROM import_batches WHERE dock_id = $1)
           AND message_sent = FALSE
           AND phone <> ''`,
        [dockId]
      );
      targets = rows;
    } else if (Array.isArray(ids)) {
      const { rows } = await db.query(
        `SELECT * FROM reservations
         WHERE id = ANY($1::text[]) AND message_sent = FALSE AND phone <> ''`,
        [ids]
      );
      targets = rows;
    } else {
      return res.status(400).json({ error: "Provide ids array or 'all'" });
    }
  } catch (err) {
    console.error("Bulk target query error:", err);
    return res.status(500).json({ error: "Database error" });
  }

  const results = { sent: 0, failed: 0, errors: [] };
  for (const r of targets) {
    try {
      await sendAndLogSms(r);
      results.sent++;
    } catch (err) {
      console.error(`SMS failed for ${r.id}:`, err.message);
      results.failed++;
      results.errors.push({ id: r.id, error: err.message });
    }
  }
  res.json({ success: true, ...results });
});

// --- Twilio Webhooks ---

// POST /api/sms/incoming
app.post("/api/sms/incoming", twilioWebhookValidation, async (req, res) => {
  const { From, Body } = req.body;
  const inboundText = (Body || "").trim();
  const normalizedFrom = normalizePhone(From);

  let responseText;
  try {
    const reservation = await findReservationByPhone(From);

    // Log inbound message (always, even if no reservation found — so replies
    // from a stale phone still appear in the conversation history)
    await db.query(
      `INSERT INTO messages (phone, reservation_id, dock_id, direction, body)
       VALUES ($1, $2, $3, 'in', $4)`,
      [normalizedFrom, reservation ? reservation.id : null, reservation ? reservation.dock_id : null, inboundText]
    );
    await db.withTx(async (c) => {
      await upsertMember(c, normalizedFrom, reservation ? reservation.name : null, null);
    });

    if (!reservation) {
      responseText =
        "Sorry, we couldn't find a reservation associated with this number. " +
        "Please call us directly for assistance.";
    } else {
      const replyLower = inboundText.toLowerCase();
      if (replyLower === "confirm" || replyLower === "yes" || replyLower === "c") {
        await db.query(`UPDATE reservations SET status = 'confirmed' WHERE id = $1`, [reservation.id]);
        responseText = "Thank you! Your reservation is confirmed. We look forward to seeing you!";
      } else if (replyLower === "cancel" || replyLower === "no") {
        await db.query(`UPDATE reservations SET status = 'cancelled' WHERE id = $1`, [reservation.id]);
        responseText = "Your reservation has been cancelled. If you change your mind, please call us to rebook.";
      } else {
        const timeMatch = replyLower.match(/^time\s+(\d{1,2}):?(\d{2})?\s*(am|pm)?$/i);
        if (timeMatch) {
          let h = parseInt(timeMatch[1]);
          const m = parseInt(timeMatch[2] || "0");
          const ampm = timeMatch[3];
          if (ampm && ampm.toLowerCase() === "pm" && h < 12) h += 12;
          if (ampm && ampm.toLowerCase() === "am" && h === 12) h = 0;

          const dateObj = new Date(reservation.reservation_date);
          const originalTime = reservation.original_time || reservation.reservation_date;
          dateObj.setHours(h, m, 0, 0);
          await db.query(
            `UPDATE reservations
             SET reservation_date = $1, time_updated = TRUE,
                 original_time = COALESCE(original_time, $2)
             WHERE id = $3`,
            [dateObj.toISOString(), originalTime, reservation.id]
          );
          const newTimeStr = dateObj.toLocaleTimeString("en-US", { hour: "numeric", minute: "2-digit" });
          responseText =
            `Got it! Your arrival time has been updated to ${newTimeStr}. ` +
            `Please reply CONFIRM to finalize your reservation.`;
        } else {
          responseText =
            "Sorry, I didn't understand that. Please reply:\n" +
            "• CONFIRM to confirm\n" +
            "• CANCEL to cancel\n" +
            "• TIME [new time] to change arrival (e.g. TIME 7:30 PM)";
        }
      }
    }

    // Log the outbound reply
    await db.query(
      `INSERT INTO messages (phone, reservation_id, dock_id, direction, body)
       VALUES ($1, $2, $3, 'out', $4)`,
      [normalizedFrom, reservation ? reservation.id : null, reservation ? reservation.dock_id : null, responseText]
    );
  } catch (err) {
    console.error("Inbound webhook error:", err);
    responseText = "We received your message but something went wrong on our end. Please try again shortly.";
  }

  const twiml = new twilio.twiml.MessagingResponse();
  twiml.message(responseText);
  res.type("text/xml").send(twiml.toString());
});

// POST /api/sms/status
app.post("/api/sms/status", twilioWebhookValidation, async (req, res) => {
  const { MessageSid, MessageStatus } = req.body;
  try {
    await db.query(
      `UPDATE messages SET twilio_status = $1 WHERE twilio_sid = $2`,
      [MessageStatus, MessageSid]
    );
  } catch (err) {
    console.error("Status callback error:", err);
  }
  res.sendStatus(200);
});

// --- Conversations ---

// GET /api/sms/log/:id?dock=:id — backwards-compatible per-reservation view,
// but returns the full PHONE conversation so the drawer shows all history
app.get("/api/sms/log/:id", requireAuth, async (req, res) => {
  const { id } = req.params;
  try {
    const { rows } = await db.query(`SELECT * FROM reservations WHERE id = $1`, [id]);
    if (rows.length === 0) return res.status(404).json({ error: "Reservation not found" });
    const reservation = rows[0];

    const { rows: messages } = await db.query(
      `SELECT * FROM messages WHERE phone = $1 ORDER BY created_at ASC`,
      [reservation.phone]
    );
    res.json({
      reservation: rowToReservation(reservation),
      smsLog: messages.map((m) => ({
        from: m.direction === "out" ? "system" : "member",
        text: m.body,
        time: m.created_at,
        twilioSid: m.twilio_sid,
        twilioStatus: m.twilio_status,
        reservationId: m.reservation_id,
      })),
    });
  } catch (err) {
    console.error("SMS log fetch error:", err);
    res.status(500).json({ error: "Database error" });
  }
});

// GET /api/conversations — list every member with a message history
app.get("/api/conversations", requireAuth, async (req, res) => {
  try {
    const { rows } = await db.query(
      `SELECT
         m.phone,
         COALESCE(mem.name, r_last.name) AS name,
         mem.email,
         COUNT(*)::int AS message_count,
         MAX(m.created_at) AS last_message_at,
         (ARRAY_AGG(m.body ORDER BY m.created_at DESC))[1] AS last_message_body,
         (ARRAY_AGG(m.direction ORDER BY m.created_at DESC))[1] AS last_direction,
         (ARRAY_AGG(m.dock_id ORDER BY m.created_at DESC))[1] AS last_dock_id
       FROM messages m
       LEFT JOIN members mem ON mem.phone = m.phone
       LEFT JOIN LATERAL (
         SELECT name FROM reservations r
         WHERE r.phone = m.phone
         ORDER BY r.created_at DESC LIMIT 1
       ) r_last ON TRUE
       GROUP BY m.phone, mem.name, mem.email, r_last.name
       ORDER BY MAX(m.created_at) DESC`
    );
    res.json({ conversations: rows });
  } catch (err) {
    console.error("Conversations list error:", err);
    res.status(500).json({ error: "Database error" });
  }
});

// GET /api/conversations/:phone — full timeline + reservation history
app.get("/api/conversations/:phone", requireAuth, async (req, res) => {
  const phone = normalizePhone(req.params.phone);
  try {
    const [{ rows: member }, { rows: messages }, { rows: reservations }] = await Promise.all([
      db.query(`SELECT * FROM members WHERE phone = $1`, [phone]),
      db.query(`SELECT * FROM messages WHERE phone = $1 ORDER BY created_at ASC`, [phone]),
      db.query(
        `SELECT * FROM reservations WHERE phone = $1 ORDER BY reservation_date DESC NULLS LAST`,
        [phone]
      ),
    ]);
    res.json({
      phone,
      member: member[0] || null,
      messages: messages.map((m) => ({
        from: m.direction === "out" ? "system" : "member",
        text: m.body,
        time: m.created_at,
        reservationId: m.reservation_id,
        dockId: m.dock_id,
        twilioSid: m.twilio_sid,
        twilioStatus: m.twilio_status,
      })),
      reservations: reservations.map(rowToReservation),
    });
  } catch (err) {
    console.error("Conversation fetch error:", err);
    res.status(500).json({ error: "Database error" });
  }
});

// --- Health ---
app.get("/api/health", (req, res) => {
  res.json({
    status: "ok",
    twilioConfigured: !!(accountSid && authToken && twilioPhone),
  });
});

// --- Static ---
app.use(express.static(path.join(__dirname, "public")));
app.get("/dashboard", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// --- Start ---
async function start() {
  try {
    await db.initSchema();
  } catch (err) {
    console.error("Schema init failed:", err.message);
    if (isProduction) process.exit(1);
  }
  app.listen(PORT, () => {
    console.log(`\nReservation SMS server running on port ${PORT}`);
    console.log(`   Health check: http://localhost:${PORT}/api/health`);
    if (!accountSid || !authToken || !twilioPhone) {
      console.log(`\n   Twilio credentials not configured!`);
      console.log(`   Copy env.example.txt to .env and add your credentials.\n`);
    } else {
      console.log(`   Twilio phone: ${twilioPhone}`);
      if (messagingServiceSid) console.log(`   Messaging Service: ${messagingServiceSid}`);
      console.log(`   Webhook URL:  ${baseUrl || "http://localhost:" + PORT}/api/sms/incoming\n`);
    }
  });
}

start();
