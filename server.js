// -----------------------------------------------------------------
//  Reservation SMS Confirmation Server — Multi-Tenant
//  Express + Twilio, Postgres-backed, row-level isolation by franchise_id.
// -----------------------------------------------------------------

require("dotenv").config();
const express = require("express");
const cors = require("cors");
const twilio = require("twilio");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const path = require("path");
const db = require("./db");

const app = express();
app.set("trust proxy", 1);
const PORT = process.env.PORT || 3001;
const isProduction = process.env.NODE_ENV === "production";

// --- Phone normalization ---
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

// --- Security / middleware ---
app.use(helmet({ contentSecurityPolicy: false }));

const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 500,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many requests, please try again later" },
});
app.use(globalLimiter);

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many login attempts, please try again later" },
});

const allowedOrigins = process.env.CORS_ORIGINS
  ? process.env.CORS_ORIGINS.split(",").map((s) => s.trim())
  : [];
app.use(cors({
  origin: allowedOrigins.length > 0
    ? (origin, cb) => (!origin || allowedOrigins.includes(origin)) ? cb(null, true) : cb(new Error("Not allowed by CORS"))
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

// --- Franchise / user helpers ---
const franchiseCache = new Map(); // id -> franchise row
const twilioClientCache = new Map(); // franchise id -> twilio client

async function loadFranchise(id) {
  if (!id) return null;
  if (franchiseCache.has(id)) return franchiseCache.get(id);
  const { rows } = await db.query(`SELECT * FROM franchises WHERE id = $1`, [id]);
  if (rows.length === 0) return null;
  franchiseCache.set(id, rows[0]);
  return rows[0];
}
function invalidateFranchise(id) {
  franchiseCache.delete(id);
  twilioClientCache.delete(id);
}

function getTwilioClient(franchise) {
  if (!franchise || !franchise.twilio_account_sid || !franchise.twilio_auth_token) return null;
  let client = twilioClientCache.get(franchise.id);
  if (!client) {
    client = twilio(franchise.twilio_account_sid, franchise.twilio_auth_token);
    twilioClientCache.set(franchise.id, client);
  }
  return client;
}

async function findFranchiseByInboundTo(toNumber) {
  const normalized = normalizePhone(toNumber);
  const { rows } = await db.query(
    `SELECT * FROM franchises WHERE twilio_phone_number = $1 LIMIT 1`,
    [normalized]
  );
  return rows[0] || null;
}

// --- Auth middleware ---
function requireAuth(req, res, next) {
  if (!req.session || !req.session.userId) {
    return res.status(401).json({ error: "Authentication required" });
  }
  next();
}

// After auth. Ensures an active franchise is selected. Super-admins must pick
// one before touching tenant-scoped routes (via /api/admin/switch-franchise).
async function requireFranchiseContext(req, res, next) {
  const activeId = req.session.activeFranchiseId;
  if (!activeId) {
    return res.status(409).json({ error: "No active franchise selected", needsFranchiseSelection: true });
  }
  const franchise = await loadFranchise(activeId);
  if (!franchise) return res.status(404).json({ error: "Active franchise no longer exists" });
  req.franchise = franchise;
  req.franchiseId = franchise.id;
  next();
}

function requireSuperAdmin(req, res, next) {
  if (req.session.role !== "super_admin") return res.status(403).json({ error: "Super-admin only" });
  next();
}

// --- Auth routes ---
app.post("/api/login", loginLimiter, async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: "Email and password are required" });

  try {
    const { rows } = await db.query(
      `SELECT id, email, password_hash, role, franchise_id FROM users WHERE email = $1`,
      [email.toLowerCase().trim()]
    );
    const user = rows[0];
    const ok = user && await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: "Invalid email or password" });

    req.session.userId = user.id;
    req.session.email = user.email;
    req.session.role = user.role;
    req.session.franchiseId = user.franchise_id; // home franchise (null for super_admin)
    req.session.activeFranchiseId = user.franchise_id; // super_admin picks one via /api/admin/switch-franchise

    await db.query(`UPDATE users SET last_login = NOW() WHERE id = $1`, [user.id]);
    res.json({
      success: true,
      user: { email: user.email, role: user.role, franchiseId: user.franchise_id },
      needsFranchiseSelection: user.role === "super_admin",
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Login failed" });
  }
});

app.post("/api/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) return res.status(500).json({ error: "Failed to logout" });
    res.clearCookie("fbc.rsms.sid");
    res.json({ success: true });
  });
});

app.get("/api/session", (req, res) => {
  res.json({
    authenticated: !!(req.session && req.session.userId),
    email: req.session?.email || null,
    role: req.session?.role || null,
    needsFranchiseSelection: !!req.session?.userId && !req.session?.activeFranchiseId,
  });
});

// --- Forgot / reset password ---
const email = require("./lib/email");

const forgotLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5, // per IP
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many reset requests, please try again later" },
});

const resetLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
});

function hashToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

// Returns the public origin of this request so reset links point at the UI the
// user came from. Falls back to host header.
function originFromRequest(req) {
  const proto = (req.headers["x-forwarded-proto"] || req.protocol || "https").split(",")[0].trim();
  const host = req.headers["x-forwarded-host"] || req.get("host");
  return `${proto}://${host}`;
}

// POST /api/forgot-password — always returns 200 to avoid leaking which emails
// are registered. If the email exists, a one-hour token is emailed.
app.post("/api/forgot-password", forgotLimiter, async (req, res) => {
  const email_ = (req.body?.email || "").toLowerCase().trim();
  if (!email_) return res.status(400).json({ error: "Email is required" });

  const genericOk = { success: true, message: "If an account exists for that email, a reset link has been sent." };

  try {
    const { rows } = await db.query(
      `SELECT id, email FROM users WHERE email = $1`,
      [email_]
    );
    const user = rows[0];
    if (!user) return res.json(genericOk);

    // Invalidate any prior unused tokens for this user (optional — limits blast radius).
    await db.query(
      `UPDATE password_resets SET used_at = NOW()
       WHERE user_id = $1 AND used_at IS NULL AND expires_at > NOW()`,
      [user.id]
    );

    const rawToken = crypto.randomBytes(32).toString("hex");
    const tokenHash = hashToken(rawToken);
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

    await db.query(
      `INSERT INTO password_resets (user_id, token_hash, expires_at) VALUES ($1, $2, $3)`,
      [user.id, tokenHash, expiresAt]
    );

    const origin = originFromRequest(req);
    const resetUrl = `${origin}/?reset=${rawToken}`;
    const subject = "Reset your Reservation SMS Dashboard password";
    const text =
      `Someone requested a password reset for your account (${user.email}).\n\n` +
      `If that was you, click this link within 1 hour to set a new password:\n` +
      `${resetUrl}\n\n` +
      `If you didn't request this, you can ignore this email — your password stays the same.`;
    const html =
      `<p>Someone requested a password reset for your account (<strong>${user.email}</strong>).</p>` +
      `<p>If that was you, click the link below within 1 hour to set a new password:</p>` +
      `<p><a href="${resetUrl}" style="background:#0ea5e9;color:#fff;padding:10px 18px;border-radius:6px;text-decoration:none;display:inline-block;">Reset password</a></p>` +
      `<p style="font-size:12px;color:#666">Or copy this link: <br><code>${resetUrl}</code></p>` +
      `<p style="font-size:12px;color:#666">If you didn't request this, you can ignore this email — your password stays the same.</p>`;

    try {
      await email.sendEmail({ to: user.email, subject, text, html });
    } catch (mailErr) {
      console.error("Reset email send failed:", mailErr.message);
      // Don't reveal failure to the caller — the token is still valid and the
      // link is in server logs for manual recovery if SMTP is misconfigured.
    }

    res.json(genericOk);
  } catch (err) {
    console.error("Forgot-password error:", err);
    res.json(genericOk); // still return generic success shape
  }
});

// POST /api/reset-password — redeem a token, set new password.
app.post("/api/reset-password", resetLimiter, async (req, res) => {
  const { token, password } = req.body || {};
  if (!token || !password) return res.status(400).json({ error: "Token and password are required" });
  if (password.length < 8) return res.status(400).json({ error: "Password must be at least 8 characters" });

  try {
    const tokenHash = hashToken(token);
    const { rows } = await db.query(
      `SELECT pr.id, pr.user_id, pr.expires_at, pr.used_at
       FROM password_resets pr
       WHERE pr.token_hash = $1`,
      [tokenHash]
    );
    const reset = rows[0];
    if (!reset) return res.status(400).json({ error: "Invalid or expired reset link" });
    if (reset.used_at) return res.status(400).json({ error: "This reset link has already been used" });
    if (new Date(reset.expires_at) < new Date()) return res.status(400).json({ error: "This reset link has expired" });

    const hash = await bcrypt.hash(password, 12);
    await db.withTx(async (c) => {
      await c.query(`UPDATE users SET password_hash = $1 WHERE id = $2`, [hash, reset.user_id]);
      await c.query(`UPDATE password_resets SET used_at = NOW() WHERE id = $1`, [reset.id]);
    });

    res.json({ success: true });
  } catch (err) {
    console.error("Reset-password error:", err);
    res.status(500).json({ error: "Failed to reset password" });
  }
});

// GET /api/me — current user, active franchise, dock list, branding
app.get("/api/me", requireAuth, async (req, res) => {
  try {
    const activeId = req.session.activeFranchiseId;
    let franchise = null;
    let docks = [];
    if (activeId) {
      franchise = await loadFranchise(activeId);
      if (franchise) {
        const { rows } = await db.query(
          `SELECT id, name, sort_order FROM docks WHERE franchise_id = $1 ORDER BY sort_order ASC, name ASC`,
          [franchise.id]
        );
        docks = rows;
      }
    }
    res.json({
      user: { email: req.session.email, role: req.session.role, franchiseId: req.session.franchiseId },
      franchise: franchise && {
        id: franchise.id, slug: franchise.slug, name: franchise.name,
        timezone: franchise.timezone, logoUrl: franchise.logo_url,
        brandColor: franchise.brand_color,
        twilioConfigured: !!(franchise.twilio_account_sid && franchise.twilio_auth_token),
      },
      docks,
    });
  } catch (err) {
    console.error("/api/me error:", err);
    res.status(500).json({ error: "Failed to load profile" });
  }
});

// --- Super-admin: franchise switcher ---
app.get("/api/admin/franchises", requireAuth, requireSuperAdmin, async (req, res) => {
  const { rows } = await db.query(
    `SELECT id, slug, name, timezone,
            twilio_phone_number,
            (twilio_auth_token IS NOT NULL) AS twilio_configured,
            created_at
     FROM franchises ORDER BY name ASC`
  );
  res.json({ franchises: rows });
});

app.post("/api/admin/switch-franchise", requireAuth, requireSuperAdmin, async (req, res) => {
  const { franchiseId } = req.body || {};
  if (!franchiseId) return res.status(400).json({ error: "franchiseId required" });
  const franchise = await loadFranchise(franchiseId);
  if (!franchise) return res.status(404).json({ error: "Franchise not found" });
  req.session.activeFranchiseId = franchise.id;
  res.json({ success: true, franchise: { id: franchise.id, slug: franchise.slug, name: franchise.name } });
});

// --- Docks (scoped) ---
app.get("/api/docks", requireAuth, requireFranchiseContext, async (req, res) => {
  const { rows } = await db.query(
    `SELECT id, name, sort_order FROM docks WHERE franchise_id = $1 ORDER BY sort_order ASC, name ASC`,
    [req.franchiseId]
  );
  res.json({ docks: rows });
});

// --- Member helpers ---
async function upsertMember(client, franchiseId, phone, name, email) {
  if (!phone) return;
  await client.query(
    `INSERT INTO members (franchise_id, phone, name, email)
     VALUES ($1, $2, $3, $4)
     ON CONFLICT (franchise_id, phone) DO UPDATE
       SET name = COALESCE(EXCLUDED.name, members.name),
           email = COALESCE(NULLIF(EXCLUDED.email, ''), members.email),
           last_seen = NOW()`,
    [franchiseId, phone, name || null, email || null]
  );
}

// Visiting-member lookup: same phone on OTHER franchises. Returns null if
// the phone is only known to the active franchise.
async function findHomeFranchises(activeFranchiseId, phone) {
  if (!phone) return [];
  const { rows } = await db.query(
    `SELECT f.id, f.name, f.slug, m.first_seen
     FROM members m
     JOIN franchises f ON f.id = m.franchise_id
     WHERE m.phone = $1 AND m.franchise_id <> $2
     ORDER BY m.first_seen ASC`,
    [phone, activeFranchiseId]
  );
  return rows;
}

async function findReservationByPhoneInFranchise(franchiseId, phone) {
  const tail = last10(phone);
  if (!tail || !franchiseId) return null;
  const { rows } = await db.query(
    `SELECT * FROM reservations
     WHERE franchise_id = $1
       AND RIGHT(REGEXP_REPLACE(phone, '\\D', '', 'g'), 10) = $2
     ORDER BY reservation_date DESC NULLS LAST, created_at DESC
     LIMIT 1`,
    [franchiseId, tail]
  );
  return rows[0] || null;
}

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
    franchiseId: r.franchise_id,
  };
}

// --- Reservations ---
app.get("/api/reservations", requireAuth, requireFranchiseContext, async (req, res) => {
  const dockId = req.query.dock;
  if (!dockId) return res.status(400).json({ error: "Missing dock parameter" });

  try {
    // Confirm dock belongs to active franchise
    const { rows: dockRows } = await db.query(
      `SELECT id FROM docks WHERE id = $1 AND franchise_id = $2`,
      [dockId, req.franchiseId]
    );
    if (dockRows.length === 0) return res.status(404).json({ error: "Dock not found for this franchise" });

    const { rows: reservations } = await db.query(
      `SELECT * FROM reservations
       WHERE franchise_id = $1 AND dock_id = $2
         AND import_batch_id = (
           SELECT MAX(id) FROM import_batches WHERE franchise_id = $1 AND dock_id = $2
         )
       ORDER BY reservation_date ASC NULLS LAST`,
      [req.franchiseId, dockId]
    );

    const phones = [...new Set(reservations.map((r) => r.phone).filter(Boolean))];
    let messagesByPhone = {};
    let visitingByPhone = {};

    if (phones.length > 0) {
      const { rows: messages } = await db.query(
        `SELECT * FROM messages
         WHERE franchise_id = $1 AND phone = ANY($2::text[])
         ORDER BY created_at ASC`,
        [req.franchiseId, phones]
      );
      for (const m of messages) {
        (messagesByPhone[m.phone] = messagesByPhone[m.phone] || []).push({
          from: m.direction === "out" ? "system" : "member",
          text: m.body,
          time: m.created_at,
          twilioSid: m.twilio_sid,
          twilioStatus: m.twilio_status,
          reservationId: m.reservation_id,
        });
      }

      // Visiting-member lookup: same phone registered under other franchises
      const { rows: visits } = await db.query(
        `SELECT m.phone, f.id AS f_id, f.name AS f_name, f.slug AS f_slug
         FROM members m
         JOIN franchises f ON f.id = m.franchise_id
         WHERE m.phone = ANY($1::text[]) AND m.franchise_id <> $2`,
        [phones, req.franchiseId]
      );
      for (const v of visits) {
        (visitingByPhone[v.phone] = visitingByPhone[v.phone] || []).push({
          id: v.f_id, name: v.f_name, slug: v.f_slug,
        });
      }
    }

    const enriched = reservations.map((r) => ({
      ...rowToReservation(r),
      smsLog: messagesByPhone[r.phone] || [],
      homeFranchises: visitingByPhone[r.phone] || [],
    }));

    res.json({ reservations: enriched, dock: dockId });
  } catch (err) {
    console.error("GET /api/reservations error:", err);
    res.status(500).json({ error: "Database error" });
  }
});

app.post("/api/reservations/import", requireAuth, requireFranchiseContext, async (req, res) => {
  const dockId = req.query.dock || req.body.dock;
  if (!dockId) return res.status(400).json({ error: "Missing dock parameter" });

  try {
    const { rows: dockRows } = await db.query(
      `SELECT id FROM docks WHERE id = $1 AND franchise_id = $2`,
      [dockId, req.franchiseId]
    );
    if (dockRows.length === 0) return res.status(404).json({ error: "Dock not found for this franchise" });
  } catch (err) {
    console.error("Dock check error:", err);
    return res.status(500).json({ error: "Database error" });
  }

  const { data } = req.body;
  if (!Array.isArray(data) || data.length === 0) {
    return res.status(400).json({ error: "No reservation data provided" });
  }

  try {
    const result = await db.withTx(async (c) => {
      const { rows: [batch] } = await c.query(
        `INSERT INTO import_batches (franchise_id, dock_id, row_count) VALUES ($1,$2,$3) RETURNING id`,
        [req.franchiseId, dockId, data.length]
      );
      const batchId = batch.id;
      const prefix = dockId.toUpperCase().slice(0, 3);

      for (let i = 0; i < data.length; i++) {
        const r = data[i];
        const sourceId = r.id || `${prefix}-${String(i + 1).padStart(3, "0")}`;
        const reservationId = `F${req.franchiseId}-${prefix}-B${batchId}-${String(i + 1).padStart(3, "0")}`;
        const normalizedPhone = r.phone ? normalizePhone(r.phone) : "";

        if (normalizedPhone) {
          await upsertMember(c, req.franchiseId, normalizedPhone, r.name, r.email);
        }

        await c.query(
          `INSERT INTO reservations
           (id, franchise_id, import_batch_id, source_id, dock_id, phone, name, email, service,
            reservation_date, guests, status, channel, notes)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
          [
            reservationId, req.franchiseId, batchId, sourceId, dockId, normalizedPhone,
            r.name || `Guest ${i + 1}`, r.email || "", r.service || "Reservation",
            r.date || null, r.guests || 1, r.status || "unconfirmed", r.channel || "sms", r.notes || "",
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

app.post("/api/reservations/:id/status", requireAuth, requireFranchiseContext, async (req, res) => {
  const { id } = req.params;
  const { status } = req.body;
  try {
    const { rows } = await db.query(
      `UPDATE reservations SET status = $1
       WHERE id = $2 AND franchise_id = $3
       RETURNING *`,
      [status, id, req.franchiseId]
    );
    if (rows.length === 0) return res.status(404).json({ error: "Reservation not found" });
    res.json({ success: true, reservation: rowToReservation(rows[0]) });
  } catch (err) {
    console.error("Status update error:", err);
    res.status(500).json({ error: "Database error" });
  }
});

// --- SMS building ---
function buildSmsBody(reservation) {
  const dateObj = new Date(reservation.reservation_date || reservation.date);
  const dateStr = dateObj.toLocaleDateString("en-US", { weekday: "long", month: "long", day: "numeric" });
  const timeStr = dateObj.toLocaleTimeString("en-US", { hour: "numeric", minute: "2-digit" });
  const name = reservation.name || "there";
  return (
    `Hi ${name.split(" ")[0]}! ` +
    `This is a reminder about your upcoming ${reservation.service || "reservation"} ` +
    `on ${dateStr} at ${timeStr} for ${reservation.guests || 1} guest(s).\n\n` +
    `Can you make it? Just reply YES to confirm, CANCEL to cancel, or send a new time (e.g. 7:30 AM) if you need to change your arrival.`
  );
}

async function sendAndLogSms(franchise, reservationRow, customBody) {
  const client = getTwilioClient(franchise);
  if (!client) throw new Error(`Twilio is not configured for ${franchise.name}`);
  if (!reservationRow.phone) throw new Error("No phone number on file");
  const toPhone = normalizePhone(reservationRow.phone);
  if (!toPhone || toPhone.length < 10) throw new Error("Invalid phone number format");

  const body = customBody || buildSmsBody(reservationRow);
  const statusCallback = franchise.base_url
    ? `${franchise.base_url.replace(/\/+$/, "")}/api/sms/status`
    : undefined;

  const message = await client.messages.create({
    body,
    ...(franchise.twilio_messaging_service_sid
      ? { messagingServiceSid: franchise.twilio_messaging_service_sid }
      : { from: franchise.twilio_phone_number }),
    to: toPhone,
    statusCallback,
  });

  await db.withTx(async (c) => {
    await c.query(
      `INSERT INTO messages (franchise_id, phone, reservation_id, dock_id, direction, body, twilio_sid, twilio_status)
       VALUES ($1,$2,$3,$4,'out',$5,$6,$7)`,
      [franchise.id, toPhone, reservationRow.id, reservationRow.dock_id, body, message.sid, message.status]
    );
    await c.query(
      `UPDATE reservations
       SET message_sent = TRUE,
           message_time = NOW(),
           status = CASE WHEN status = 'unconfirmed' THEN 'pending' ELSE status END
       WHERE id = $1`,
      [reservationRow.id]
    );
    await upsertMember(c, franchise.id, toPhone, reservationRow.name, reservationRow.email);
  });

  return message;
}

app.post("/api/sms/send/:id", requireAuth, requireFranchiseContext, async (req, res) => {
  const { id } = req.params;
  const { customBody } = req.body || {};
  try {
    const { rows } = await db.query(
      `SELECT * FROM reservations WHERE id = $1 AND franchise_id = $2`,
      [id, req.franchiseId]
    );
    if (rows.length === 0) return res.status(404).json({ error: "Reservation not found" });
    const message = await sendAndLogSms(req.franchise, rows[0], customBody);
    const { rows: updated } = await db.query(`SELECT * FROM reservations WHERE id = $1`, [id]);
    res.json({ success: true, messageSid: message.sid, reservation: rowToReservation(updated[0]) });
  } catch (err) {
    console.error("Twilio send error:", err.message);
    res.status(500).json({ error: `Failed to send SMS: ${err.message}`, details: err.message });
  }
});

app.post("/api/sms/send-bulk", requireAuth, requireFranchiseContext, async (req, res) => {
  const { ids, dock: dockId } = req.body;
  if (!dockId) return res.status(400).json({ error: "Missing dock parameter" });

  let targets;
  try {
    if (ids === "all") {
      const { rows } = await db.query(
        `SELECT * FROM reservations
         WHERE franchise_id = $1 AND dock_id = $2
           AND import_batch_id = (SELECT MAX(id) FROM import_batches WHERE franchise_id = $1 AND dock_id = $2)
           AND message_sent = FALSE AND phone <> ''`,
        [req.franchiseId, dockId]
      );
      targets = rows;
    } else if (Array.isArray(ids)) {
      const { rows } = await db.query(
        `SELECT * FROM reservations
         WHERE id = ANY($1::text[]) AND franchise_id = $2 AND message_sent = FALSE AND phone <> ''`,
        [ids, req.franchiseId]
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
      await sendAndLogSms(req.franchise, r);
      results.sent++;
    } catch (err) {
      console.error(`SMS failed for ${r.id}:`, err.message);
      results.failed++;
      results.errors.push({ id: r.id, error: err.message });
    }
  }
  res.json({ success: true, ...results });
});

// --- Admin chat box — send arbitrary SMS to a reservation's phone ---
app.post("/api/sms/simulate", requireAuth, requireFranchiseContext, async (req, res) => {
  const { id, reply } = req.body;
  if (!id || !reply) return res.status(400).json({ error: "Missing id or reply" });

  try {
    const { rows } = await db.query(
      `SELECT * FROM reservations WHERE id = $1 AND franchise_id = $2`,
      [id, req.franchiseId]
    );
    if (rows.length === 0) return res.status(404).json({ error: "Reservation not found" });
    const reservation = rows[0];
    if (!reservation.phone) return res.status(400).json({ error: "No phone number on file for this reservation" });

    const client = getTwilioClient(req.franchise);
    if (!client) return res.status(400).json({ error: `Twilio is not configured for ${req.franchise.name}` });

    const toPhone = normalizePhone(reservation.phone);
    if (!toPhone || toPhone.length < 10) return res.status(400).json({ error: "Invalid phone number format" });

    const message = await client.messages.create({
      body: reply,
      ...(req.franchise.twilio_messaging_service_sid
        ? { messagingServiceSid: req.franchise.twilio_messaging_service_sid }
        : { from: req.franchise.twilio_phone_number }),
      to: toPhone,
      statusCallback: req.franchise.base_url
        ? `${req.franchise.base_url.replace(/\/+$/, "")}/api/sms/status`
        : undefined,
    });

    await db.query(
      `INSERT INTO messages (franchise_id, phone, reservation_id, dock_id, direction, body, twilio_sid, twilio_status)
       VALUES ($1,$2,$3,$4,'out',$5,$6,$7)`,
      [req.franchiseId, toPhone, reservation.id, reservation.dock_id, reply, message.sid, message.status]
    );
    res.json({ success: true, messageSid: message.sid });
  } catch (err) {
    console.error("Twilio send error (chat):", err.message);
    res.status(500).json({ error: `Failed to send: ${err.message}` });
  }
});

// --- Inbound reply parsing (Postgres-native) ---
async function parseAndApplyReply(inboundText, reservation) {
  const replyLower = inboundText.toLowerCase().replace(/[^a-z0-9\s:]/g, "").trim();

  const confirmPatterns = /^(confirm|confirmed|yes|yep|yeah|yea|yup|y|c|ok|okay|sure|sounds good|good|great|absolutely|perfect|see you there|will be there|we will be there|ill be there|looking forward|affirmative)$/;
  const confirmLoose = /(confirm|yes|yep|yeah|yup|sounds good|okay|ok sure|absolutely|perfect|see you|will be there|looking forward|count me in|im in|we're in|all good|good to go)/;
  const cancelPatterns = /^(cancel|cancelled|no|nope|nah|n|cant make it|can not make it|cannot make it|wont be there|not coming|count me out|remove|pass)$/;
  const cancelLoose = /(cancel|cant make it|can not make it|cannot make it|wont be there|not coming|count me out|need to cancel|want to cancel|have to cancel|please cancel)/;
  const timeMatch = replyLower.match(
    /(?:time|change.*time|move.*to|reschedule.*to|change.*to|switch.*to|make it|new time)?\s*(\d{1,2}):?(\d{2})?\s*(am|pm)/i
  );

  if (!reservation) {
    return "Sorry, we couldn't find a reservation associated with this number. Please call us directly for assistance.";
  }

  if (confirmPatterns.test(replyLower) || confirmLoose.test(replyLower)) {
    await db.query(`UPDATE reservations SET status = 'confirmed' WHERE id = $1`, [reservation.id]);
    return "Thank you! Your reservation is confirmed. We look forward to seeing you!";
  }
  if (cancelPatterns.test(replyLower) || cancelLoose.test(replyLower)) {
    await db.query(`UPDATE reservations SET status = 'cancelled' WHERE id = $1`, [reservation.id]);
    return "Your reservation has been cancelled. If you change your mind, please call us to rebook.";
  }
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
    return `Got it! Your arrival time has been updated to ${newTimeStr}. Just reply YES to confirm your reservation.`;
  }

  return (
    "Sorry, I didn't quite catch that. You can reply:\n" +
    "• YES to confirm\n" +
    "• CANCEL to cancel\n" +
    "• A new time like \"7:30 AM\" to change your arrival"
  );
}

// --- Twilio inbound webhook ---
// Routes by the `To` number to the franchise, then validates the signature
// with THAT franchise's auth token before trusting the request.
app.post("/api/sms/incoming", express.urlencoded({ extended: false }), async (req, res) => {
  const { From, To, Body } = req.body;
  const franchise = await findFranchiseByInboundTo(To);

  if (!franchise) {
    console.warn(`Inbound SMS to unknown number: ${To}`);
    return res.status(404).send("Unknown recipient");
  }

  // Validate Twilio signature with this franchise's auth token, in prod only.
  if (isProduction && franchise.twilio_auth_token) {
    const signature = req.headers["x-twilio-signature"];
    const url = (franchise.base_url ? franchise.base_url.replace(/\/+$/, "") : "") + "/api/sms/incoming";
    const valid = twilio.validateRequest(franchise.twilio_auth_token, signature, url, req.body);
    if (!valid) {
      console.warn(`Invalid Twilio signature for franchise ${franchise.id}`);
      return res.status(403).send("Invalid signature");
    }
  }

  const inboundText = (Body || "").trim();
  const normalizedFrom = normalizePhone(From);

  let responseText;
  try {
    const reservation = await findReservationByPhoneInFranchise(franchise.id, From);

    await db.query(
      `INSERT INTO messages (franchise_id, phone, reservation_id, dock_id, direction, body)
       VALUES ($1,$2,$3,$4,'in',$5)`,
      [franchise.id, normalizedFrom, reservation ? reservation.id : null,
       reservation ? reservation.dock_id : null, inboundText]
    );
    await db.withTx(async (c) => {
      await upsertMember(c, franchise.id, normalizedFrom, reservation ? reservation.name : null, null);
    });

    responseText = await parseAndApplyReply(inboundText, reservation);

    await db.query(
      `INSERT INTO messages (franchise_id, phone, reservation_id, dock_id, direction, body)
       VALUES ($1,$2,$3,$4,'out',$5)`,
      [franchise.id, normalizedFrom, reservation ? reservation.id : null,
       reservation ? reservation.dock_id : null, responseText]
    );
  } catch (err) {
    console.error("Inbound webhook error:", err);
    responseText = "We received your message but something went wrong on our end. Please try again shortly.";
  }

  const twiml = new twilio.twiml.MessagingResponse();
  twiml.message(responseText);
  res.type("text/xml").send(twiml.toString());
});

// Delivery-status callback. We don't bother validating signature here — the
// worst case is a bogus status flag, and the SID is the join key anyway.
app.post("/api/sms/status", express.urlencoded({ extended: false }), async (req, res) => {
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

// --- Conversations (scoped) ---
app.get("/api/sms/log/:id", requireAuth, requireFranchiseContext, async (req, res) => {
  const { id } = req.params;
  try {
    const { rows } = await db.query(
      `SELECT * FROM reservations WHERE id = $1 AND franchise_id = $2`,
      [id, req.franchiseId]
    );
    if (rows.length === 0) return res.status(404).json({ error: "Reservation not found" });
    const reservation = rows[0];

    const { rows: messages } = await db.query(
      `SELECT * FROM messages WHERE franchise_id = $1 AND phone = $2 ORDER BY created_at ASC`,
      [req.franchiseId, reservation.phone]
    );
    const homeFranchises = await findHomeFranchises(req.franchiseId, reservation.phone);
    res.json({
      reservation: rowToReservation(reservation),
      homeFranchises,
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

app.get("/api/conversations", requireAuth, requireFranchiseContext, async (req, res) => {
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
       LEFT JOIN members mem ON mem.phone = m.phone AND mem.franchise_id = m.franchise_id
       LEFT JOIN LATERAL (
         SELECT name FROM reservations r
         WHERE r.phone = m.phone AND r.franchise_id = m.franchise_id
         ORDER BY r.created_at DESC LIMIT 1
       ) r_last ON TRUE
       WHERE m.franchise_id = $1
       GROUP BY m.phone, mem.name, mem.email, r_last.name
       ORDER BY MAX(m.created_at) DESC`,
      [req.franchiseId]
    );

    const phones = rows.map((r) => r.phone).filter(Boolean);
    let visiting = {};
    if (phones.length > 0) {
      const { rows: visits } = await db.query(
        `SELECT m.phone, f.id, f.name, f.slug
         FROM members m
         JOIN franchises f ON f.id = m.franchise_id
         WHERE m.phone = ANY($1::text[]) AND m.franchise_id <> $2`,
        [phones, req.franchiseId]
      );
      for (const v of visits) {
        (visiting[v.phone] = visiting[v.phone] || []).push({ id: v.id, name: v.name, slug: v.slug });
      }
    }

    res.json({
      conversations: rows.map((c) => ({ ...c, home_franchises: visiting[c.phone] || [] })),
    });
  } catch (err) {
    console.error("Conversations list error:", err);
    res.status(500).json({ error: "Database error" });
  }
});

app.get("/api/conversations/:phone", requireAuth, requireFranchiseContext, async (req, res) => {
  const phone = normalizePhone(req.params.phone);
  try {
    const [{ rows: member }, { rows: messages }, { rows: reservations }, homeFranchises] = await Promise.all([
      db.query(`SELECT * FROM members WHERE franchise_id = $1 AND phone = $2`, [req.franchiseId, phone]),
      db.query(`SELECT * FROM messages WHERE franchise_id = $1 AND phone = $2 ORDER BY created_at ASC`, [req.franchiseId, phone]),
      db.query(
        `SELECT * FROM reservations WHERE franchise_id = $1 AND phone = $2 ORDER BY reservation_date DESC NULLS LAST`,
        [req.franchiseId, phone]
      ),
      findHomeFranchises(req.franchiseId, phone),
    ]);
    res.json({
      phone,
      member: member[0] || null,
      homeFranchises,
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
  res.json({ status: "ok" });
});

// --- Root + static ---
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));
app.use(express.static(path.join(__dirname, "public")));
app.get("/dashboard", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));

// --- Start ---
async function start() {
  try {
    await db.initSchema();
  } catch (err) {
    console.error("Schema init failed:", err.message);
    if (isProduction) process.exit(1);
  }
  app.listen(PORT, () => {
    console.log(`\nReservation SMS (multi-tenant) running on port ${PORT}`);
    console.log(`   Health check: http://localhost:${PORT}/api/health`);
  });
}

start();
