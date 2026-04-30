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
const crypto = require("crypto");
const path = require("path");
const { OAuth2Client } = require("google-auth-library");
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
    // 'lax' (not 'strict') so the session cookie survives the top-level
    // redirect from accounts.google.com back to /api/auth/google/callback —
    // 'strict' drops the cookie on any cross-site navigation, breaking OAuth.
    sameSite: "lax",
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
  if (req.session.status && req.session.status !== "approved") {
    return res.status(403).json({ error: "Account pending approval", pendingApproval: true, status: req.session.status });
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

// Returns the public origin of this request so OAuth redirects point at the UI the
// user came from. Falls back to host header.
function originFromRequest(req) {
  const proto = (req.headers["x-forwarded-proto"] || req.protocol || "https").split(",")[0].trim();
  const host = req.headers["x-forwarded-host"] || req.get("host");
  return `${proto}://${host}`;
}

// --- Google OAuth ---
const googleClientId = process.env.GOOGLE_CLIENT_ID;
const googleClientSecret = process.env.GOOGLE_CLIENT_SECRET;

function googleRedirectUri(req) {
  if (process.env.GOOGLE_OAUTH_REDIRECT_URL) return process.env.GOOGLE_OAUTH_REDIRECT_URL;
  return `${originFromRequest(req)}/api/auth/google/callback`;
}

function googleOAuthClient(req) {
  if (!googleClientId || !googleClientSecret) return null;
  return new OAuth2Client(googleClientId, googleClientSecret, googleRedirectUri(req));
}

// Kick off the OAuth dance. We sign a CSRF state into the session so the
// callback can prove this exact browser started the flow.
app.get("/api/auth/google", loginLimiter, (req, res) => {
  const client = googleOAuthClient(req);
  if (!client) return res.status(500).json({ error: "Google SSO is not configured" });
  const state = crypto.randomBytes(24).toString("hex");
  req.session.oauthState = state;
  const url = client.generateAuthUrl({
    access_type: "online",
    prompt: "select_account",
    scope: ["openid", "email", "profile"],
    state,
  });
  res.redirect(url);
});

// Callback: verify the ID token, find-or-create the user, set session.
// Brand-new users land in status='pending' with no role/franchise — a
// super_admin must approve them before requireAuth lets them through.
app.get("/api/auth/google/callback", loginLimiter, async (req, res) => {
  const client = googleOAuthClient(req);
  if (!client) return res.status(500).send("Google SSO is not configured");
  const { code, state } = req.query;
  if (!code || !state || state !== req.session.oauthState) {
    return res.redirect("/?sso_error=state");
  }
  delete req.session.oauthState;

  try {
    const { tokens } = await client.getToken(code);
    const ticket = await client.verifyIdToken({ idToken: tokens.id_token, audience: googleClientId });
    const payload = ticket.getPayload();
    if (!payload || !payload.email) return res.redirect("/?sso_error=verify");
    if (!payload.email_verified) return res.redirect("/?sso_error=unverified");

    const email = payload.email.toLowerCase();
    const googleId = payload.sub;
    const fullName = payload.name || null;
    const avatarUrl = payload.picture || null;

    // Match on google_id first, then fall back to email so existing
    // pre-SSO accounts (e.g. the bootstrap super_admin) link cleanly.
    const { rows } = await db.query(
      `SELECT * FROM users WHERE google_id = $1 OR email = $2 ORDER BY (google_id IS NOT NULL) DESC LIMIT 1`,
      [googleId, email]
    );
    let user = rows[0];

    if (!user) {
      const inserted = await db.query(
        `INSERT INTO users (email, google_id, name, avatar_url, status)
         VALUES ($1, $2, $3, $4, 'pending')
         RETURNING *`,
        [email, googleId, fullName, avatarUrl]
      );
      user = inserted.rows[0];
    } else {
      const updated = await db.query(
        `UPDATE users
            SET google_id  = COALESCE(google_id, $1),
                name       = COALESCE($2, name),
                avatar_url = COALESCE($3, avatar_url),
                last_login = NOW()
          WHERE id = $4
        RETURNING *`,
        [googleId, fullName, avatarUrl, user.id]
      );
      user = updated.rows[0];
    }

    req.session.userId = user.id;
    req.session.email = user.email;
    req.session.role = user.role;
    req.session.status = user.status;
    req.session.franchiseId = user.franchise_id;
    req.session.activeFranchiseId = user.franchise_id;

    res.redirect("/");
  } catch (err) {
    console.error("Google OAuth callback error:", err);
    res.redirect("/?sso_error=exchange");
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
  const status = req.session?.status || null;
  const authenticated = !!(req.session && req.session.userId);
  res.json({
    authenticated,
    email: req.session?.email || null,
    role: req.session?.role || null,
    status,
    pendingApproval: authenticated && status && status !== "approved",
    needsFranchiseSelection: authenticated && status === "approved" && !req.session?.activeFranchiseId,
  });
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

// --- Super-admin: user approvals ---
const VALID_ROLES = ["super_admin", "franchise_admin", "franchise_staff"];

app.get("/api/admin/users", requireAuth, requireSuperAdmin, async (req, res) => {
  const status = req.query.status || null;
  try {
    const { rows } = await db.query(
      `SELECT u.id, u.email, u.name, u.avatar_url, u.role, u.status,
              u.franchise_id, f.name AS franchise_name,
              u.created_at, u.last_login, u.approved_at
         FROM users u
         LEFT JOIN franchises f ON f.id = u.franchise_id
        WHERE ($1::text IS NULL OR u.status = $1)
        ORDER BY
          CASE u.status WHEN 'pending' THEN 0 WHEN 'approved' THEN 1
                       WHEN 'disabled' THEN 2 ELSE 3 END,
          u.created_at DESC`,
      [status]
    );
    res.json({ users: rows });
  } catch (err) {
    console.error("List users error:", err);
    res.status(500).json({ error: "Database error" });
  }
});

// Approve a pending user. super_admin requires franchise_id = NULL;
// franchise_admin/franchise_staff requires a valid franchise_id.
app.post("/api/admin/users/:id/approve", requireAuth, requireSuperAdmin, async (req, res) => {
  const targetId = parseInt(req.params.id, 10);
  const { role, franchiseId } = req.body || {};
  if (!VALID_ROLES.includes(role)) return res.status(400).json({ error: "Invalid role" });
  const wantsFranchise = role !== "super_admin";
  const fid = wantsFranchise ? parseInt(franchiseId, 10) : null;
  if (wantsFranchise && !fid) return res.status(400).json({ error: "franchiseId required for this role" });

  try {
    if (fid) {
      const f = await loadFranchise(fid);
      if (!f) return res.status(404).json({ error: "Franchise not found" });
    }
    const { rows } = await db.query(
      `UPDATE users
          SET role = $1, franchise_id = $2, status = 'approved',
              approved_at = NOW(), approved_by = $3
        WHERE id = $4
        RETURNING id, email, role, franchise_id, status`,
      [role, fid, req.session.userId, targetId]
    );
    if (rows.length === 0) return res.status(404).json({ error: "User not found" });
    res.json({ success: true, user: rows[0] });
  } catch (err) {
    console.error("Approve user error:", err);
    res.status(500).json({ error: err.message || "Failed to approve user" });
  }
});

app.post("/api/admin/users/:id/reject", requireAuth, requireSuperAdmin, async (req, res) => {
  const targetId = parseInt(req.params.id, 10);
  if (targetId === req.session.userId) return res.status(400).json({ error: "Cannot reject yourself" });
  try {
    const { rows } = await db.query(
      `UPDATE users SET status = 'rejected' WHERE id = $1 RETURNING id, email, status`,
      [targetId]
    );
    if (rows.length === 0) return res.status(404).json({ error: "User not found" });
    res.json({ success: true, user: rows[0] });
  } catch (err) {
    console.error("Reject user error:", err);
    res.status(500).json({ error: "Database error" });
  }
});

app.post("/api/admin/users/:id/disable", requireAuth, requireSuperAdmin, async (req, res) => {
  const targetId = parseInt(req.params.id, 10);
  if (targetId === req.session.userId) return res.status(400).json({ error: "Cannot disable yourself" });
  try {
    const { rows } = await db.query(
      `UPDATE users SET status = 'disabled' WHERE id = $1 RETURNING id, email, status`,
      [targetId]
    );
    if (rows.length === 0) return res.status(404).json({ error: "User not found" });
    res.json({ success: true, user: rows[0] });
  } catch (err) {
    console.error("Disable user error:", err);
    res.status(500).json({ error: "Database error" });
  }
});

// --- Feedback (bug / enhancement / general) ---
const FEEDBACK_CATEGORIES = new Set(["bug", "feedback", "enhancement"]);
const FEEDBACK_STATUSES = new Set(["new", "in_progress", "resolved", "wont_fix"]);

const feedbackSubmitLimiter = rateLimit({
  windowMs: 60 * 1000, max: 6,
  standardHeaders: true, legacyHeaders: false,
  message: { error: "Too many feedback submissions, slow down." },
});

const feedbackReadLimiter = rateLimit({
  windowMs: 60 * 1000, max: 60,
  standardHeaders: true, legacyHeaders: false,
});

function feedbackToWire(r, { includeReply = true } = {}) {
  return {
    id: r.id,
    ts: r.created_at,
    category: r.category,
    message: r.message,
    status: r.status,
    page_url: r.page_url,
    ctx_dock: r.ctx_dock,
    ctx_view: r.ctx_view,
    is_known_issue: r.is_known_issue,
    resolved_at: r.resolved_at,
    user_email: r.user_email,
    user_name: r.user_name,
    franchise_id: r.franchise_id,
    ...(includeReply && r.admin_reply
      ? { admin_reply: r.admin_reply, admin_reply_at: r.admin_reply_at }
      : {}),
  };
}

// Submit feedback. Any approved user can post.
app.post("/api/feedback", requireAuth, feedbackSubmitLimiter, async (req, res) => {
  const category = String(req.body?.category || "").toLowerCase();
  const message = String(req.body?.message || "").trim();
  const ctx = req.body?.context || {};
  if (!FEEDBACK_CATEGORIES.has(category)) return res.status(400).json({ error: "Invalid category" });
  if (!message || message.length < 3) return res.status(400).json({ error: "Please include a short description" });
  if (message.length > 4000) return res.status(400).json({ error: "Message too long (max 4000 chars)" });

  try {
    const { rows } = await db.query(
      `INSERT INTO feedback
         (franchise_id, user_id, user_email, user_name, category, message,
          page_url, ctx_dock, ctx_view, user_agent)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
       RETURNING id`,
      [
        req.session.activeFranchiseId || null,
        req.session.userId,
        req.session.email || null,
        req.session.name || null,
        category,
        message,
        ctx.page_url ? String(ctx.page_url).slice(0, 500) : null,
        ctx.dock ? String(ctx.dock).slice(0, 100) : null,
        ctx.view ? String(ctx.view).slice(0, 100) : null,
        (req.get("user-agent") || "").slice(0, 500),
      ]
    );
    res.json({ success: true, id: rows[0].id });
  } catch (err) {
    console.error("Feedback submit error:", err);
    res.status(500).json({ error: "Failed to record feedback" });
  }
});

// The submitter's own feedback, with admin replies attached.
app.get("/api/me/feedback", requireAuth, feedbackReadLimiter, async (req, res) => {
  try {
    const { rows } = await db.query(
      `SELECT * FROM feedback WHERE user_id = $1 ORDER BY id DESC LIMIT 100`,
      [req.session.userId]
    );
    res.json({ success: true, feedback: rows.map((r) => feedbackToWire(r)) });
  } catch (err) {
    console.error("My-feedback error:", err);
    res.status(500).json({ error: "Database error" });
  }
});

// Pinned issues, visible to every approved user. Open issues first, then
// resolved-in-the-last-30-days so techs see what's been fixed recently.
app.get("/api/known-issues", requireAuth, feedbackReadLimiter, async (req, res) => {
  try {
    const { rows } = await db.query(
      `SELECT * FROM feedback
        WHERE is_known_issue = TRUE
          AND (status IN ('new','in_progress')
               OR (status IN ('resolved','wont_fix') AND resolved_at > NOW() - INTERVAL '30 days'))
        ORDER BY
          CASE WHEN status IN ('new','in_progress') THEN 0 ELSE 1 END,
          created_at DESC
        LIMIT 50`
    );
    res.json({ success: true, issues: rows.map((r) => feedbackToWire(r)) });
  } catch (err) {
    console.error("Known-issues error:", err);
    res.status(500).json({ error: "Database error" });
  }
});

// --- Super-admin: feedback triage ---
app.get("/api/admin/feedback", requireAuth, requireSuperAdmin, async (req, res) => {
  const status = req.query.status || null;
  if (status && !FEEDBACK_STATUSES.has(status)) {
    return res.status(400).json({ error: "Invalid status filter" });
  }
  try {
    const { rows } = await db.query(
      `SELECT f.*, fr.name AS franchise_name
         FROM feedback f
         LEFT JOIN franchises fr ON fr.id = f.franchise_id
        WHERE ($1::text IS NULL OR f.status = $1)
        ORDER BY
          CASE f.status WHEN 'new' THEN 0 WHEN 'in_progress' THEN 1 ELSE 2 END,
          f.created_at DESC
        LIMIT 200`,
      [status]
    );
    res.json({ success: true, feedback: rows });
  } catch (err) {
    console.error("Admin feedback list error:", err);
    res.status(500).json({ error: "Database error" });
  }
});

app.post("/api/admin/feedback/:id/status", requireAuth, requireSuperAdmin, async (req, res) => {
  const id = parseInt(req.params.id, 10);
  const status = String(req.body?.status || "");
  if (!id || !FEEDBACK_STATUSES.has(status)) {
    return res.status(400).json({ error: "Invalid id or status" });
  }
  try {
    const isResolution = status === "resolved" || status === "wont_fix";
    const { rows } = await db.query(
      `UPDATE feedback
          SET status = $1,
              resolved_at = CASE
                WHEN $2::boolean THEN COALESCE(resolved_at, NOW())
                ELSE NULL
              END
        WHERE id = $3
        RETURNING *`,
      [status, isResolution, id]
    );
    if (rows.length === 0) return res.status(404).json({ error: "Not found" });
    res.json({ success: true, feedback: rows[0] });
  } catch (err) {
    console.error("Feedback status error:", err);
    res.status(500).json({ error: "Database error" });
  }
});

app.post("/api/admin/feedback/:id/reply", requireAuth, requireSuperAdmin, async (req, res) => {
  const id = parseInt(req.params.id, 10);
  const reply = req.body?.reply == null ? null : String(req.body.reply).trim().slice(0, 4000);
  if (!id) return res.status(400).json({ error: "Invalid id" });
  try {
    const { rows } = await db.query(
      `UPDATE feedback
          SET admin_reply = $1,
              admin_reply_at = CASE WHEN $1 IS NULL THEN NULL ELSE NOW() END
        WHERE id = $2
        RETURNING *`,
      [reply || null, id]
    );
    if (rows.length === 0) return res.status(404).json({ error: "Not found" });
    res.json({ success: true, feedback: rows[0] });
  } catch (err) {
    console.error("Feedback reply error:", err);
    res.status(500).json({ error: "Database error" });
  }
});

app.post("/api/admin/feedback/:id/pin", requireAuth, requireSuperAdmin, async (req, res) => {
  const id = parseInt(req.params.id, 10);
  const pin = !!req.body?.pin;
  if (!id) return res.status(400).json({ error: "Invalid id" });
  try {
    const { rows } = await db.query(
      `UPDATE feedback SET is_known_issue = $1 WHERE id = $2 RETURNING *`,
      [pin, id]
    );
    if (rows.length === 0) return res.status(404).json({ error: "Not found" });
    res.json({ success: true, feedback: rows[0] });
  } catch (err) {
    console.error("Feedback pin error:", err);
    res.status(500).json({ error: "Database error" });
  }
});

app.post("/api/admin/users/:id/reinstate", requireAuth, requireSuperAdmin, async (req, res) => {
  const targetId = parseInt(req.params.id, 10);
  try {
    const { rows } = await db.query(
      `UPDATE users SET status = 'approved' WHERE id = $1 AND status IN ('disabled','rejected')
       RETURNING id, email, status`,
      [targetId]
    );
    if (rows.length === 0) return res.status(404).json({ error: "User not found or already approved" });
    res.json({ success: true, user: rows[0] });
  } catch (err) {
    console.error("Reinstate user error:", err);
    res.status(500).json({ error: "Database error" });
  }
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
