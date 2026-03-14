// -----------------------------------------------------------------
//  Reservation SMS Confirmation Server
//  Express + Twilio integration for two-way SMS confirmations
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

const app = express();
const PORT = process.env.PORT || 3001;
const isProduction = process.env.NODE_ENV === "production";

// --- Admin Password (hashed with SHA-256) ---
// Default fallback password: "fbc-admin-2024"
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "fbc-admin-2024";

// --- Twilio Client ---
const accountSid = process.env.TWILIO_ACCOUNT_SID;
const authToken = process.env.TWILIO_AUTH_TOKEN;
const twilioPhone = process.env.TWILIO_PHONE_NUMBER;
const messagingServiceSid = process.env.TWILIO_MESSAGING_SERVICE_SID; // A2P 10DLC
const baseUrl = (process.env.BASE_URL || "").replace(/\/+$/, ""); // Strip trailing slashes
const client = twilio(accountSid, authToken);

// --- Phone Number Normalization ---
// Ensures phone numbers are in E.164 format (+1XXXXXXXXXX for US)
function normalizePhone(phone) {
  if (!phone) return "";
  let digits = phone.replace(/\D/g, "");
  // If 10 digits, assume US and add +1
  if (digits.length === 10) return `+1${digits}`;
  // If 11 digits starting with 1, add +
  if (digits.length === 11 && digits.startsWith("1")) return `+${digits}`;
  // If already has +, return as-is
  if (phone.startsWith("+")) return phone.replace(/[^\d+]/g, "");
  return `+${digits}`;
}

// --- Security Headers (Helmet) ---
app.use(helmet({
  contentSecurityPolicy: false, // Disabled for now (inline scripts in dashboard)
}));

// --- Rate Limiting ---
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many requests, please try again later" },
});
app.use(globalLimiter);

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many login attempts, please try again later" },
});

// --- CORS (restricted) ---
const allowedOrigins = process.env.CORS_ORIGINS
  ? process.env.CORS_ORIGINS.split(",").map((s) => s.trim())
  : [];

app.use(cors({
  origin: allowedOrigins.length > 0
    ? (origin, callback) => {
        // Allow requests with no origin (same-origin, curl, etc.)
        if (!origin || allowedOrigins.includes(origin)) {
          callback(null, true);
        } else {
          callback(new Error("Not allowed by CORS"));
        }
      }
    : false, // Same-origin only when no whitelist configured
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
  credentials: true,
}));

// --- Body Parsers (with size limit) ---
app.use(express.json({ limit: "10kb" }));
app.use(express.urlencoded({ extended: true, limit: "10kb" })); // Twilio webhooks send form-encoded

// --- Session Management ---
app.use(session({
  secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex"),
  resave: false,
  saveUninitialized: false,
  name: "fbc.rsms.sid",
  cookie: {
    httpOnly: true,
    secure: isProduction,
    sameSite: "strict",
    maxAge: 8 * 60 * 60 * 1000, // 8 hours
  },
}));

// --- Authentication Middleware ---
function requireAuth(req, res, next) {
  if (req.session && req.session.authenticated) {
    return next();
  }
  return res.status(401).json({ error: "Authentication required" });
}

// --- Auth Endpoints ---

// POST /api/login
app.post("/api/login", loginLimiter, (req, res) => {
  const { password } = req.body;
  if (!password) {
    return res.status(400).json({ error: "Password is required" });
  }
  if (password === ADMIN_PASSWORD) {
    req.session.authenticated = true;
    req.session.loginTime = new Date().toISOString();
    return res.json({ success: true });
  }
  return res.status(401).json({ error: "Invalid password" });
});

// POST /api/logout
app.post("/api/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ error: "Failed to logout" });
    }
    res.clearCookie("fbc.rsms.sid");
    return res.json({ success: true });
  });
});

// GET /api/session
app.get("/api/session", (req, res) => {
  if (req.session && req.session.authenticated) {
    return res.json({ authenticated: true });
  }
  return res.json({ authenticated: false });
});

// --- Twilio Webhook Validation Middleware ---
const twilioWebhookValidation = twilio.webhook({ validate: isProduction });

// Root route — serve dashboard
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

// --- In-Memory Store (per dock) ---
// In production, replace with a real database (PostgreSQL, MongoDB, etc.)
const dockData = {};
DOCKS.forEach((d) => {
  dockData[d.id] = { reservations: [], smsLogs: {} };
});

function getDock(dockId) {
  if (!dockData[dockId]) return null;
  return dockData[dockId];
}

// GET /api/docks -- list all docks (protected)
app.get("/api/docks", requireAuth, (req, res) => {
  res.json({ docks: DOCKS });
});

// Map phone numbers to reservation IDs for inbound routing
function findReservationByPhone(phone) {
  const normalize = (p) => p.replace(/\D/g, "").slice(-10);
  const normalized = normalize(phone);
  for (const [dockId, data] of Object.entries(dockData)) {
    const res = data.reservations.find((r) => normalize(r.phone) === normalized);
    if (res) return { reservation: res, dockId };
  }
  return null;
}

// --- API Routes (all protected) ---

// GET /api/reservations?dock=:dockId -- list reservations for a dock
app.get("/api/reservations", requireAuth, (req, res) => {
  const dockId = req.query.dock;
  if (!dockId || !getDock(dockId)) {
    return res.status(400).json({ error: "Invalid or missing dock parameter", docks: DOCKS.map((d) => d.id) });
  }
  const dock = getDock(dockId);
  const enriched = dock.reservations.map((r) => ({
    ...r,
    smsLog: dock.smsLogs[r.id] || [],
  }));
  res.json({ reservations: enriched, dock: dockId });
});

// POST /api/reservations/import?dock=:dockId -- bulk import for a dock
app.post("/api/reservations/import", requireAuth, (req, res) => {
  const dockId = req.query.dock || req.body.dock;
  if (!dockId || !getDock(dockId)) {
    return res.status(400).json({ error: "Invalid or missing dock parameter" });
  }
  const { data } = req.body;
  if (!Array.isArray(data) || data.length === 0) {
    return res.status(400).json({ error: "No reservation data provided" });
  }
  const dock = getDock(dockId);
  dock.reservations = data.map((r, i) => ({
    id: r.id || `${dockId.toUpperCase().slice(0, 3)}-${String(i + 1).padStart(3, "0")}`,
    name: r.name || `Guest ${i + 1}`,
    email: r.email || "",
    phone: r.phone || "",
    service: r.service || "Reservation",
    date: r.date,
    guests: r.guests || 1,
    status: r.status || "unconfirmed",
    channel: r.channel || "sms",
    messageSent: false,
    messageTime: null,
    notes: r.notes || "",
    timeUpdated: false,
    originalTime: null,
    dock: dockId,
  }));
  dock.smsLogs = {};
  res.json({ success: true, count: dock.reservations.length, dock: dockId });
});

// POST /api/reservations/:id/status?dock=:dockId -- update status
app.post("/api/reservations/:id/status", requireAuth, (req, res) => {
  const { id } = req.params;
  const dockId = req.query.dock || req.body.dock;
  if (!dockId || !getDock(dockId)) {
    return res.status(400).json({ error: "Invalid or missing dock parameter" });
  }
  const dock = getDock(dockId);
  const { status } = req.body;
  const reservation = dock.reservations.find((r) => r.id === id);
  if (!reservation) return res.status(404).json({ error: "Reservation not found" });
  reservation.status = status;
  res.json({ success: true, reservation });
});

// --- SMS Sending ---

// Build the outbound SMS message body
function buildSmsBody(reservation) {
  const dateObj = new Date(reservation.date);
  const dateStr = dateObj.toLocaleDateString("en-US", {
    weekday: "long",
    month: "long",
    day: "numeric",
  });
  const timeStr = dateObj.toLocaleTimeString("en-US", {
    hour: "numeric",
    minute: "2-digit",
  });

  return (
    `Hi ${reservation.name.split(" ")[0]}! ` +
    `This is a reminder about your upcoming ${reservation.service} ` +
    `on ${dateStr} at ${timeStr} for ${reservation.guests} guest(s).\n\n` +
    `Reply:\n` +
    `• CONFIRM to confirm\n` +
    `• CANCEL to cancel\n` +
    `• TIME [new time] to update arrival (e.g. TIME 7:30 PM)`
  );
}

// POST /api/sms/send/:id -- send SMS to a single reservation (protected)
app.post("/api/sms/send/:id", requireAuth, async (req, res) => {
  const { id } = req.params;
  const { customBody, dock: dockId } = req.body || {};
  if (!dockId || !getDock(dockId)) {
    return res.status(400).json({ error: "Invalid or missing dock parameter" });
  }
  const dock = getDock(dockId);
  const reservation = dock.reservations.find((r) => r.id === id);
  if (!reservation) return res.status(404).json({ error: "Reservation not found" });

  if (!reservation.phone) {
    return res.status(400).json({ error: "No phone number on file for this reservation" });
  }

  const body = customBody || buildSmsBody(reservation);

  try {
    const toPhone = normalizePhone(reservation.phone);
    if (!toPhone || toPhone.length < 10) {
      return res.status(400).json({ error: "Invalid phone number format" });
    }
    const message = await client.messages.create({
      body,
      ...(messagingServiceSid ? { messagingServiceSid } : { from: twilioPhone }),
      to: toPhone,
      statusCallback: `${baseUrl}/api/sms/status`,
    });

    // Log the outbound message
    if (!dock.smsLogs[id]) dock.smsLogs[id] = [];
    dock.smsLogs[id].push({
      from: "system",
      text: body,
      time: new Date().toISOString(),
      twilioSid: message.sid,
      twilioStatus: message.status,
    });

    reservation.messageSent = true;
    reservation.messageTime = new Date().toISOString();
    if (reservation.status === "unconfirmed") reservation.status = "pending";

    res.json({
      success: true,
      messageSid: message.sid,
      reservation,
    });
  } catch (err) {
    console.error("Twilio send error:", err.message);
    res.status(500).json({ error: "Failed to send SMS", details: err.message });
  }
});

// POST /api/sms/send-bulk -- send SMS to multiple reservations (protected)
app.post("/api/sms/send-bulk", requireAuth, async (req, res) => {
  const { ids, dock: dockId } = req.body;
  if (!dockId || !getDock(dockId)) {
    return res.status(400).json({ error: "Invalid or missing dock parameter" });
  }
  const dock = getDock(dockId);
  let targets;

  if (ids === "all") {
    targets = dock.reservations.filter((r) => !r.messageSent && r.phone);
  } else if (Array.isArray(ids)) {
    targets = dock.reservations.filter((r) => ids.includes(r.id) && !r.messageSent && r.phone);
  } else {
    return res.status(400).json({ error: "Provide ids array or 'all'" });
  }

  const results = { sent: 0, failed: 0, errors: [] };

  for (const reservation of targets) {
    const body = buildSmsBody(reservation);
    try {
      const toPhone = normalizePhone(reservation.phone);
      if (!toPhone || toPhone.length < 10) { results.failed++; continue; }
      const message = await client.messages.create({
        body,
        ...(messagingServiceSid ? { messagingServiceSid } : { from: twilioPhone }),
        to: toPhone,
        statusCallback: `${baseUrl}/api/sms/status`,
      });

      if (!dock.smsLogs[reservation.id]) dock.smsLogs[reservation.id] = [];
      dock.smsLogs[reservation.id].push({
        from: "system",
        text: body,
        time: new Date().toISOString(),
        twilioSid: message.sid,
        twilioStatus: message.status,
      });

      reservation.messageSent = true;
      reservation.messageTime = new Date().toISOString();
      if (reservation.status === "unconfirmed") reservation.status = "pending";
      results.sent++;
    } catch (err) {
      console.error(`SMS failed for ${reservation.id}:`, err.message);
      results.failed++;
      results.errors.push({ id: reservation.id, error: err.message });
    }
  }

  res.json({ success: true, ...results });
});

// --- Twilio Webhooks (validated, NOT auth-protected) ---

// POST /api/sms/incoming -- Twilio sends inbound messages here
// Configure this URL in your Twilio phone number settings under
// "A MESSAGE COMES IN" -> Webhook -> POST -> https://yourdomain.com/api/sms/incoming
app.post("/api/sms/incoming", twilioWebhookValidation, (req, res) => {
  const { From, Body } = req.body;
  const inboundText = (Body || "").trim();
  const found = findReservationByPhone(From);

  if (!found) {
    const twiml = new twilio.twiml.MessagingResponse();
    twiml.message(
      "Sorry, we couldn't find a reservation associated with this number. " +
      "Please call us directly for assistance."
    );
    res.type("text/xml").send(twiml.toString());
    return;
  }

  const { reservation, dockId } = found;
  const dock = getDock(dockId);
  const id = reservation.id;
  if (!dock.smsLogs[id]) dock.smsLogs[id] = [];

  // Log inbound
  dock.smsLogs[id].push({
    from: "member",
    text: inboundText,
    time: new Date().toISOString(),
    twilioFrom: From,
  });

  const replyLower = inboundText.toLowerCase();
  let responseText;

  // -- Parse CONFIRM --
  if (replyLower === "confirm" || replyLower === "yes" || replyLower === "c") {
    reservation.status = "confirmed";
    responseText =
      "Thank you! Your reservation is confirmed. We look forward to seeing you!";
  }
  // -- Parse CANCEL --
  else if (replyLower === "cancel" || replyLower === "no") {
    reservation.status = "cancelled";
    responseText =
      "Your reservation has been cancelled. If you change your mind, please call us to rebook.";
  }
  // -- Parse TIME change --
  else {
    const timeMatch = replyLower.match(
      /^time\s+(\d{1,2}):?(\d{2})?\s*(am|pm)?$/i
    );
    if (timeMatch) {
      let h = parseInt(timeMatch[1]);
      const m = parseInt(timeMatch[2] || "0");
      const ampm = timeMatch[3];
      if (ampm && ampm.toLowerCase() === "pm" && h < 12) h += 12;
      if (ampm && ampm.toLowerCase() === "am" && h === 12) h = 0;

      const dateObj = new Date(reservation.date);
      if (!reservation.originalTime) reservation.originalTime = reservation.date;
      dateObj.setHours(h, m, 0, 0);
      reservation.date = dateObj.toISOString();
      reservation.timeUpdated = true;

      const newTimeStr = dateObj.toLocaleTimeString("en-US", {
        hour: "numeric",
        minute: "2-digit",
      });
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

  // Log outbound reply
  dock.smsLogs[id].push({
    from: "system",
    text: responseText,
    time: new Date().toISOString(),
  });

  // Respond via TwiML
  const twiml = new twilio.twiml.MessagingResponse();
  twiml.message(responseText);
  res.type("text/xml").send(twiml.toString());
});

// POST /api/sms/status -- Twilio delivery status callbacks (validated, NOT auth-protected)
app.post("/api/sms/status", twilioWebhookValidation, (req, res) => {
  const { MessageSid, MessageStatus } = req.body;
  console.log(`SMS ${MessageSid}: ${MessageStatus}`);

  // Update the log entry with delivery status
  for (const [dockId, dock] of Object.entries(dockData)) {
    for (const [resId, logs] of Object.entries(dock.smsLogs)) {
      const entry = logs.find((l) => l.twilioSid === MessageSid);
      if (entry) {
        entry.twilioStatus = MessageStatus;
        res.sendStatus(200);
        return;
      }
    }
  }

  res.sendStatus(200);
});

// --- SMS Log Endpoint (protected) ---

// GET /api/sms/log/:id?dock=:dockId -- get SMS conversation for a reservation
app.get("/api/sms/log/:id", requireAuth, (req, res) => {
  const { id } = req.params;
  const dockId = req.query.dock;
  if (!dockId || !getDock(dockId)) {
    return res.status(400).json({ error: "Invalid or missing dock parameter" });
  }
  const dock = getDock(dockId);
  const reservation = dock.reservations.find((r) => r.id === id);
  if (!reservation) return res.status(404).json({ error: "Reservation not found" });
  res.json({
    reservation,
    smsLog: dock.smsLogs[id] || [],
  });
});

// --- Health Check (NOT protected) ---
app.get("/api/health", (req, res) => {
  res.json({ status: "ok" });
});

// --- Serve Dashboard ---
app.use(express.static(path.join(__dirname, "public")));
app.get("/dashboard", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// --- Start Server ---
app.listen(PORT, () => {
  console.log(`\nReservation SMS server running on port ${PORT}`);
  console.log(`   Health check: http://localhost:${PORT}/api/health`);
  if (!accountSid || !authToken || !twilioPhone) {
    console.log(`\n   Twilio credentials not configured!`);
    console.log(`   Copy .env.example to .env and add your credentials.\n`);
  } else {
    console.log(`   Twilio phone: ${twilioPhone}`);
    if (messagingServiceSid) console.log(`   Messaging Service: ${messagingServiceSid}`);
    console.log(`   Webhook URL:  ${baseUrl || "http://localhost:" + PORT}/api/sms/incoming\n`);
  }
});
