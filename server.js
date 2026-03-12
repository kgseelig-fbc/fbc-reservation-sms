// ─────────────────────────────────────────────────────────────────
//  Reservation SMS Confirmation Server
//  Express + Twilio integration for two-way SMS confirmations
// ─────────────────────────────────────────────────────────────────

require("dotenv").config();
const express = require("express");
const cors = require("cors");
const twilio = require("twilio");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3001;

// ─── Twilio Client ───────────────────────────────────────────────
const accountSid = process.env.TWILIO_ACCOUNT_SID;
const authToken = process.env.TWILIO_AUTH_TOKEN;
const twilioPhone = process.env.TWILIO_PHONE_NUMBER;
const messagingServiceSid = process.env.TWILIO_MESSAGING_SERVICE_SID || "MGb0e243d1219dc595b59d1803ccf9a3cb"; // A2P 10DLC
const baseUrl = (process.env.BASE_URL || "").replace(/\/+$/, ""); // Strip trailing slashes
const client = twilio(accountSid, authToken);

// ─── Phone Number Normalization ─────────────────────────────────
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

// ─── Middleware ──────────────────────────────────────────────────
app.use(cors({
  origin: "*",
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true })); // Twilio webhooks send form-encoded

// ─── Password Protection ────────────────────────────────────────
const DASHBOARD_PASSWORD = process.env.DASHBOARD_PASSWORD || "FreedomAiTools";
const activeSessions = new Set();

function generateSessionId() {
  return Math.random().toString(36).slice(2) + Date.now().toString(36);
}

// Login page HTML
function loginPageHtml(error) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Freedom Boat Club — Login</title>
  <link href="https://fonts.googleapis.com/css2?family=Montserrat:wght@400;600;700&family=Open+Sans:wght@400;500;600&display=swap" rel="stylesheet">
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { background: #F0F4F8; min-height: 100vh; display: flex; align-items: center; justify-content: center; font-family: 'Open Sans', sans-serif; }
    .login-card { background: #fff; border-radius: 20px; padding: 48px 40px; width: 90%; max-width: 400px; box-shadow: 0 4px 24px rgba(11,37,69,0.08); text-align: center; }
    .logo { width: 80px; height: 80px; border-radius: 50%; margin: 0 auto 20px; }
    h1 { font-family: 'Montserrat', sans-serif; color: #0B2545; font-size: 22px; margin-bottom: 6px; }
    .subtitle { color: #6B7D94; font-size: 13px; margin-bottom: 28px; }
    input { width: 100%; padding: 14px 18px; border: 2px solid #D1DAE6; border-radius: 12px; font-size: 15px; font-family: 'Open Sans', sans-serif; outline: none; transition: border-color 0.2s; margin-bottom: 16px; }
    input:focus { border-color: #0B2545; }
    button { width: 100%; padding: 14px; border: none; border-radius: 12px; background: #0B2545; color: #fff; font-size: 15px; font-weight: 600; font-family: 'Open Sans', sans-serif; cursor: pointer; transition: background 0.2s; }
    button:hover { background: #163A6A; }
    .error { color: #C41E3A; font-size: 13px; margin-bottom: 16px; font-weight: 600; }
  </style>
</head>
<body>
  <div class="login-card">
    <h1>Reservation Confirmations</h1>
    <div class="subtitle">Freedom Boat Club of NE Florida</div>
    ${error ? '<div class="error">Incorrect password. Please try again.</div>' : ''}
    <form method="POST" action="/login">
      <input type="password" name="password" placeholder="Enter password" autofocus required />
      <button type="submit">Sign In</button>
    </form>
  </div>
</body>
</html>`;
}

// Login routes
app.post("/login", (req, res) => {
  const { password } = req.body;
  if (password === DASHBOARD_PASSWORD) {
    const sessionId = generateSessionId();
    activeSessions.add(sessionId);
    res.cookie("fbc_session", sessionId, { httpOnly: true, maxAge: 24 * 60 * 60 * 1000 }); // 24 hours
    res.redirect("/");
  } else {
    res.send(loginPageHtml(true));
  }
});

app.get("/logout", (req, res) => {
  const sid = parseCookie(req.headers.cookie || "", "fbc_session");
  activeSessions.delete(sid);
  res.clearCookie("fbc_session");
  res.redirect("/");
});

function parseCookie(cookieStr, name) {
  const match = cookieStr.match(new RegExp("(?:^|;\\s*)" + name + "=([^;]*)"));
  return match ? match[1] : null;
}

function requireAuth(req, res, next) {
  const sid = parseCookie(req.headers.cookie || "", "fbc_session");
  if (sid && activeSessions.has(sid)) return next();
  res.send(loginPageHtml(false));
}

// Root route — serve dashboard (protected)
app.get("/", requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// ─── Dock Locations ─────────────────────────────────────────────
const DOCKS = [
  { id: "jax-beach", name: "Jacksonville Beach" },
  { id: "julington-east", name: "Julington Creek East" },
  { id: "julington-west", name: "Julington Creek West" },
  { id: "camachee-cove", name: "St. Augustine — Camachee Cove" },
  { id: "shipyard", name: "St. Augustine — Shipyard" },
];

// ─── In-Memory Store (per dock) ──────────────────────────────────
// In production, replace with a real database (PostgreSQL, MongoDB, etc.)
const dockData = {};
DOCKS.forEach((d) => {
  dockData[d.id] = { reservations: [], smsLogs: {} };
});

function getDock(dockId) {
  if (!dockData[dockId]) return null;
  return dockData[dockId];
}

// GET /api/docks — list all docks
app.get("/api/docks", (req, res) => {
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

// ─── API Routes ──────────────────────────────────────────────────

// GET /api/reservations?dock=:dockId — list reservations for a dock
app.get("/api/reservations", (req, res) => {
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

// POST /api/reservations/import?dock=:dockId — bulk import for a dock
app.post("/api/reservations/import", (req, res) => {
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

// POST /api/reservations/:id/status?dock=:dockId — update status
app.post("/api/reservations/:id/status", (req, res) => {
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

// ─── SMS Sending ─────────────────────────────────────────────────

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

// POST /api/sms/send/:id — send SMS to a single reservation
app.post("/api/sms/send/:id", async (req, res) => {
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

// POST /api/sms/send-bulk — send SMS to multiple reservations
app.post("/api/sms/send-bulk", async (req, res) => {
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

// ─── Twilio Webhooks ─────────────────────────────────────────────

// POST /api/sms/incoming — Twilio sends inbound messages here
// Configure this URL in your Twilio phone number settings under
// "A MESSAGE COMES IN" → Webhook → POST → https://yourdomain.com/api/sms/incoming
app.post("/api/sms/incoming", (req, res) => {
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

  // ── Parse CONFIRM ──
  if (replyLower === "confirm" || replyLower === "yes" || replyLower === "c") {
    reservation.status = "confirmed";
    responseText =
      "Thank you! Your reservation is confirmed. We look forward to seeing you!";
  }
  // ── Parse CANCEL ──
  else if (replyLower === "cancel" || replyLower === "no") {
    reservation.status = "cancelled";
    responseText =
      "Your reservation has been cancelled. If you change your mind, please call us to rebook.";
  }
  // ── Parse TIME change ──
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

// POST /api/sms/status — Twilio delivery status callbacks
app.post("/api/sms/status", (req, res) => {
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

// ─── SMS Log Endpoint ────────────────────────────────────────────

// GET /api/sms/log/:id?dock=:dockId — get SMS conversation for a reservation
app.get("/api/sms/log/:id", (req, res) => {
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

// ─── Health Check ────────────────────────────────────────────────
app.get("/api/health", (req, res) => {
  const dockCounts = {};
  DOCKS.forEach((d) => { dockCounts[d.id] = dockData[d.id].reservations.length; });
  res.json({
    status: "ok",
    twilioConfigured: !!(accountSid && authToken && (twilioPhone || messagingServiceSid)),
    messagingService: messagingServiceSid ? true : false,
    docks: DOCKS.length,
    reservationsByDock: dockCounts,
    timestamp: new Date().toISOString(),
  });
});

// ─── Serve Dashboard ─────────────────────────────────────────────
// Protect direct access to index.html
app.get("/index.html", requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});
app.use(express.static(path.join(__dirname, "public"), { index: false }));
app.get("/dashboard", requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// ─── Start Server ────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n🚀 Reservation SMS server running on port ${PORT}`);
  console.log(`   Health check: http://localhost:${PORT}/api/health`);
  if (!accountSid || !authToken || !twilioPhone) {
    console.log(`\n⚠️  Twilio credentials not configured!`);
    console.log(`   Copy .env.example to .env and add your credentials.\n`);
  } else {
    console.log(`   Twilio phone: ${twilioPhone}`);
    if (messagingServiceSid) console.log(`   Messaging Service: ${messagingServiceSid}`);
    console.log(`   Webhook URL:  ${baseUrl || "http://localhost:" + PORT}/api/sms/incoming\n`);
  }
});
