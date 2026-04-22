// Thin email helper. Uses SMTP if fully configured; otherwise logs the email
// to stdout so the flow still completes in dev or during a provider outage.
// Configure via env:
//   SMTP_HOST, SMTP_PORT (default 587), SMTP_USER, SMTP_PASS,
//   SMTP_FROM (sender address, defaults to SMTP_USER if unset),
//   SMTP_SECURE (true/false, default true when PORT=465 else false)
const nodemailer = require("nodemailer");

const host = process.env.SMTP_HOST;
const port = parseInt(process.env.SMTP_PORT || "587", 10);
const user = process.env.SMTP_USER;
const pass = process.env.SMTP_PASS;
const from = process.env.SMTP_FROM || user;
const secure = process.env.SMTP_SECURE
  ? /^(1|true|yes)$/i.test(process.env.SMTP_SECURE)
  : port === 465;

let transporter = null;
if (host && user && pass) {
  transporter = nodemailer.createTransport({
    host, port, secure, auth: { user, pass },
  });
  transporter.verify().then(
    () => console.log(`SMTP ready (${host}:${port})`),
    (err) => console.warn(`SMTP verify failed: ${err.message}`)
  );
} else {
  console.log("SMTP not configured — password reset emails will be logged to stdout.");
}

async function sendEmail({ to, subject, text, html }) {
  if (!transporter) {
    console.log(
      "\n===== EMAIL (SMTP not configured) =====\n" +
      `To:      ${to}\n` +
      `Subject: ${subject}\n` +
      `${text || html}\n` +
      "=======================================\n"
    );
    return { sent: false, logged: true };
  }
  const info = await transporter.sendMail({ from, to, subject, text, html });
  return { sent: true, messageId: info.messageId };
}

module.exports = { sendEmail, isConfigured: () => !!transporter };
