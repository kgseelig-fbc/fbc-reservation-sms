# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Freedom Boat Club reservation SMS confirmation system. An Express server integrates with Twilio for two-way SMS to confirm, cancel, or reschedule boat reservations across multiple dock locations. A React-based dashboard (served as static HTML) provides the admin UI.

## Commands

- **Start server:** `npm start` (runs on port 3001 by default)
- **Dev mode:** `npm run dev` (uses nodemon for auto-reload)
- **Install deps:** `npm install`

No test framework or linter is configured.

## Architecture

**Single-file server** (`server.js`): All backend logic lives here — Express routes, Twilio integration, in-memory data store, phone normalization, and SMS message building.

**Single-file frontend** (`public/index.html`): A self-contained React app loaded via CDN (React 18, Babel standalone, SheetJS for Excel import). No build step. Uses `window.location.origin` as API base.

**Data storage:** In-memory only (`dockData` object keyed by dock ID). All data is lost on server restart. Each dock has `reservations[]` and `smsLogs{}`.

**Multi-dock model:** Five hardcoded dock locations in `DOCKS` array (duplicated in both server.js and public/index.html). Most API routes require a `dock` query/body parameter.

## Key API Routes

- `GET /api/docks` — list docks
- `GET /api/reservations?dock=ID` — list reservations for a dock
- `POST /api/reservations/import?dock=ID` — bulk import (expects `{data: [...]}`)
- `POST /api/sms/send/:id` — send SMS to one reservation
- `POST /api/sms/send-bulk` — send to multiple (`{ids: [...] | "all", dock}`)
- `POST /api/sms/incoming` — Twilio inbound webhook (TwiML response)
- `POST /api/sms/status` — Twilio delivery status callback

## Environment

Configured via `.env` (see `env.example.txt`): `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, `TWILIO_PHONE_NUMBER`, `TWILIO_MESSAGING_SERVICE_SID` (optional, for A2P 10DLC), `BASE_URL` (public URL for webhooks, use ngrok in dev), `PORT`.

## Important Patterns

- Phone numbers are normalized to E.164 format via `normalizePhone()` before sending
- Inbound SMS routing uses last-10-digits matching across all docks (`findReservationByPhone`)
- Guests can reply CONFIRM/YES/C, CANCEL/NO, or TIME [new time] to update reservations
- SMS conversations are logged per-reservation in `dock.smsLogs[reservationId]`
- The messaging service SID takes priority over the phone number when both are configured
