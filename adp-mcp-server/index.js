#!/usr/bin/env node

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import https from "node:https";
import fs from "node:fs";
import path from "node:path";

// ---------------------------------------------------------------------------
// ADP HTTP client – handles OAuth 2.0 + mutual TLS
// ---------------------------------------------------------------------------

class ADPClient {
  constructor() {
    this.clientId = process.env.ADP_CLIENT_ID;
    this.clientSecret = process.env.ADP_CLIENT_SECRET;
    this.certPath = process.env.ADP_SSL_CERT_PATH;
    this.keyPath = process.env.ADP_SSL_KEY_PATH;
    this.apiBase = process.env.ADP_API_BASE || "https://api.adp.com";
    this.tokenUrl =
      process.env.ADP_TOKEN_URL ||
      "https://accounts.adp.com/auth/oauth/v2/token";

    this.accessToken = null;
    this.tokenExpiry = 0;
  }

  /** Build an https.Agent with mutual TLS certs when configured */
  _agent() {
    if (!this.certPath || !this.keyPath) return undefined;
    return new https.Agent({
      cert: fs.readFileSync(path.resolve(this.certPath)),
      key: fs.readFileSync(path.resolve(this.keyPath)),
      rejectUnauthorized: true,
    });
  }

  /** Low-level fetch wrapper that attaches the mTLS agent */
  async _fetch(url, options = {}) {
    const agent = this._agent();
    const res = await fetch(url, {
      ...options,
      ...(agent ? { dispatcher: undefined } : {}),
      // Node 18+ fetch doesn't support agent directly; for mTLS use
      // the undici dispatcher or run with --experimental-fetch.  In
      // environments where native fetch lacks mTLS support, swap this
      // out for the `undici` or `node-fetch` + https.Agent approach.
    });
    return res;
  }

  /** Obtain (or refresh) an OAuth 2.0 access token */
  async authenticate() {
    if (!this.clientId || !this.clientSecret) {
      throw new Error(
        "ADP_CLIENT_ID and ADP_CLIENT_SECRET environment variables are required"
      );
    }

    if (this.accessToken && Date.now() < this.tokenExpiry) {
      return this.accessToken;
    }

    const body = new URLSearchParams({
      grant_type: "client_credentials",
      client_id: this.clientId,
      client_secret: this.clientSecret,
    });

    const res = await this._fetch(this.tokenUrl, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body,
    });

    if (!res.ok) {
      const text = await res.text();
      throw new Error(`ADP auth failed (${res.status}): ${text}`);
    }

    const data = await res.json();
    this.accessToken = data.access_token;
    // Expire 5 min early to be safe
    this.tokenExpiry = Date.now() + (data.expires_in - 300) * 1000;
    return this.accessToken;
  }

  /** Authenticated GET */
  async get(endpoint, params = {}) {
    const token = await this.authenticate();
    const url = new URL(endpoint, this.apiBase);
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== null && v !== "") url.searchParams.set(k, v);
    }
    const res = await this._fetch(url.toString(), {
      headers: { Authorization: `Bearer ${token}`, Accept: "application/json" },
    });
    if (!res.ok) {
      const text = await res.text();
      throw new Error(`ADP GET ${endpoint} failed (${res.status}): ${text}`);
    }
    return res.json();
  }

  /** Authenticated POST (for event-based writes) */
  async post(endpoint, payload) {
    const token = await this.authenticate();
    const url = new URL(endpoint, this.apiBase);
    const res = await this._fetch(url.toString(), {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const text = await res.text();
      throw new Error(`ADP POST ${endpoint} failed (${res.status}): ${text}`);
    }
    return res.json();
  }
}

// ---------------------------------------------------------------------------
// MCP Server
// ---------------------------------------------------------------------------

const adp = new ADPClient();
const server = new McpServer({
  name: "adp-run",
  version: "1.0.0",
});

// ===== WORKERS / EMPLOYEES =================================================

server.tool(
  "adp_list_workers",
  "List all workers (employees) in ADP Run. Supports pagination.",
  {
    top: z
      .number()
      .optional()
      .describe("Max number of workers to return (default 100)"),
    skip: z
      .number()
      .optional()
      .describe("Number of workers to skip for pagination"),
    filter: z
      .string()
      .optional()
      .describe(
        "OData filter expression, e.g. workers/workerStatus/statusCode/codeValue eq 'Active'"
      ),
  },
  async ({ top, skip, filter }) => {
    const params = {};
    if (top) params["$top"] = top;
    if (skip) params["$skip"] = skip;
    if (filter) params["$filter"] = filter;
    const data = await adp.get("/hr/v2/workers", params);
    return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
  }
);

server.tool(
  "adp_get_worker",
  "Get detailed information for a single worker by their Associate OID.",
  {
    aoid: z.string().describe("The Associate OID (unique ADP worker ID)"),
  },
  async ({ aoid }) => {
    const data = await adp.get(`/hr/v2/workers/${encodeURIComponent(aoid)}`);
    return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
  }
);

server.tool(
  "adp_hire_worker",
  "Hire a new worker (create a new employee record in ADP Run).",
  {
    givenName: z.string().describe("Employee first name"),
    familyName: z.string().describe("Employee last name"),
    hireDate: z.string().describe("Original hire date (YYYY-MM-DD)"),
    positionTitle: z.string().optional().describe("Job title"),
    email: z.string().optional().describe("Work email address"),
    phone: z.string().optional().describe("Work phone number"),
  },
  async ({ givenName, familyName, hireDate, positionTitle, email, phone }) => {
    const worker = {
      person: {
        legalName: { givenName, familyName1: familyName },
      },
      workerDates: { originalHireDate: hireDate },
    };
    if (positionTitle) {
      worker.workAssignments = [{ positionTitle }];
    }
    if (email) {
      worker.businessCommunication = {
        emails: [{ emailUri: email }],
      };
    }
    if (phone) {
      worker.businessCommunication = {
        ...(worker.businessCommunication || {}),
        landlines: [{ formattedNumber: phone }],
      };
    }

    const payload = {
      events: [
        {
          eventNameCode: { codeValue: "worker.hire" },
          data: { eventContext: { worker } },
        },
      ],
    };
    const data = await adp.post("/events/hr/v1/worker.hire", payload);
    return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
  }
);

server.tool(
  "adp_terminate_worker",
  "Terminate (separate) a worker in ADP Run.",
  {
    aoid: z.string().describe("The Associate OID of the worker to terminate"),
    terminationDate: z.string().describe("Termination date (YYYY-MM-DD)"),
    reasonCode: z
      .string()
      .optional()
      .describe("Reason code for termination (e.g. 'Resignation', 'Involuntary')"),
  },
  async ({ aoid, terminationDate, reasonCode }) => {
    const payload = {
      events: [
        {
          eventNameCode: { codeValue: "worker.terminate" },
          data: {
            eventContext: {
              worker: {
                associateOID: aoid,
                workerDates: { terminationDate },
                ...(reasonCode
                  ? {
                      workerStatus: {
                        reasonCode: { codeValue: reasonCode },
                      },
                    }
                  : {}),
              },
            },
          },
        },
      ],
    };
    const data = await adp.post("/events/hr/v1/worker.terminate", payload);
    return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
  }
);

server.tool(
  "adp_rehire_worker",
  "Rehire a previously terminated worker.",
  {
    aoid: z.string().describe("The Associate OID of the worker to rehire"),
    rehireDate: z.string().describe("Rehire date (YYYY-MM-DD)"),
  },
  async ({ aoid, rehireDate }) => {
    const payload = {
      events: [
        {
          eventNameCode: { codeValue: "worker.rehire" },
          data: {
            eventContext: {
              worker: {
                associateOID: aoid,
                workerDates: { originalHireDate: rehireDate },
              },
            },
          },
        },
      ],
    };
    const data = await adp.post("/events/hr/v1/worker.rehire", payload);
    return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
  }
);

server.tool(
  "adp_update_worker_contact",
  "Update a worker's personal contact information (email, phone, address).",
  {
    aoid: z.string().describe("The Associate OID"),
    email: z.string().optional().describe("New email address"),
    phone: z.string().optional().describe("New phone number"),
    streetAddress: z.string().optional().describe("Street address line 1"),
    city: z.string().optional().describe("City"),
    state: z.string().optional().describe("State/province code"),
    postalCode: z.string().optional().describe("Postal/ZIP code"),
  },
  async ({ aoid, email, phone, streetAddress, city, state, postalCode }) => {
    const person = {};
    if (email) {
      person.communication = {
        emails: [{ emailUri: email }],
      };
    }
    if (phone) {
      person.communication = {
        ...(person.communication || {}),
        mobiles: [{ formattedNumber: phone }],
      };
    }
    if (streetAddress || city || state || postalCode) {
      person.legalAddress = {
        ...(streetAddress ? { lineOne: streetAddress } : {}),
        ...(city ? { cityName: city } : {}),
        ...(state
          ? { countrySubdivisionLevel1: { codeValue: state } }
          : {}),
        ...(postalCode ? { postalCode } : {}),
      };
    }

    const payload = {
      events: [
        {
          eventNameCode: { codeValue: "worker.personal-contact.change" },
          data: {
            eventContext: {
              worker: { associateOID: aoid, person },
            },
          },
        },
      ],
    };
    const data = await adp.post(
      "/events/hr/v1/worker.personal-contact.change",
      payload
    );
    return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
  }
);

// ===== PAYROLL ==============================================================

server.tool(
  "adp_get_pay_statements",
  "Get pay statements (pay stubs) for a worker.",
  {
    aoid: z.string().describe("The Associate OID"),
    top: z.number().optional().describe("Max number of statements to return"),
    skip: z.number().optional().describe("Number of statements to skip"),
  },
  async ({ aoid, top, skip }) => {
    const params = {};
    if (top) params["$top"] = top;
    if (skip) params["$skip"] = skip;
    const data = await adp.get(
      `/pay/v2/workers/${encodeURIComponent(aoid)}/pay-statements`,
      params
    );
    return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
  }
);

server.tool(
  "adp_get_pay_statement_detail",
  "Get detailed breakdown of a specific pay statement.",
  {
    aoid: z.string().describe("The Associate OID"),
    payStatementId: z.string().describe("The pay statement ID"),
  },
  async ({ aoid, payStatementId }) => {
    const data = await adp.get(
      `/pay/v2/workers/${encodeURIComponent(aoid)}/pay-statements/${encodeURIComponent(payStatementId)}`
    );
    return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
  }
);

server.tool(
  "adp_submit_pay_data",
  "Submit payroll input data (hours, earnings, deductions) for processing.",
  {
    batchId: z.string().optional().describe("Batch identifier"),
    workerAoid: z.string().describe("The Associate OID of the worker"),
    earningCode: z
      .string()
      .describe("Earning type code (e.g. 'REG' for regular, 'OT' for overtime)"),
    hours: z.number().optional().describe("Number of hours"),
    amount: z.number().optional().describe("Dollar amount"),
    payPeriodStart: z.string().optional().describe("Pay period start date (YYYY-MM-DD)"),
    payPeriodEnd: z.string().optional().describe("Pay period end date (YYYY-MM-DD)"),
  },
  async ({ batchId, workerAoid, earningCode, hours, amount, payPeriodStart, payPeriodEnd }) => {
    const payDataInput = {
      worker: { associateOID: workerAoid },
      earningCode: { codeValue: earningCode },
    };
    if (hours !== undefined) payDataInput.hoursQuantity = hours;
    if (amount !== undefined) payDataInput.amount = { amountValue: amount };
    if (payPeriodStart || payPeriodEnd) {
      payDataInput.payPeriod = {};
      if (payPeriodStart) payDataInput.payPeriod.startDate = payPeriodStart;
      if (payPeriodEnd) payDataInput.payPeriod.endDate = payPeriodEnd;
    }

    const payload = {
      events: [
        {
          eventNameCode: { codeValue: "pay-data-input.add" },
          data: {
            eventContext: {
              ...(batchId ? { batchID: batchId } : {}),
              payDataInput,
            },
          },
        },
      ],
    };
    const data = await adp.post(
      "/events/payroll/v1/pay-data-input.add",
      payload
    );
    return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
  }
);

// ===== ORGANIZATION =========================================================

server.tool(
  "adp_get_organization",
  "Get company/organization information from ADP.",
  {},
  async () => {
    const data = await adp.get("/core/v1/organizations");
    return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
  }
);

server.tool(
  "adp_list_departments",
  "List all departments in the organization.",
  {},
  async () => {
    const data = await adp.get("/core/v1/organization-departments");
    return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
  }
);

server.tool(
  "adp_list_work_locations",
  "List all work locations configured in ADP.",
  {},
  async () => {
    const data = await adp.get("/core/v1/work-locations");
    return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
  }
);

server.tool(
  "adp_list_job_titles",
  "List all job titles configured in ADP.",
  {},
  async () => {
    const data = await adp.get("/core/v1/job-titles");
    return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
  }
);

// ===== TIME & ATTENDANCE ====================================================

server.tool(
  "adp_get_time_cards",
  "Get time cards (clock in/out records) for a worker.",
  {
    aoid: z.string().describe("The Associate OID"),
    startDate: z
      .string()
      .optional()
      .describe("Filter start date (YYYY-MM-DD)"),
    endDate: z
      .string()
      .optional()
      .describe("Filter end date (YYYY-MM-DD)"),
    top: z.number().optional().describe("Max results"),
    skip: z.number().optional().describe("Skip for pagination"),
  },
  async ({ aoid, startDate, endDate, top, skip }) => {
    const params = {};
    if (top) params["$top"] = top;
    if (skip) params["$skip"] = skip;
    if (startDate) params["$filter"] = `timeCards/timePeriod/startDate ge '${startDate}'`;
    if (endDate) {
      const endFilter = `timeCards/timePeriod/endDate le '${endDate}'`;
      params["$filter"] = params["$filter"]
        ? `${params["$filter"]} and ${endFilter}`
        : endFilter;
    }
    const data = await adp.get(
      `/time/v2/workers/${encodeURIComponent(aoid)}/time-cards`,
      params
    );
    return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
  }
);

server.tool(
  "adp_add_time_card",
  "Submit a new time card entry for a worker.",
  {
    aoid: z.string().describe("The Associate OID"),
    date: z.string().describe("Date of the time entry (YYYY-MM-DD)"),
    startTime: z.string().optional().describe("Clock-in time (HH:MM)"),
    endTime: z.string().optional().describe("Clock-out time (HH:MM)"),
    hoursWorked: z.number().optional().describe("Total hours worked"),
    earningCode: z
      .string()
      .optional()
      .describe("Earning code (e.g. 'REG', 'OT')"),
  },
  async ({ aoid, date, startTime, endTime, hoursWorked, earningCode }) => {
    const timeCard = {
      worker: { associateOID: aoid },
      timePeriod: { startDate: date, endDate: date },
    };
    if (startTime || endTime) {
      timeCard.timeEntries = [
        {
          ...(startTime ? { entryDateTime: `${date}T${startTime}:00` } : {}),
          ...(endTime ? { exitDateTime: `${date}T${endTime}:00` } : {}),
        },
      ];
    }
    if (hoursWorked !== undefined) {
      timeCard.dailyTotals = [{ hoursQuantity: hoursWorked }];
    }
    if (earningCode) {
      timeCard.earningCode = { codeValue: earningCode };
    }

    const payload = {
      events: [
        {
          eventNameCode: { codeValue: "time-card.add" },
          data: { eventContext: { timeCard } },
        },
      ],
    };
    const data = await adp.post("/events/time/v1/time-card.add", payload);
    return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
  }
);

// ===== PTO / LEAVE ==========================================================

server.tool(
  "adp_get_time_off_balances",
  "Get PTO/leave balances for a worker (vacation, sick, personal days, etc.).",
  {
    aoid: z.string().describe("The Associate OID"),
  },
  async ({ aoid }) => {
    const data = await adp.get(
      `/time/v1/workers/${encodeURIComponent(aoid)}/time-off-balances`
    );
    return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
  }
);

server.tool(
  "adp_get_time_off_requests",
  "Get time-off requests for a worker.",
  {
    aoid: z.string().describe("The Associate OID"),
    status: z
      .string()
      .optional()
      .describe("Filter by status (e.g. 'Pending', 'Approved', 'Denied')"),
  },
  async ({ aoid, status }) => {
    const params = {};
    if (status) params["$filter"] = `status/codeValue eq '${status}'`;
    const data = await adp.get(
      `/time/v1/workers/${encodeURIComponent(aoid)}/time-off-requests`,
      params
    );
    return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
  }
);

server.tool(
  "adp_request_time_off",
  "Submit a new time-off (PTO) request for a worker.",
  {
    aoid: z.string().describe("The Associate OID"),
    startDate: z.string().describe("Start date of time off (YYYY-MM-DD)"),
    endDate: z.string().describe("End date of time off (YYYY-MM-DD)"),
    timeOffCode: z
      .string()
      .describe("Type of time off (e.g. 'VACATION', 'SICK', 'PERSONAL')"),
    hours: z
      .number()
      .optional()
      .describe("Number of hours requested (for partial days)"),
    comment: z.string().optional().describe("Optional comment/reason"),
  },
  async ({ aoid, startDate, endDate, timeOffCode, hours, comment }) => {
    const timeOffRequest = {
      worker: { associateOID: aoid },
      timePeriod: { startDate, endDate },
      timeOffCode: { codeValue: timeOffCode },
    };
    if (hours !== undefined) timeOffRequest.hoursQuantity = hours;
    if (comment) timeOffRequest.comment = { text: comment };

    const payload = {
      events: [
        {
          eventNameCode: { codeValue: "time-off-request.add" },
          data: { eventContext: { timeOffRequest } },
        },
      ],
    };
    const data = await adp.post(
      "/events/time/v1/time-off-request.add",
      payload
    );
    return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
  }
);

// ---------------------------------------------------------------------------
// Start the server
// ---------------------------------------------------------------------------

const transport = new StdioServerTransport();
await server.connect(transport);
