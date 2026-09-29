# SOC Copilot v9.2 — Final Competition Edition

> **“Our Copilot assists you decide what you don't yet know how to decide.”**  
> **AI-guided. Analyst-decided.**

SOC Copilot is a human-in-the-loop L1 security analyst assistant that turns raw alerts into structured, explainable investigations and carries the analyst from first signal to an auditable decision, reusable SOP knowledge, and shift handoff.

## The problem it solves

L1 analysts routinely jump between SIEM/EDR/email tooling, CTI portals, SOPs, tickets and handoff notes. New or ambiguous alerts increase cognitive load, documentation quality varies by analyst, and context is easily lost between shifts. SOC Copilot provides one guided workflow while keeping every final security decision under human control.

## End-to-end workflow

**Raw Alert → Smart Intake → Dynamic Investigation → Platform Pivots → CTI → Ask SOC Copilot → Documentation → Evidence-based Verdict Guidance → Human Verdict → Client/Global SOP → Export → Shift Handoff → Audit**

## Product modules

1. **Smart Intake** — paste raw alert/ticket/email text; dynamically extract platform, alert family, severity, entities, IOCs and rule conditions.
2. **Analyst Workbench** — case interpretation, detailed scenario-specific triage, platform-native pivots, CTI, editable documentation and decision support.
3. **Ask SOC Copilot** — context-aware investigation chat that understands the active case, triage progress, CTI and documentation. Analyst can explicitly add useful answers to documentation, triage or an SOP draft.
4. **Evidence-based Verdict Guidance** — confidence and missing-evidence guidance updates as the investigation progresses. **SOC Copilot never selects the final verdict.**
5. **SOP Library** — detailed SOP templates for identity, phishing, endpoint/malware, ransomware, C2/network and full investigations.
6. **Client Profiles / SOP overlays** — client name/code, industry, region, SIEM, EDR, email security, identity, classification, approver and escalation path can be applied to generated SOPs.
7. **SOP Export** — download SOPs as **PDF, DOCX, Markdown or JSON**.
8. **Integration Hub** — 14 connector definitions across CTI, SIEM, EDR/XDR, ITSM, email, collaboration and AI.
9. **Shift Handoff** — editable AI-drafted handoff from analyst-closed/open cases.
10. **Audit Logs** — searchable and exportable record of analyst and AI-assisted workflow events.
11. **Settings** — UI density/tile sizing, documentation standards, privacy defaults, guardrails, SOP governance and client profiles.
12. **Authentication** — username/password sign-in with server-side sessions, HttpOnly cookies, expiry and login throttling for hosted demos.

## Integrations

**Threat Intelligence:** VirusTotal, AbuseIPDB, GreyNoise, MISP  
**SIEM:** Splunk, Microsoft Sentinel, Google SecOps  
**EDR/XDR:** CrowdStrike Falcon, Microsoft Defender XDR  
**Ticketing:** ServiceNow  
**Email:** Proofpoint TAP, Microsoft Graph / Outlook  
**Collaboration:** Microsoft Teams  
**AI reasoning:** Claude API (optional; local scenario-driven reasoning works without a key)

### Public-demo safety defaults

The Render blueprint intentionally starts with:

- `AUTH_REQUIRED=true`
- `DEMO_MODE=true`
- `DEMO_PERSIST_WRITES=false`
- `ALLOW_CLOUD_CASE_CONTEXT=true` (required for live Ask SOC Copilot when the API key is configured)

Generated SIEM queries remain available for demonstration while direct live SIEM execution stays disabled by default. Live chat sends the active case context to the configured AI provider only because the operator has explicitly enabled `ALLOW_CLOUD_CASE_CONTEXT=true`; set it back to `false` for local-only case guidance.

## Run locally

Requirements: Node.js 18+.

```bash
npm test
node server.js
```

Default local URL:

```text
http://127.0.0.1:4220/?v=9.0.0
```

On Windows you can also double-click `START_HERE.bat`.

Authentication is optional locally unless `AUTH_REQUIRED=true` is configured.

## Configure authentication

Never commit real credentials. Set them in `.env` locally or in Render Environment Variables:

```text
AUTH_REQUIRED=true
SOC_COPILOT_USERNAME=<demo username>
SOC_COPILOT_PASSWORD=<strong demo password>
SOC_COPILOT_DISPLAY_NAME=Demo Analyst
SESSION_TTL_MIN=240
```

For enterprise rollout, replace demo credentials with SSO/Entra ID or another approved identity provider and role-based access control.

## Configure live integrations

Copy `.env.example` to `.env` for local use. Add only credentials that are approved for the environment. Secrets stay server-side and are never returned to browser JavaScript.

See `INTEGRATIONS.md` and `SECURITY.md` before connecting organizational data.

## SOP export formats

| Format | Intended use |
|---|---|
| PDF | Controlled distribution / client-ready copy |
| DOCX | Editable operational and review document |
| Markdown | GitHub, GitBook, wiki and engineering documentation |
| JSON | Re-import, API integration and versioned machine-readable exchange |

## Competition demo flow

1. Sign in.
2. Paste the Splunk brute-force sample in **Smart Intake**.
3. Review extraction and open the **Analyst Workbench**.
4. Generate the dynamic investigation and show detailed triage.
5. Show platform-native Splunk pivots and public-demo read-only guardrail.
6. Enrich the public IP using available CTI integrations.
7. Ask **SOC Copilot** what evidence is missing and add an accepted answer to documentation.
8. Recalculate verdict guidance and show that the analyst still owns the final verdict.
9. Create a client-specific SOP from the investigation.
10. Download it as PDF or DOCX.
11. Show the Integration Hub, Shift Handoff and Audit Logs.

## Human-control boundary

SOC Copilot may recommend, explain and draft. It does **not** autonomously:

- close tickets,
- choose the final verdict,
- suppress detections,
- block indicators,
- disable accounts,
- isolate endpoints, or
- perform containment.

Those decisions remain with authorized humans and existing security controls.

## Validation

Run:

```bash
npm test
```

The final smoke test verifies dynamic extraction, scenario-driven reasoning, contextual chat, evidence-based verdict guidance, integration catalog, public-demo SIEM guardrails, private-IOC egress protection, PDF/DOCX/Markdown/JSON SOP exports, and authenticated API protection.

## Deployment

The repository includes `render.yaml`. See `DEPLOYMENT.md` for GitHub → Render deployment and required environment variables.

## Production note

This is a competition/demo edition designed to demonstrate the product workflow safely. A commercial deployment should add enterprise SSO/RBAC, tenant isolation, a durable system-of-record for cases/SOPs/audit, managed secrets, approved OAuth/service identities, observability, data-retention policies and formal security/privacy review.

## Live Ask SOC Copilot

The chat has two clearly identified modes:

- **Live AI · streaming** — open-ended contextual answers stream into the workbench token-by-token using the configured Claude API. Follow-up questions include recent chat history plus the active case, triage, CTI, documentation and verdict guidance.
- **Local fallback** — deterministic case guidance when a cloud model is unavailable. It never blocks the analyst workflow.

For real-time conversational answers on Render, configure these environment variables:

```text
ANTHROPIC_API_KEY=<your approved server-side key>
ANTHROPIC_BASE_URL=https://api.anthropic.com
CLAUDE_MODEL=claude-sonnet-4-6
ALLOW_CLOUD_CASE_CONTEXT=true
```

The key stays server-side and is never returned to the browser. The chat header shows **Live AI** only when the server is actually ready to use cloud case reasoning. The `/api/chat/stream` endpoint uses newline-delimited streaming events so the analyst sees the answer as it is generated. If the live model fails, the same question falls back to local case-aware guidance instead of leaving a blank or frozen chat. Use **Test AI** in the chat panel or Integration Hub to validate connectivity.