# Deploy SOC Copilot from GitHub to Render

## 1. GitHub

The repository root must contain `server.js`, `package.json`, `render.yaml`, `public/`, `data/` and the project documentation.

Never commit `.env` or real API credentials.

## 2. Render

Use **New → Blueprint** or **New → Web Service** and connect the GitHub repository.

The included `render.yaml` uses:

```text
Runtime: Node
Start command: node server.js
Health check: /api/health
```

## 3. Required Render environment variables

Set at minimum:

```text
AUTH_REQUIRED=true
SOC_COPILOT_USERNAME=<competition demo username>
SOC_COPILOT_PASSWORD=<strong competition demo password>
SOC_COPILOT_DISPLAY_NAME=Demo Analyst
DEMO_MODE=true
DEMO_PERSIST_WRITES=false
ALLOW_CLOUD_CASE_CONTEXT=true
```

Do not place the username/password in GitHub.

## 4. Optional integrations

Configure only integrations approved for the demo. CTI API keys can be added server-side. Keep real SIEM/EDR credentials out of a public competition environment unless explicitly authorized.

## 5. Validate after deployment

Open:

```text
https://<your-render-service>.onrender.com/api/health
```

Expected properties include:

```json
{"ok":true,"version":"9.0.0","demo_mode":true,"auth_required":true}
```

Then open the base URL and verify the login page, Smart Intake, Workbench, Ask SOC Copilot, SOP export and Audit Logs.

## Competition submission

Submit both when the form supports them:

- **GitHub repository URL** — source / architecture / documentation.
- **Live Render URL** — judges can sign in and use the product in a browser.

If the repository must be publicly accessible, change GitHub repository visibility to **Public** before submission.


## Verify live Ask SOC Copilot

After deployment, open the Workbench and click **Test AI**. The chat badge should show **Live AI · <model> · streaming**. Ask a case-specific question and confirm the answer appears progressively. If it shows **Local fallback**, verify `ANTHROPIC_API_KEY`, `CLAUDE_MODEL`, and `ALLOW_CLOUD_CASE_CONTEXT=true` in Render environment variables.