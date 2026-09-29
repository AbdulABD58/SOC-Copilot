# SOC Copilot — Security Model

## Final competition build controls

The hosted demo is designed to be safer than the original localhost prototype:

- username/password authentication with server-side in-memory sessions;
- `HttpOnly`, `SameSite=Strict` session cookie and session expiry;
- login throttling and global request rate limiting;
- protected `/api/*` routes except health/authentication endpoints;
- same-origin checks for mutating API requests;
- CSP, frame blocking, MIME sniffing protection, referrer and permissions policies;
- API credentials remain server-side;
- public-demo mode disables direct SIEM execution by default;
- server-side SPL/KQL safety validation exists for enterprise-mode direct query execution;
- private/internal IPv4 addresses and `.local`/`.internal` domains are not sent to external CTI by default;
- cloud case-context transmission is disabled by default;
- prompt-injection instructions explicitly treat alerts/logs/email/CTI/tickets as untrusted data;
- final verdict remains human-selected;
- no automated blocking, account disablement, ticket closure or endpoint isolation.

## Public competition deployment

Recommended Render variables:

```text
AUTH_REQUIRED=true
DEMO_MODE=true
DEMO_PERSIST_WRITES=false
ALLOW_CLOUD_CASE_CONTEXT=true  # competition live-chat mode; set false to keep case context local
SOC_COPILOT_USERNAME=<judge/demo username>
SOC_COPILOT_PASSWORD=<strong unique password>
SESSION_TTL_MIN=240
```

Do not add production SIEM/EDR credentials to the public competition environment unless explicitly approved.

## Production gaps to close

Before commercial production, add:

1. SSO / Entra ID / OIDC and RBAC rather than demo username/password.
2. Durable, append-only audit storage.
3. Database-backed cases, SOPs, client profiles and tenant isolation.
4. Managed secrets / key vault.
5. OAuth/service identities with least privilege and rotation.
6. CSRF token framework if browser cross-origin patterns expand.
7. Centralized rate limiting for multi-instance deployments.
8. DLP/redaction policy for cloud AI usage.
9. Formal SPL/KQL allowlisting and query-cost controls.
10. SAST/SCA/DAST, penetration testing and dependency governance.
11. Monitoring, alerting, backup, disaster recovery and retention policy.
12. Client-specific contractual/privacy review for external CTI and AI processing.