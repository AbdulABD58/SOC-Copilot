# SOC Copilot — Architecture

```text
Browser UI
  │
  ├─ Authentication session
  │
  ▼
SOC Copilot Node Backend
  ├─ Smart Intake parser
  ├─ Scenario-driven reasoning
  ├─ Contextual Ask SOC Copilot assistant
  ├─ Evidence-based verdict guidance
  ├─ SOP generator + export service
  ├─ Integration gateway
  └─ Demo security policy / rate limiting
       │
       ├─ Threat Intel: VirusTotal / AbuseIPDB / GreyNoise / MISP
       ├─ SIEM: Splunk / Microsoft Sentinel / Google SecOps
       ├─ EDR/XDR: CrowdStrike / Defender XDR
       ├─ ITSM: ServiceNow
       ├─ Email: Proofpoint / Microsoft Graph
       └─ Collaboration: Teams
```

## Core design principle

The AI reasoning layer is separate from deterministic controls. AI may interpret ambiguous evidence and recommend the next investigation step. Deterministic application logic governs authentication, API boundaries, demo-mode restrictions, exports and required human verdict selection.

## Demo persistence

The competition build uses browser/local demo state and packaged JSON starter content. SOP writes are ephemeral by default in public demo mode. A commercial deployment should replace this with tenant-aware durable storage.