# SOC Copilot — Integration Hub

## Design principle

The browser never receives connector secrets. The UI calls the SOC Copilot backend, which performs approved server-side lookups and normalizes evidence for the analyst.

**Default posture: read-only first.** Security-impacting actions such as isolation, blocking, account disablement, suppression or ticket closure are intentionally outside autonomous execution.

## Prebuilt adapters

| Integration | Category | Primary capability | Demo execution |
|---|---|---|---|
| VirusTotal | Threat Intelligence | IP/domain/URL/hash reputation | Live lookup |
| AbuseIPDB | Threat Intelligence | IP abuse context | Live lookup |
| GreyNoise | Threat Intelligence | Internet noise / RIOT / classification | Live lookup |
| MISP | Threat Intelligence | Internal/community sightings | Live lookup |
| Splunk | SIEM | SPL pivots and results | Read-only query on analyst click |
| Microsoft Sentinel | SIEM | KQL pivots and results | Read-only query on analyst click |
| Google SecOps | SIEM | UDM pivots | Query generation + adapter health |
| CrowdStrike Falcon | EDR/XDR | Host/detection/IOC context | Connector health scaffold |
| Microsoft Defender XDR | EDR/XDR | Alert/endpoint context | Connector health scaffold |
| ServiceNow | ITSM | Incident/SLA/owner context | Read-only health scaffold |
| Proofpoint TAP | Email Security | Message/click/threat context | Read-only health scaffold |
| Outlook / Graph | Mail | Security mailbox context | Read-only health scaffold |
| Microsoft Teams | Collaboration | Handoff / ACK channel | Explicit-send integration scaffold |
| Claude | AI | Shared reasoning engine | Live reasoning when configured |

## Add a new tool

Open **Integrations → + Add Integration**. The form creates a Draft connector specification containing name, category, base URL, auth model and capabilities. It intentionally does not collect secrets.

To enable the Draft connector in production:

1. Implement a server-side adapter function.
2. Define server-side environment variables / secret-store references.
3. Add a non-destructive health test.
4. Define whether it is read-only or write-capable.
5. Require explicit analyst confirmation for any write-capable operation.
6. Add normalization so the workbench receives consistent evidence objects.

## Configuration

See `.env.example` for supported environment variable names.