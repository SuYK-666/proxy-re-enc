# Scenario Templates

## Medical Data Delegation

| Field | Value |
|---|---|
| Owner | Hospital department |
| Recipient | Consulting doctor |
| Policy | `allowPreview=true`, `allowDownload=false`, short expiry |
| Audit Focus | Diagnosis access and revoke evidence |

## Enterprise Outsourcing

| Field | Value |
|---|---|
| Owner | Enterprise document owner |
| Recipient | External contractor |
| Policy | download allowed, reshare denied, max download count |
| Audit Focus | Package id guessing, revoke after contract ends |

## Research Data Sharing

| Field | Value |
|---|---|
| Owner | Dataset maintainer |
| Recipient | Research collaborator |
| Policy | purpose-bound grant, expiry, benchmarkable large files |
| Audit Focus | Grant policy hash, content key version, reproducible audit proof |
