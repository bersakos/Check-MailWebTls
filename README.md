# Check-MailWebTls.ps1 – Manual

## Overview

`Check-MailWebTls.ps1` is a PowerShell script for checking **TLS/SSL certificates**
used by common **mail and web services** on a host:

- HTTPS (443)
- SMTPS (465)
- IMAPS (993)
- POP3S (995)

The script is designed for **operations, monitoring, and CI/CD usage** and works on:

- Windows PowerShell **5.1+**
- PowerShell **7+**

---

## What the script does

For each supported service/port, the script:

1. **Checks if the TCP port is open**
   - Uses a fast TCP connection test with a configurable timeout
   - If the port is not responding:
     - It is **reported as informational**
     - No TLS checks are performed
     - It does **NOT** count as warning or error

2. **If the port is open, performs TLS checks**
   - Retrieves the server certificate
   - Validates hostname (CN / SAN, including wildcard rules)
   - Validates certificate dates
   - Builds and verifies the certificate chain
   - Detects self-signed certificates
   - Checks key algorithm and key size
   - Checks signature hash algorithm
   - Calculates validity length
   - Detects certificate changes between runs (serial number tracking)
   - Optional certificate pinning (thumbprint)

3. **Outputs color-coded results**
   - Green  → OK
   - Yellow → Warning
   - Red    → Error
   - Cyan   → Informational

4. **Returns meaningful exit codes**
   - Suitable for automation and monitoring systems

---

## Checked services

| Service | Port |
|---------|------|
|  HTTPS  | 443  |
|  SMTPS  | 465  |
|  IMAPS  | 993  |
|  POP3S  | 995  |

---

## Requirements

- Windows PowerShell 5.1 or newer  
- Network access to the target host  
- Permissions to run scripts (`Set-ExecutionPolicy` if needed)

---

## Usage

### Interactive mode

```powershell
.\Check-MailWebTls.ps1
