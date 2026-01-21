# Check-SslCert.ps1
# SSL/TLS certificate check for:
# HTTPS (443), SMTPS (465), IMAPS (993), POP3S (995)
# Windows PowerShell 5.1+ compatible
#
# Behavior:
# - First checks if the TCP port is open (Test-NetConnection).
# - If port is closed/unreachable: prints "server:port is not responding" (INFO) and skips TLS checks.
#   This is NOT treated as warning or error and does NOT affect exit code.
#
# Exit codes:
# 0 = OK, 1 = Warning, 2 = Error

[CmdletBinding()]
param(
    [string]$Server,
    [int]$WarnDays = 14,
    [switch]$Json,
    [string]$CsvPath,
    [string]$PinThumbprint  # optional expected thumbprint (no spaces)
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Normalize-Thumbprint {
    param([string]$Tp)
    if (-not $Tp) { return $null }
    return ($Tp -replace '\s','').ToUpperInvariant()
}

function Write-Status {
    param(
        [string]$Label,
        [string]$Value,
        [ValidateSet('OK','WARN','FAIL','INFO')]
        [string]$Level
    )
    $color = "Gray"
    if     ($Level -eq "OK")   { $color = "Green" }
    elseif ($Level -eq "WARN") { $color = "Yellow" }
    elseif ($Level -eq "FAIL") { $color = "Red" }
    elseif ($Level -eq "INFO") { $color = "Cyan" }

    Write-Host ("{0,-22} {1}" -f $Label, $Value) -ForegroundColor $color
}

function Get-CertificateNames {
    param(
        [Parameter(Mandatory=$true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert
    )

    $cn = $null
    if ($Cert.Subject -match "CN=([^,]+)") { $cn = $Matches[1].Trim() }

    $sans = New-Object System.Collections.Generic.List[string]
    foreach ($ext in $Cert.Extensions) {
        if ($ext.Oid -and $ext.Oid.Value -eq "2.5.29.17") { # Subject Alternative Name
            $formatted = $ext.Format($true)
            foreach ($line in ($formatted -split "(`r`n|`n|`r)")) {
                if ($line -match "DNS Name=(.+)$") {
                    $sans.Add($Matches[1].Trim()) | Out-Null
                }
            }
        }
    }

    $uniqueSans = @($sans | Select-Object -Unique)

    return [pscustomobject]@{
        CN   = $cn
        SANs = $uniqueSans
    }
}

function Test-HostnameMatch {
    param(
        [Parameter(Mandatory=$true)][string]$ServerName,
        [Parameter(Mandatory=$true)][string[]]$Names
    )

    $serverLower = $ServerName.Trim().ToLowerInvariant()

    foreach ($name in ($Names | Where-Object { $_ -and $_.Trim() -ne "" })) {
        $n = $name.Trim().ToLowerInvariant()

        if ($n -eq $serverLower) { return $true }

        # Wildcard covers exactly one label: *.example.com => a.example.com OK, a.b.example.com NOT OK
        if ($n.StartsWith("*.")) {
            $suffix = $n.Substring(1) # ".example.com"
            if ($serverLower.EndsWith($suffix)) {
                $serverLabels = $serverLower.Split(".").Count
                $suffixLabels = $suffix.TrimStart(".").Split(".").Count
                if ($serverLabels -eq ($suffixLabels + 1)) { return $true }
            }
        }
    }
    return $false
}

function Get-KeyInfo {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert)

    $algo = $null
    $size = $null

    try { $algo = $Cert.PublicKey.Oid.FriendlyName } catch { $algo = $null }
    try { $size = $Cert.PublicKey.Key.KeySize } catch { $size = $null }

    return [pscustomobject]@{
        Algorithm = $algo
        KeySize   = $size
    }
}

function Get-TlsCertificate {
    param(
        [Parameter(Mandatory=$true)][string]$Server,
        [Parameter(Mandatory=$true)][int]$Port
    )

    $tcp = New-Object System.Net.Sockets.TcpClient
    $tcp.ReceiveTimeout = 8000
    $tcp.SendTimeout    = 8000
    $tcp.Connect($Server, $Port)

    try {
        $stream = $tcp.GetStream()

        # Accept here; we validate ourselves later.
        $cb = [System.Net.Security.RemoteCertificateValidationCallback]{
            param($sender, $certificate, $chain, $sslPolicyErrors)
            return $true
        }

        $ssl = New-Object System.Net.Security.SslStream($stream, $false, $cb)
        $ssl.ReadTimeout  = 8000
        $ssl.WriteTimeout = 8000

        # SNI = Server
        $ssl.AuthenticateAsClient($Server)

        $remote = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($ssl.RemoteCertificate)

        # Build chain
        $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
        $chain.ChainPolicy.RevocationMode  = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::Online
        $chain.ChainPolicy.RevocationFlag  = [System.Security.Cryptography.X509Certificates.X509RevocationFlag]::ExcludeRoot
        $chain.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::NoFlag

        $chainOk = $chain.Build($remote)

        $chainStatus = @()
        $hasPartialChain = $false
        if ($chain.ChainStatus) {
            foreach ($st in $chain.ChainStatus) {
                $chainStatus += ($st.Status.ToString() + ": " + $st.StatusInformation.Trim())
                if ($st.Status.ToString() -eq "PartialChain") { $hasPartialChain = $true }
            }
        }

        $ssl.Close()

        return [pscustomobject]@{
            Cert            = $remote
            ChainOk         = $chainOk
            ChainStatus     = @($chainStatus)
            HasPartialChain = $hasPartialChain
        }
    }
    finally {
        $tcp.Close()
    }
}

function Load-CacheHashtable {
    param([string]$Path)

    $cache = @{ hosts = @{} }

    if (Test-Path -LiteralPath $Path) {
        try {
            $raw = Get-Content -LiteralPath $Path -Raw
            if ($raw -and $raw.Trim().Length -gt 0) {
                $obj = $raw | ConvertFrom-Json
                if ($obj -and $obj.hosts) {
                    foreach ($hprop in $obj.hosts.PSObject.Properties) {
                        $serverKey = $hprop.Name
                        $cache.hosts[$serverKey] = @{ endpoints = @{} }

                        $endpointsObj = $hprop.Value.endpoints
                        if ($endpointsObj) {
                            foreach ($eprop in $endpointsObj.PSObject.Properties) {
                                $epKey = $eprop.Name
                                $cache.hosts[$serverKey].endpoints[$epKey] = @{
                                    serial     = $eprop.Value.serial
                                    thumbprint = $eprop.Value.thumbprint
                                    lastSeen   = $eprop.Value.lastSeen
                                }
                            }
                        }
                    }
                }
            }
        } catch {
            # ignore corrupted cache
        }
    }

    return $cache
}

function Save-CacheHashtable {
    param([string]$Path, [hashtable]$Cache)
    try { $Cache | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $Path -Encoding UTF8 } catch { }
}

function Test-PortOpen {
    param(
        [string]$Server,
        [int]$Port,
        [int]$TimeoutMs = 3000
    )

    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $iar = $client.BeginConnect($Server, $Port, $null, $null)
        $success = $iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)

        if (-not $success) {
            $client.Close()
            return $false
        }

        $client.EndConnect($iar)
        $client.Close()
        return $true
    } catch {
        return $false
    }
}


# --- Input ---
if (-not $Server -or [string]::IsNullOrWhiteSpace($Server)) {
    $Server = (Read-Host "Enter server (e.g., mail.example.com)").Trim()
}
if ([string]::IsNullOrWhiteSpace($Server)) {
    Write-Host "No server provided. Exiting." -ForegroundColor Red
    exit 2
}

$PinThumbprint = Normalize-Thumbprint $PinThumbprint

$services = @(
    @{ Name="HTTPS"; Port=443 },
    @{ Name="SMTPS"; Port=465 },
    @{ Name="IMAPS"; Port=993 },
    @{ Name="POP3S"; Port=995 }
)

$scriptDir = $PSScriptRoot
if (-not $scriptDir) { $scriptDir = (Get-Location).Path }
$cachePath = Join-Path $scriptDir ".sslcert_cache.json"
$cache = Load-CacheHashtable -Path $cachePath

if (-not $cache.hosts.ContainsKey($Server)) {
    $cache.hosts[$Server] = @{ endpoints = @{} }
}
if (-not $cache.hosts[$Server].ContainsKey("endpoints")) {
    $cache.hosts[$Server].endpoints = @{}
}

Write-Host ""
Write-Host ("SSL/TLS certificate check for: {0}" -f $Server) -ForegroundColor Cyan
Write-Host ("Date: {0}" -f (Get-Date)) -ForegroundColor DarkGray
Write-Host ""

$allResults = New-Object System.Collections.Generic.List[object]
$anyFail = $false
$anyWarn = $false
$thumbprintsByService = @{}

foreach ($svc in $services) {
    $svcName = $svc.Name
    $port = [int]$svc.Port
    $endpointKey = "{0}:{1}" -f $svcName, $port

    Write-Host ("=== {0} (port {1}) ===" -f $svcName, $port) -ForegroundColor Yellow

    # 1) Port check first
    $portOpen = Test-PortOpen -Server $Server -Port $port
    if (-not $portOpen) {
        Write-Status -Label "Port status:" -Value ("{0}:{1} is not responding" -f $Server, $port) -Level "INFO"

        $allResults.Add([pscustomobject]@{
            ServerTarget = $Server
            Service      = $svcName
            Port         = $port
            Overall      = "SKIPPED"
            Reason       = "Port not responding"
        }) | Out-Null

        Write-Host ""
        continue
    }

    # 2) TLS checks only if port is open
    try {
        $res  = Get-TlsCertificate -Server $Server -Port $port
        $cert = $res.Cert
        $now  = Get-Date

        $names = Get-CertificateNames -Cert $cert

        $allNames = @()
        if ($names.CN) { $allNames += $names.CN }
        $sansArray = @($names.SANs)
        if ($sansArray.Count -gt 0) { $allNames += $sansArray }
        $allNames = @($allNames | Select-Object -Unique)

        $hostnameOk = Test-HostnameMatch -ServerName $Server -Names $allNames
        $dateOk = (($now -ge $cert.NotBefore) -and ($now -lt $cert.NotAfter))
        $daysLeft = [math]::Floor(($cert.NotAfter - $now).TotalDays)

        $chainOk = [bool]$res.ChainOk
        $chainCompleteOk = -not [bool]$res.HasPartialChain
        $selfSigned = ($cert.Subject -eq $cert.Issuer)

        $keyInfo = Get-KeyInfo -Cert $cert
        $keyAlgo = if ($keyInfo.Algorithm) { $keyInfo.Algorithm } else { "(unknown)" }
        $keySize = $keyInfo.KeySize
        $keyMsg  = if ($keySize) { "$keyAlgo $keySize" } else { $keyAlgo }

        $keyOk = $true
        if ($keyAlgo -match "RSA" -and $keySize -and $keySize -lt 2048) { $keyOk = $false }
        if ($keyAlgo -match "DSA") { $keyOk = $false }

        $sigName = $cert.SignatureAlgorithm.FriendlyName
        if (-not $sigName) { $sigName = "(unknown)" }
        $sigOk = $true
        if ($sigName -match "sha1" -or $sigName -match "md5") { $sigOk = $false }

        $issuer = $cert.Issuer
        $validityDays = [math]::Round(($cert.NotAfter - $cert.NotBefore).TotalDays)

        $thumbprint = Normalize-Thumbprint $cert.Thumbprint
        $pinOk = $true
        if ($PinThumbprint) { if ($thumbprint -ne $PinThumbprint) { $pinOk = $false } }

        # Serial change detection (cache)
        $serial = $cert.SerialNumber
        $prevSerial = $null
        $serialChanged = $false

        if ($cache.hosts[$Server].endpoints.ContainsKey($endpointKey)) {
            $prevSerial = $cache.hosts[$Server].endpoints[$endpointKey].serial
            if ($prevSerial -and $prevSerial -ne $serial) { $serialChanged = $true }
        } else {
            $cache.hosts[$Server].endpoints[$endpointKey] = @{ }
        }

        $cache.hosts[$Server].endpoints[$endpointKey].serial = $serial
        $cache.hosts[$Server].endpoints[$endpointKey].thumbprint = $thumbprint
        $cache.hosts[$Server].endpoints[$endpointKey].lastSeen = (Get-Date).ToString("o")

        # Warnings (only: expiry + serial change)
        $expireWarn = ($daysLeft -le $WarnDays -and $daysLeft -ge 0)
        $serialWarn = $serialChanged

        # Hard failures
        $hardOk = ($hostnameOk -and $dateOk -and $chainOk -and $chainCompleteOk -and (-not $selfSigned) -and $keyOk -and $sigOk -and $pinOk)

        $overallLevel = "OK"
        if (-not $hardOk) { $overallLevel = "FAIL" }
        elseif ($expireWarn -or $serialWarn) { $overallLevel = "WARN" }

        Write-Status -Label "Overall result:" -Value $overallLevel -Level $overallLevel

        Write-Host ("Subject CN:           {0}" -f ($(if ($names.CN) { $names.CN } else { "(no CN)" })))
        Write-Host ("SAN (DNS):            {0}" -f ($(if ($sansArray.Count -gt 0) { ($sansArray -join ", ") } else { "(no SAN)" })))
        Write-Host ("Issuer:               {0}" -f $issuer)
        Write-Host ("Valid from:           {0}" -f $cert.NotBefore)
        Write-Host ("Valid until:          {0}  ({1} days left)" -f $cert.NotAfter, $daysLeft)
        Write-Host ("Validity length:      {0} days" -f $validityDays)
        Write-Host ("Thumbprint:           {0}" -f $thumbprint)
        Write-Host ("Serial:               {0}" -f $serial)
        Write-Host ("Key:                  {0}" -f $keyMsg)
        Write-Host ("Signature:            {0}" -f $sigName)

        Write-Status -Label "Hostname match:" -Value ($(if ($hostnameOk) { "OK" } else { "FAILED (CN/SAN mismatch)" })) -Level ($(if ($hostnameOk) { "OK" } else { "FAIL" }))
        Write-Status -Label "Date validity:"  -Value ($(if ($dateOk) { "OK" } else { "FAILED (expired/not yet valid)" })) -Level ($(if ($dateOk) { "OK" } else { "FAIL" }))
        Write-Status -Label "Chain trust:"    -Value ($(if ($chainOk) { "OK" } else { "FAILED" })) -Level ($(if ($chainOk) { "OK" } else { "FAIL" }))
        Write-Status -Label "Chain complete:" -Value ($(if ($chainCompleteOk) { "OK" } else { "FAILED (missing intermediate / PartialChain)" })) -Level ($(if ($chainCompleteOk) { "OK" } else { "FAIL" }))
        Write-Status -Label "Self-signed:"    -Value ($(if (-not $selfSigned) { "No" } else { "Yes" })) -Level ($(if (-not $selfSigned) { "OK" } else { "FAIL" }))
        Write-Status -Label "Key strength:"   -Value ($(if ($keyOk) { "OK ($keyMsg)" } else { "WEAK ($keyMsg)" })) -Level ($(if ($keyOk) { "OK" } else { "FAIL" }))
        Write-Status -Label "Signature hash:" -Value ($(if ($sigOk) { "OK ($sigName)" } else { "WEAK/DEPRECATED ($sigName)" })) -Level ($(if ($sigOk) { "OK" } else { "FAIL" }))

        Write-Status -Label "Expiry warning:" -Value ($(if (-not $expireWarn) { "No" } else { "Yes (<= $WarnDays days)" })) -Level ($(if (-not $expireWarn) { "OK" } else { "WARN" }))
        Write-Status -Label "Serial changed:" -Value ($(if (-not $serialWarn) { "No" } else { "Yes (previous: $prevSerial)" })) -Level ($(if (-not $serialWarn) { "OK" } else { "WARN" }))

        if ($PinThumbprint) {
            Write-Status -Label "Pinning:" -Value ($(if ($pinOk) { "OK" } else { "FAILED (thumbprint mismatch)" })) -Level ($(if ($pinOk) { "OK" } else { "FAIL" }))
        }

        if (-not $chainOk -and @($res.ChainStatus).Count -gt 0) {
            Write-Host "Chain details:" -ForegroundColor Red
            foreach ($s in @($res.ChainStatus)) { Write-Host ("  - {0}" -f $s) -ForegroundColor Red }
        }

        $thumbprintsByService[$svcName] = $thumbprint

        if ($overallLevel -eq "FAIL") { $anyFail = $true }
        elseif ($overallLevel -eq "WARN") { $anyWarn = $true }

        $allResults.Add([pscustomobject]@{
            ServerTarget     = $Server
            Service          = $svcName
            Port             = $port
            Overall          = $overallLevel
            PortOpen         = $true
            HostnameMatch    = $hostnameOk
            DateValid        = $dateOk
            ChainTrusted     = $chainOk
            ChainComplete    = $chainCompleteOk
            SelfSigned       = $selfSigned
            KeyAlgorithm     = $keyAlgo
            KeySize          = $keySize
            Signature        = $sigName
            CN               = $names.CN
            SANs             = ($sansArray -join ", ")
            Issuer           = $issuer
            NotBefore        = $cert.NotBefore
            NotAfter         = $cert.NotAfter
            DaysLeft         = $daysLeft
            ValidityDays     = $validityDays
            Thumbprint       = $thumbprint
            Serial           = $serial
            ExpiryWarn       = $expireWarn
            SerialChanged    = $serialWarn
            Pinned           = ([bool]$PinThumbprint)
            PinOk            = $pinOk
        }) | Out-Null

    } catch {
        $anyFail = $true
        Write-Status -Label "Overall result:" -Value "FAIL" -Level "FAIL"
        Write-Host ("Error:                {0}" -f $_.Exception.Message) -ForegroundColor Red

        $allResults.Add([pscustomobject]@{
            ServerTarget = $Server
            Service      = $svcName
            Port         = $port
            Overall      = "FAIL"
            PortOpen     = $true
            Error        = $_.Exception.Message
        }) | Out-Null
    }

    Write-Host ""
}

# Same certificate across services (only among ports that were checked)
if ($thumbprintsByService.Keys.Count -gt 1) {
    $uniqueTps = @($thumbprintsByService.Values | Select-Object -Unique)
    if ($uniqueTps.Count -eq 1) {
        Write-Status -Label "Cert reuse:" -Value "OK (same certificate on all checked services)" -Level "OK"
    } else {
        Write-Status -Label "Cert reuse:" -Value "Different certificates across checked services" -Level "WARN"
        $anyWarn = $true
    }
    Write-Host ""
}

# Save cache
Save-CacheHashtable -Path $cachePath -Cache $cache

# CSV export
if ($CsvPath) {
    try {
        $allResults | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $CsvPath
        Write-Status -Label "CSV export:" -Value ("Saved to {0}" -f $CsvPath) -Level "INFO"
    } catch {
        Write-Status -Label "CSV export:" -Value ("Failed: {0}" -f $_.Exception.Message) -Level "WARN"
        $anyWarn = $true
    }
}

# JSON output
if ($Json) {
    $allResults | ConvertTo-Json -Depth 10
}

# Exit code
if ($anyFail) {
    Write-Host "Done. Exit code: 2 (Error)" -ForegroundColor Red
    exit 2
} elseif ($anyWarn) {
    Write-Host "Done. Exit code: 1 (Warning)" -ForegroundColor Yellow
    exit 1
} else {
    Write-Host "Done. Exit code: 0 (OK)" -ForegroundColor Green
    exit 0
}
