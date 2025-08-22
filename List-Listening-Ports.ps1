[CmdletBinding()]
param (
    [string]$LogPath = "$env:TEMP\List-Listening-Ports.log",
    [string]$ARLog   = 'C:\Program Files (x86)\ossec-agent\active-response\active-responses.log'
)

$ErrorActionPreference = 'Stop'
$HostName  = $env:COMPUTERNAME
$LogMaxKB  = 100
$LogKeep   = 5

function Rotate-Log {
    param ([string]$Path, [int]$MaxKB, [int]$Keep)
    if (Test-Path $Path) {
        $SizeKB = (Get-Item $Path).Length / 1KB
        if ($SizeKB -ge $MaxKB) {
            for ($i = $Keep; $i -ge 1; $i--) {
                $Old = "$Path.$i"
                $New = "$Path.$($i + 1)"
                if (Test-Path $Old) { Rename-Item $Old $New -Force }
            }
            Rename-Item $Path "$Path.1" -Force
        }
    }
}

function Write-Log {
    param ([string]$Level, [string]$Message)
    $Timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
    Add-Content -Path $LogPath -Value "[$Timestamp][$Level] $Message"
}

Rotate-Log -Path $LogPath -MaxKB $LogMaxKB -Keep $LogKeep
Write-Log INFO "=== SCRIPT START : List Listening Ports ==="

try {
    $netConnections = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
                      Select-Object LocalPort, OwningProcess, LocalAddress
    $udpConnections = Get-NetUDPEndpoint -ErrorAction SilentlyContinue |
                      Select-Object LocalPort, OwningProcess, LocalAddress

    $udpConnections | ForEach-Object { $_ | Add-Member -NotePropertyName Protocol -NotePropertyValue "UDP" -Force }
    $netConnections | ForEach-Object { $_ | Add-Member -NotePropertyName Protocol -NotePropertyValue "TCP" -Force }

    $connections = $netConnections + $udpConnections

    $results = foreach ($conn in $connections) {
        $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
        $path = $null
        try { $path = $proc.Path } catch {}
        [PSCustomObject]@{
            Protocol       = $conn.Protocol
            LocalPort      = $conn.LocalPort
            LocalAddress   = $conn.LocalAddress
            ProcessName    = $proc.ProcessName
            ProcessId      = $conn.OwningProcess
            ExecutablePath = $path
        }
    }

    $standardPorts = @(80,443,135,139,445,3389)

    $lines = @()

    # Summary line first (NDJSON)
    $flaggedCount = 0
    $totalCount   = ($results | Measure-Object).Count
    $summaryObj = [PSCustomObject]@{
        timestamp      = (Get-Date).ToString('o')
        host           = $HostName
        action         = 'list_listening_ports'
        total_ports    = $totalCount
        copilot_action = $true
    }
    $lines += ($summaryObj | ConvertTo-Json -Compress -Depth 3)

    foreach ($r in $results) {
        $reasons = @()
        if ($r.LocalPort -notin $standardPorts) { $reasons += 'nonstandard_port' }
        if ($r.ExecutablePath -match '\\AppData\\') { $reasons += 'path_AppData' }
        if ($r.ExecutablePath -match '\\Temp\\')    { $reasons += 'path_Temp' }
        $isFlagged = $reasons.Count -gt 0
        if ($isFlagged) { $flaggedCount++ }

        $lines += ([PSCustomObject]@{
            timestamp       = (Get-Date).ToString('o')
            host            = $HostName
            action          = 'list_listening_ports'
            protocol        = $r.Protocol
            local_port      = $r.LocalPort
            local_address   = $r.LocalAddress
            process_name    = $r.ProcessName
            process_id      = $r.ProcessId
            executable_path = $r.ExecutablePath
            flagged         = $isFlagged
            reasons         = if ($reasons.Count) { ($reasons -join ',') } else { $null }
            copilot_action  = $true
        } | ConvertTo-Json -Compress -Depth 4)
    }

    # Replace the summary line with final flagged count (keep it as the first NDJSON line)
    $lines[0] = ([PSCustomObject]@{
        timestamp      = $summaryObj.timestamp
        host           = $HostName
        action         = 'list_listening_ports'
        total_ports    = $totalCount
        flagged_ports  = $flaggedCount
        copilot_action = $true
    } | ConvertTo-Json -Compress -Depth 3)

    $ndjson = [string]::Join("`n", $lines)

    $tempFile = "$env:TEMP\arlog.tmp"
    Set-Content -Path $tempFile -Value $ndjson -Encoding ascii -Force

    $recordCount = $lines.Count
    try {
        Move-Item -Path $tempFile -Destination $ARLog -Force
        Write-Log INFO "Wrote $recordCount NDJSON record(s) to $ARLog"
    } catch {
        Move-Item -Path $tempFile -Destination "$ARLog.new" -Force
        Write-Log WARN "ARLog locked; wrote to $($ARLog).new"
    }

    Write-Log INFO "Collected $totalCount listening ports. Flagged $flaggedCount."
    Write-Host "Collected $totalCount listening ports. Flagged $flaggedCount." -ForegroundColor Cyan

    if ($flaggedCount -gt 0) {
        Write-Host "`nFlagged Listening Ports:" -ForegroundColor Yellow
        $results | Where-Object {
            ($_ -and $_.LocalPort -notin $standardPorts) -or
            ($_.ExecutablePath -match '\\AppData\\' -or $_.ExecutablePath -match '\\Temp\\')
        } | Format-Table Protocol,LocalPort,ProcessName,ExecutablePath -AutoSize
    } else {
        Write-Host "`nNo suspicious ports or processes detected." -ForegroundColor Green
    }

    Write-Host "`nResults written to $ARLog (or .new if locked)" -ForegroundColor Gray
}
catch {
    Write-Log ERROR "Failed to enumerate listening ports: $_"
    $errorObj = [PSCustomObject]@{
        timestamp      = (Get-Date).ToString('o')
        host           = $HostName
        action         = 'list_listening_ports'
        status         = 'error'
        error          = $_.Exception.Message
        copilot_action = $true
    }
    $ndjson = ($errorObj | ConvertTo-Json -Compress -Depth 3)
    $tempFile = "$env:TEMP\arlog.tmp"
    Set-Content -Path $tempFile -Value $ndjson -Encoding ascii -Force
    try {
        Move-Item -Path $tempFile -Destination $ARLog -Force
        Write-Log INFO "Error JSON written to $ARLog"
    } catch {
        Move-Item -Path $tempFile -Destination "$ARLog.new" -Force
        Write-Log WARN "ARLog locked; wrote error to $($ARLog).new"
    }
}

Write-Log INFO "=== SCRIPT END : List Listening Ports ==="
