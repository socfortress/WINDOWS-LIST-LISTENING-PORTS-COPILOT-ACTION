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
    $flagged = $results | Where-Object {
        ($_ -and $_.LocalPort -notin $standardPorts) -or
        ($_.ExecutablePath -match '\\AppData\\' -or $_.ExecutablePath -match '\\Temp\\')
    }
    $report = [PSCustomObject]@{
        timestamp = (Get-Date).ToString('o')
        hostname  = $HostName
        type      = 'listening_ports'
        total_ports = $results.Count
        flagged_ports = $flagged.Count
        all_ports = $results
        flagged   = $flagged
        copilot_action = $true
    }
    $json = $report | ConvertTo-Json -Depth 5 -Compress
    $tempFile = "$env:TEMP\arlog.tmp"
    Set-Content -Path $tempFile -Value $json -Encoding ascii -Force

    try {
        Move-Item -Path $tempFile -Destination $ARLog -Force
        Write-Log INFO "Log file replaced at $ARLog"
    } catch {
        Move-Item -Path $tempFile -Destination "$ARLog.new" -Force
        Write-Log WARN "Log locked, wrote results to $ARLog.new"
    }
    Write-Log INFO "Collected $($results.Count) listening ports. Flagged $($flagged.Count)."
    Write-Host "Collected $($results.Count) listening ports. Flagged $($flagged.Count)." -ForegroundColor Cyan

    if ($flagged.Count -gt 0) {
        Write-Host "`nFlagged Listening Ports:" -ForegroundColor Yellow
        $flagged | Format-Table Protocol,LocalPort,ProcessName,ExecutablePath -AutoSize
    } else {
        Write-Host "`nNo suspicious ports or processes detected." -ForegroundColor Green
    }

    Write-Host "`nResults written to $ARLog (or .new if locked)" -ForegroundColor Gray
}
catch {
    Write-Log ERROR "Failed to enumerate listening ports: $_"
    $errorObj = [PSCustomObject]@{
        timestamp = (Get-Date).ToString('o')
        hostname  = $HostName
        type      = 'listening_ports'
        status    = 'error'
        error     = $_.Exception.Message
        copilot_action = $true
    }
    $json = $errorObj | ConvertTo-Json -Compress
    $fallback = "$ARLog.new"
    Set-Content -Path $fallback -Value $json -Encoding ascii -Force
    Write-Log WARN "Error logged to $fallback"
}

Write-Log INFO "=== SCRIPT END : List Listening Ports ==="

