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

function Log-JSON {
    param ($Data, [string]$Type)
    $Entry = @{
        timestamp = (Get-Date).ToString('o')
        hostname  = $HostName
        type      = $Type
        data      = $Data
    } | ConvertTo-Json -Depth 5 -Compress
    Add-Content -Path $ARLog -Value $Entry
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
            Protocol = $conn.Protocol
            LocalPort = $conn.LocalPort
            LocalAddress = $conn.LocalAddress
            ProcessName = $proc.ProcessName
            ProcessId = $conn.OwningProcess
            ExecutablePath = $path
        }
    }
    $standardPorts = @(80,443,135,139,445,3389)
    $flagged = $results | Where-Object {
        ($_ -and $_.LocalPort -notin $standardPorts) -or
        ($_.ExecutablePath -match '\\AppData\\' -or $_.ExecutablePath -match '\\Temp\\')
    }
    Log-JSON -Data $results -Type 'listening_ports_full'
    Log-JSON -Data $flagged -Type 'listening_ports_flagged'
    Write-Log INFO "Collected $($results.Count) listening ports. Flagged $($flagged.Count)."
    Write-Host "Collected $($results.Count) listening ports. Flagged $($flagged.Count)." -ForegroundColor Cyan

    if ($flagged.Count -gt 0) {
        Write-Host "`nFlagged Listening Ports:" -ForegroundColor Yellow
        $flagged | Format-Table Protocol,LocalPort,ProcessName,ExecutablePath -AutoSize
    } else {
        Write-Host "`nNo suspicious ports or processes detected." -ForegroundColor Green
    }

    Write-Host "`nJSON reports (full + flagged) appended to $ARLog" -ForegroundColor Gray
    Write-Log INFO "JSON reports (full + flagged) appended to $ARLog"
}
catch {
    Write-Log ERROR "Failed to enumerate listening ports: $_"
    Write-Host "ERROR: Failed to enumerate listening ports. See $LogPath for details." -ForegroundColor Red
}

Write-Log INFO "=== SCRIPT END : List Listening Ports ==="
