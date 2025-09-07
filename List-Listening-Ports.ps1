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
  if (Test-Path $Path -PathType Leaf) {
    $SizeKB = (Get-Item $Path).Length / 1KB
    if ($SizeKB -ge $MaxKB) {
      for ($i = $Keep - 1; $i -ge 0; $i--) {
        $Old = "$Path.$i"
        $New = "$Path." + ($i + 1)
        if (Test-Path $Old) { Rename-Item $Old $New -Force }
      }
      Rename-Item $Path "$Path.1" -Force
    }
  }
}

function Write-Log {
  param ([ValidateSet('INFO','WARN','ERROR','DEBUG')] [string]$Level, [string]$Message)
  $Timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
  $line = "[$Timestamp][$Level] $Message"
  switch ($Level) {
    'ERROR' { Write-Host $line -ForegroundColor Red }
    'WARN'  { Write-Host $line -ForegroundColor Yellow }
    'DEBUG' { if ($PSCmdlet.MyInvocation.BoundParameters.ContainsKey('Verbose')) { Write-Verbose $line } default { } }
    default { Write-Host $line }
  }
  Add-Content -Path $LogPath -Value $line -Encoding utf8
}

function To-ISO8601 {
  param($dt)
  if ($dt -and $dt -is [datetime] -and $dt.Year -gt 1900) { $dt.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } else { $null }
}

function New-NdjsonLine { param([hashtable]$Data) ($Data | ConvertTo-Json -Compress -Depth 7) }

function Write-NDJSONLines {
  param([string[]]$JsonLines, [string]$Path = $ARLog)
  $tmp = Join-Path $env:TEMP ("arlog_{0}.tmp" -f ([guid]::NewGuid().ToString("N")))
  $dir = Split-Path -Parent $Path
  if ($dir -and -not (Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
  $payload = ($JsonLines -join [Environment]::NewLine) + [Environment]::NewLine
  Set-Content -Path $tmp -Value $payload -Encoding ascii -Force
  try { Move-Item -Path $tmp -Destination $Path -Force }
  catch { Move-Item -Path $tmp -Destination ($Path + '.new') -Force }
}

Rotate-Log -Path $LogPath -MaxKB $LogMaxKB -Keep $LogKeep
Write-Log INFO "=== SCRIPT START : List Listening Ports (host=$HostName) ==="

try {
  $netConnections = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
                    Select-Object LocalPort, OwningProcess, LocalAddress
  $udpConnections = Get-NetUDPEndpoint -ErrorAction SilentlyContinue |
                    Select-Object LocalPort, OwningProcess, LocalAddress

  $udpConnections | ForEach-Object { $_ | Add-Member -NotePropertyName Protocol -NotePropertyValue 'UDP' -Force }
  $netConnections | ForEach-Object { $_ | Add-Member -NotePropertyName Protocol -NotePropertyValue 'TCP' -Force }

  $connections = @()
  if ($netConnections) { $connections += $netConnections }
  if ($udpConnections) { $connections += $udpConnections }

  $results = foreach ($conn in $connections) {
    $proc = $null
    try { $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue } catch {}
    $exePath = $null
    try { if ($proc) { $exePath = $proc.Path } } catch {}
    [PSCustomObject]@{
      Protocol       = $conn.Protocol
      LocalPort      = $conn.LocalPort
      LocalAddress   = $conn.LocalAddress
      ProcessName    = ($proc.ProcessName)
      ProcessId      = $conn.OwningProcess
      ExecutablePath = $exePath
    }
  }

  $tsNow = To-ISO8601 (Get-Date)
  $standardPorts = @(80, 443, 135, 139, 445, 3389)

  $totalCount = ($results | Measure-Object).Count

  if ($totalCount -eq 0) {
    $nores = New-NdjsonLine @{
      timestamp      = $tsNow
      host           = $HostName
      action         = 'list_listening_ports'
      copilot_action = $true
      item           = 'status'
      status         = 'no_results'
      description    = 'No listening TCP/UDP ports found'
    }
    Write-NDJSONLines -JsonLines @($nores) -Path $ARLog
    Write-Log INFO "No listening ports; wrote status line to AR log"
    Write-Log INFO "=== SCRIPT END : List Listening Ports ==="
    return
  }

  $flaggedCount = 0
  $lines = New-Object System.Collections.ArrayList

  # Summary first
  [void]$lines.Add( (New-NdjsonLine @{
    timestamp      = $tsNow
    host           = $HostName
    action         = 'list_listening_ports'
    copilot_action = $true
    item           = 'summary'
    description    = 'Run summary and counts'
    total_ports    = $totalCount
  }) )

  # One line per port (self-describing)
  foreach ($r in $results) {
    $reasons = @()
    if ($r.LocalPort -notin $standardPorts) { $reasons += 'nonstandard_port' }
    if ($r.ExecutablePath -match '\\AppData\\') { $reasons += 'path_AppData' }
    if ($r.ExecutablePath -match '\\Temp\\')    { $reasons += 'path_Temp' }
    if (-not $r.ExecutablePath -or $r.ExecutablePath -eq '') { $reasons += 'unknown_executable_path' }

    $isFlagged = $reasons.Count -gt 0
    if ($isFlagged) { $flaggedCount++ }

    $desc = "Listening $($r.Protocol) on $($r.LocalAddress):$($r.LocalPort) by '$($r.ProcessName)' (PID $($r.ProcessId)); flagged=" + ([bool]$isFlagged)

    [void]$lines.Add( (New-NdjsonLine @{
      timestamp       = $tsNow
      host            = $HostName
      action          = 'list_listening_ports'
      copilot_action  = $true
      item            = 'port'
      description     = $desc
      protocol        = $r.Protocol
      local_port      = $r.LocalPort
      local_address   = $r.LocalAddress
      process_name    = $r.ProcessName
      process_id      = $r.ProcessId
      executable_path = $r.ExecutablePath
      flagged         = $isFlagged
      reasons         = $reasons
      standard_ports  = $standardPorts
    }) )
  }

  $lines[0] = (New-NdjsonLine @{
    timestamp      = $tsNow
    host           = $HostName
    action         = 'list_listening_ports'
    copilot_action = $true
    item           = 'summary'
    description    = 'Run summary and counts'
    total_ports    = $totalCount
    flagged_ports  = $flaggedCount
  })

  Write-NDJSONLines -JsonLines $lines -Path $ARLog
  Write-Log INFO ("Wrote {0} NDJSON record(s) to {1}" -f $lines.Count, $ARLog)

  Write-Host ("Collected {0} listening ports. Flagged {1}." -f $totalCount, $flaggedCount) -ForegroundColor Cyan
  if ($flaggedCount -gt 0) {
    Write-Host "`nFlagged Listening Ports:" -ForegroundColor Yellow
    $results | Where-Object {
      ($_ -and $_.LocalPort -notin $standardPorts) -or
      ($_.ExecutablePath -match '\\AppData\\' -or $_.ExecutablePath -match '\\Temp\\') -or
      (-not $_.ExecutablePath)
    } | Select-Object Protocol, LocalPort, ProcessName, ExecutablePath |
      Format-Table -AutoSize
  } else {
    Write-Host "`nNo suspicious ports or processes detected." -ForegroundColor Green
  }

} catch {
  Write-Log ERROR ("Failed to enumerate listening ports: {0}" -f $_.Exception.Message)
  $err = New-NdjsonLine @{
    timestamp      = To-ISO8601 (Get-Date)
    host           = $HostName
    action         = 'list_listening_ports'
    copilot_action = $true
    item           = 'error'
    description    = 'Unhandled error'
    error          = $_.Exception.Message
  }
  Write-NDJSONLines -JsonLines @($err) -Path $ARLog
  Write-Log INFO "Error NDJSON written to AR log"
}
finally {
  Write-Log INFO "=== SCRIPT END : List Listening Ports ==="
}
