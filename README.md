# PowerShell List Listening Ports Template

This repository provides a template for PowerShell-based active response scripts for security automation and incident response. The template ensures consistent logging, error handling, and execution flow for enumerating all listening TCP/UDP ports and their associated processes.

---

## Overview

The `List-Listening-Ports.ps1` script enumerates all listening TCP and UDP ports on the system, collects associated process information, flags non-standard ports and suspicious process paths (such as those running from AppData or Temp), and logs all actions, results, and errors in both a script log and an active-response log. This makes it suitable for integration with SOAR platforms, SIEMs, and incident response workflows.

---

## Template Structure

### Core Components

- **Parameter Definitions**: Configurable script parameters
- **Logging Framework**: Consistent logging with timestamps and rotation
- **Flagging Logic**: Identifies non-standard ports and suspicious process paths
- **JSON Output**: Standardized response format
- **Execution Timing**: Performance monitoring

---

## How Scripts Are Invoked

### Command Line Execution

```powershell
.\List-Listening-Ports.ps1 [-LogPath <string>] [-ARLog <string>]
```

### Parameters

| Parameter | Type   | Default Value                                                    | Description                                  |
|-----------|--------|------------------------------------------------------------------|----------------------------------------------|
| `LogPath` | string | `$env:TEMP\List-Listening-Ports.log`                             | Path for execution logs                      |
| `ARLog`   | string | `C:\Program Files (x86)\ossec-agent\active-response\active-responses.log` | Path for active response JSON output         |

---

### Example Invocations

```powershell
# Basic execution with default parameters
.\List-Listening-Ports.ps1

# Custom log path
.\List-Listening-Ports.ps1 -LogPath "C:\Logs\ListeningPorts.log"

# Integration with OSSEC/Wazuh active response
.\List-Listening-Ports.ps1 -ARLog "C:\ossec\active-responses.log"
```

---

## Template Functions

### `Write-Log`
**Purpose**: Standardized logging with severity levels and console output.

**Parameters**:
- `Level` (string): Log level - 'INFO', 'WARN', 'ERROR', 'DEBUG'
- `Message` (string): The log message

**Features**:
- Timestamped output
- File logging

**Usage**:
```powershell
Write-Log INFO "Collected $($results.Count) listening ports. Flagged $($flagged.Count)."
Write-Log ERROR "Failed to enumerate listening ports: $_"
```

---

### `Rotate-Log`
**Purpose**: Manages log file size and rotation.

**Features**:
- Monitors log file size (default: 100KB)
- Maintains a configurable number of backups (default: 5)
- Rotates logs automatically

**Configuration Variables**:
- `$LogMaxKB`: Max log file size in KB
- `$LogKeep`: Number of rotated logs to retain

---

### `Log-JSON`
**Purpose**: Appends structured JSON results to the active response log.

**Parameters**:
- `Data`: The data object to log
- `Type` (string): The type of report (e.g., 'listening_ports_full', 'listening_ports_flagged')

---

## Script Execution Flow

1. **Initialization**
   - Parameter validation and assignment
   - Error action preference
   - Log rotation

2. **Execution**
   - Enumerates all listening TCP and UDP ports and associated processes
   - Flags:
     - Non-standard ports (not in 80, 443, 135, 139, 445, 3389)
     - Processes running from AppData or Temp
   - Logs findings

3. **Completion**
   - Outputs full inventory and flagged ports as JSON to the active response log
   - Logs script end and duration
   - Displays summary in console

4. **Error Handling**
   - Catches and logs exceptions
   - Outputs error details to the log

---

## JSON Output Format

### Full Report Example

```json
{
  "timestamp": "2025-07-22T10:30:45.123Z",
  "hostname": "HOSTNAME",
  "type": "listening_ports_full",
  "data": [
    {
      "Protocol": "TCP",
      "LocalPort": 8080,
      "LocalAddress": "0.0.0.0",
      "ProcessName": "example.exe",
      "ProcessId": 1234,
      "ExecutablePath": "C:\\Users\\user\\AppData\\Local\\Temp\\example.exe"
    }
  ]
}
```

### Flagged Ports Example

```json
{
  "timestamp": "2025-07-22T10:30:45.123Z",
  "hostname": "HOSTNAME",
  "type": "listening_ports_flagged",
  "data": [
    {
      "Protocol": "TCP",
      "LocalPort": 8080,
      "LocalAddress": "0.0.0.0",
      "ProcessName": "example.exe",
      "ProcessId": 1234,
      "ExecutablePath": "C:\\Users\\user\\AppData\\Local\\Temp\\example.exe"
    }
  ]
}
```

---

## Implementation Guidelines

1. Use the provided logging and error handling functions.
2. Customize the flagging logic as needed for your environment.
3. Ensure JSON output matches your SOAR/SIEM requirements.
4. Test thoroughly in a non-production environment.

---

## Security Considerations

- Run with the minimum required privileges.
- Validate all input parameters.
- Secure log files and output locations.
- Monitor for errors and failed inventory.

---

## Troubleshooting

- **Permission Errors**: Run as Administrator.
- **Process Access Issues**: Some system processes may be inaccessible.
- **Log Output**: Check file permissions and disk space.

---

## License

This template is provided as-is for security
