# OSForensicator Data Collection Script using Osquery for Windows
# Version: 1.0

$Version = '1.0'
Write-Host "Version: $Version"
Write-Host "OSForensicator for Windows"
Write-Host "==========================================="

# Check if running as Administrator
$IsAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent() `
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if ($IsAdmin) {
    Write-Host "OSForensicator starting as Administrator..."
} else {
    Write-Host "No Administrator session detected. For best performance, run as Administrator. Not all data can be collected..."
}

# Check if osquery is available
try {
    $osqueryPath = (Get-Command osqueryi -ErrorAction Stop).Source
    Write-Host "Osquery found at: $osqueryPath"
} catch {
    Write-Host "Error: Osquery executable (osqueryi) not found. Please ensure osquery is installed and in your PATH." -ForegroundColor Red
    Write-Host "You can download osquery from: https://osquery.io/downloads"
    Exit 1
}

# Create output directory
$CurrentPath = $pwd
$ExecutionTime = $(Get-Date -f yyyy-MM-dd)
$ComputerName = $env:COMPUTERNAME
$FolderCreation = "$CurrentPath\OSForensicator-$ComputerName-$ExecutionTime"
mkdir -Force $FolderCreation | Out-Null
Write-Host "Output directory created: $FolderCreation..."

# CSV Output folder for SIEM import
$CSVOutputFolder = "$FolderCreation\CSV Results (SIEM Import Data)"
mkdir -Force $CSVOutputFolder | Out-Null
Write-Host "SIEM Export output directory created: $CSVOutputFolder..."

# Log file for timestamp module
$LogFile = "$FolderCreation\ExecutionLog.txt"
function Write-Log {
    param([string]$Message)
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$Timestamp - $Message" | Out-File -FilePath $LogFile -Append -Encoding UTF8
}

Write-Log "OSForensicator started."

# List of available data collection headers
$AvailableHeaders = [ordered]@{
    "System Information"       = "System Information"
    "IP Information"          = "IP Information"
    "Open Connections"        = "Open Connections"
    "Autorun Information"     = "Autorun Information"
    "Drivers"                 = "Drivers"
    "Users Information"       = "Users Information"
    "Process Information"     = "Process Information"
    "Process Hashes"          = "Process Hashes"
    "Security Events"         = "Security Events"
    "Network Shares"          = "Network Shares"
    "DNS Cache"               = "DNS Cache"
    "RDP Sessions"            = "RDP Sessions"
    "Installed Software"      = "Installed Software"
    "Running Services"        = "Running Services"
    "Scheduled Tasks"         = "Scheduled Tasks"
    "Connected Devices"       = "Connected Devices"
    "Browser History"         = "Browser History"
    "Windows Defender Data"   = "Windows Defender Data"
    "PowerShell History"      = "PowerShell History"
    "Additional System Info"  = "Additional System Info"
}

# User interface: Select headers
Write-Host "`nSelect which data to collect (enter numbers separated by commas, e.g., 1,3,5):"
$i = 1
foreach ($header in $AvailableHeaders.Keys) {
    Write-Host "$i. $($AvailableHeaders[$header])"
    $i++
}
$UserSelection = Read-Host "Make your selection (type 'all' for all)"
if ($UserSelection -eq "all") {
    $SelectedHeaders = $AvailableHeaders.Keys
} else {
    $SelectedIndices = $UserSelection -split "," | ForEach-Object { [int]$_.Trim() - 1 }
    $SelectedHeaders = ($AvailableHeaders.Keys | Select-Object -Index $SelectedIndices)
}

Write-Log "Selected headers: $($SelectedHeaders -join ', ')"

# User interface: Data collection time window
$SearchWindow = Read-Host "How many days of data to collect? (default: 2 days)"
if ([string]::IsNullOrEmpty($SearchWindow)) { $SearchWindow = 2 }
$SearchWindowTimestamp = [int][double]::Parse($(Get-Date (Get-Date).AddDays(-$SearchWindow) -UFormat %s))
Write-Host "Collecting data from the last $SearchWindow days..."
Write-Log "Data collection time window: $SearchWindow days"

# Function to run osquery queries
function Run-OsqueryQuery {
    param(
        [string]$Query,
        [string]$OutputFile,
        [string]$CsvFile,
        [string]$Directory = ""
    )
    $StartTime = Get-Date
    Write-Log "Data collection for $OutputFile started."
    
    if ($Directory) {
        $OutputPath = "$FolderCreation\$Directory"
        mkdir -Force $OutputPath | Out-Null
        $FullOutputFile = "$OutputPath\$OutputFile"
    } else {
        $FullOutputFile = "$FolderCreation\$OutputFile"
    }
    
    try {
        & $osqueryPath --json "$Query" | Out-File -FilePath $FullOutputFile -Encoding UTF8
        & $osqueryPath --csv "$Query" | Out-File -FilePath "$CSVOutputFolder\$CsvFile" -Encoding UTF8
        Write-Host "Data saved to $FullOutputFile and $CSVOutputFolder\$CsvFile."
    } catch {
        Write-Host "Error: Failed to collect $OutputFile." -ForegroundColor Red
        Write-Log "Error: Failed to collect $OutputFile - $_"
    }
    
    $EndTime = Get-Date
    Write-Log "Data collection for $OutputFile completed. Duration: $($EndTime - $StartTime).TotalSeconds seconds"
}

# Data collection functions
function Collect-Data {
    param([string]$Header)
    switch ($Header) {
        "System Information" {
            Write-Host "Collecting system information..."
            Run-OsqueryQuery -Query "SELECT * FROM system_info" -OutputFile "system_info.txt" -CsvFile "SystemInfo.csv"
        }
        "IP Information" {
            Write-Host "Collecting IP information..."
            Run-OsqueryQuery -Query "SELECT interface, address, mask, type FROM interface_addresses" -OutputFile "ipinfo.txt" -CsvFile "IPConfiguration.csv"
        }
        "Open Connections" {
            Write-Host "Collecting open connections..."
            Run-OsqueryQuery -Query "SELECT local_address, local_port, remote_address, remote_port, state, pid FROM process_open_sockets WHERE state='ESTABLISHED'" `
                -OutputFile "OpenConnections.txt" -CsvFile "OpenTCPConnections.csv" -Directory "Connections"
        }
        "Autorun Information" {
            Write-Host "Collecting autorun information..."
            Run-OsqueryQuery -Query "SELECT name, path, source, status, username FROM startup_items" `
                -OutputFile "AutoRunInfo.txt" -CsvFile "AutoRun.csv" -Directory "Persistence"
        }
        "Drivers" {
            Write-Host "Collecting drivers..."
            Run-OsqueryQuery -Query "SELECT description, path, signed, version FROM drivers" `
                -OutputFile "InstalledDrivers.txt" -CsvFile "Drivers.csv" -Directory "Persistence"
        }
        "Users Information" {
            Write-Host "Collecting users information..."
            Run-OsqueryQuery -Query "SELECT uid, gid, username, description, directory, shell, type FROM users" `
                -OutputFile "LocalUsers.txt" -CsvFile "LocalUsers.csv" -Directory "UserInformation"
            Run-OsqueryQuery -Query "SELECT user, tty, host, time, pid FROM logged_in_users" `
                -OutputFile "ActiveUsers.txt" -CsvFile "ActiveUsers.csv" -Directory "UserInformation"
        }
        "Process Information" {
            Write-Host "Collecting process information..."
            Run-OsqueryQuery -Query "SELECT pid, name, path, cmdline, parent, start_time FROM processes" `
                -OutputFile "ProcessList.txt" -CsvFile "Processes.csv" -Directory "ProcessInformation"
        }
        "Process Hashes" {
            Write-Host "Collecting process hashes..."
            $StartTime = Get-Date
            Write-Log "Data collection for process hashes started."
            $HashesFolder = "$FolderCreation\ProcessInformation"
            mkdir -Force $HashesFolder | Out-Null
            $HashesOutput = "$HashesFolder\UniqueProcessHash.csv"
            $HashesSIEM = "$CSVOutputFolder\ProcessHashes.csv"
            $ProcessesJson = & $osqueryPath --json "SELECT DISTINCT path FROM processes WHERE path IS NOT NULL"
            $Processes = $ProcessesJson | ConvertFrom-Json
            "path,sha256" | Out-File -FilePath $HashesOutput -Encoding UTF8
            "path,sha256" | Out-File -FilePath $HashesSIEM -Encoding UTF8
            foreach ($Process in $Processes) {
                $Path = $Process.path
                if ($Path -and (Test-Path $Path -ErrorAction SilentlyContinue)) {
                    try {
                        $Hash = (Get-FileHash -Algorithm SHA256 -Path $Path).Hash
                        "$Path,$Hash" | Out-File -FilePath $HashesOutput -Append -Encoding UTF8
                        "$Path,$Hash" | Out-File -FilePath $HashesSIEM -Append -Encoding UTF8
                    } catch {
                        Write-Log "Error: Failed to get hash for $Path - $_"
                    }
                }
            }
            $EndTime = Get-Date
            Write-Log "Data collection for process hashes completed. Duration: $($EndTime - $StartTime).TotalSeconds seconds"
        }
        "Security Events" {
            if ($IsAdmin) {
                Write-Host "Collecting security events (last $SearchWindow days)..."
                $EventsFolder = "$FolderCreation\SecurityEvents"
                mkdir -Force $EventsFolder | Out-Null
                Run-OsqueryQuery -Query "SELECT eventid, COUNT(*) AS count FROM windows_events WHERE source='Security' AND time > $SearchWindowTimestamp GROUP BY eventid ORDER BY count DESC" `
                    -OutputFile "EventCount.txt" -CsvFile "SecurityEventCount.csv" -Directory "SecurityEvents"
                Run-OsqueryQuery -Query "SELECT time, datetime(time, 'unixepoch') AS time_human, source, eventid, task, level, data FROM windows_events WHERE source='Security' AND time > $SearchWindowTimestamp" `
                    -OutputFile "SecurityEvents.txt" -CsvFile "SecurityEvents.csv" -Directory "SecurityEvents"
            } else {
                Write-Host "Administrator privileges required for security events." -ForegroundColor Yellow
            }
        }
        "Network Shares" {
            Write-Host "Collecting network shares..."
            Run-OsqueryQuery -Query "SELECT * FROM shared_resources" `
                -OutputFile "SMBShares.txt" -CsvFile "SMBShares.csv" -Directory "Connections"
        }
        "DNS Cache" {
            Write-Host "Collecting DNS cache..."
            Run-OsqueryQuery -Query "SELECT * FROM dns_cache" `
                -OutputFile "DNSCache.txt" -CsvFile "DNSCache.csv" -Directory "Connections"
        }
        "RDP Sessions" {
            Write-Host "Collecting RDP sessions..."
            Run-OsqueryQuery -Query "SELECT * FROM logged_in_users WHERE type='remote'" `
                -OutputFile "RDPSessions.txt" -CsvFile "RDPSessions.csv" -Directory "Connections"
        }
        "Installed Software" {
            Write-Host "Collecting installed software..."
            Run-OsqueryQuery -Query "SELECT name, version, install_date, install_location, install_source, language, publisher FROM programs" `
                -OutputFile "InstalledSoftware.txt" -CsvFile "InstalledSoftware.csv" -Directory "Applications"
        }
        "Running Services" {
            Write-Host "Collecting running services..."
            Run-OsqueryQuery -Query "SELECT name, display_name, start_type, path, status, pid FROM services WHERE status='RUNNING'" `
                -OutputFile "RunningServices.txt" -CsvFile "RunningServices.csv" -Directory "Services"
        }
        "Scheduled Tasks" {
            Write-Host "Collecting scheduled tasks..."
            Run-OsqueryQuery -Query "SELECT name, action, path, enabled, last_run_time, next_run_time FROM scheduled_tasks WHERE enabled=1" `
                -OutputFile "ScheduledTasksList.txt" -CsvFile "ScheduledTasks.csv" -Directory "ScheduledTask"
        }
        "Connected Devices" {
            Write-Host "Collecting connected devices..."
            Run-OsqueryQuery -Query "SELECT * FROM device_events" `
                -OutputFile "DeviceEvents.txt" -CsvFile "DeviceEvents.csv" -Directory "ConnectedDevices"
        }
        "Browser History" {
            if ($IsAdmin) {
                Write-Host "Collecting browser history..."
                $BrowserFolder = "$FolderCreation\Browsers"
                mkdir -Force $BrowserFolder | Out-Null
                Run-OsqueryQuery -Query "SELECT url, title, visit_count, datetime(last_visit_time/1000000-11644473600, 'unixepoch') AS last_visit FROM chrome_history" `
                    -OutputFile "ChromeHistory.txt" -CsvFile "ChromeHistory.csv" -Directory "Browsers"
                Run-OsqueryQuery -Query "SELECT url, title, visit_count, datetime(last_visit_date/1000000, 'unixepoch') AS last_visit FROM firefox_history" `
                    -OutputFile "FirefoxHistory.txt" -CsvFile "FirefoxHistory.csv" -Directory "Browsers"
                Run-OsqueryQuery -Query "SELECT url, title, visit_count, datetime(last_visit_time/1000000-11644473600, 'unixepoch') AS last_visit FROM chromium_history WHERE profile_path LIKE '%MicrosoftEdge%'" `
                    -OutputFile "EdgeHistory.txt" -CsvFile "EdgeHistory.csv" -Directory "Browsers"
            } else {
                Write-Host "Administrator privileges required for browser history." -ForegroundColor Yellow
            }
        }
        "Windows Defender Data" {
            Write-Host "Collecting Windows Defender data..."
            $DefenderFolder = "$FolderCreation\DefenderExclusions"
            mkdir -Force $DefenderFolder | Out-Null
            Run-OsqueryQuery -Query "SELECT * FROM windows_security_center" `
                -OutputFile "SecurityCenter.txt" -CsvFile "SecurityCenter.csv" -Directory "DefenderExclusions"
            Run-OsqueryQuery -Query "SELECT path, name, data FROM registry WHERE path LIKE 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions%'" `
                -OutputFile "DefenderExclusions.txt" -CsvFile "DefenderExclusions.csv" -Directory "DefenderExclusions"
        }
        "PowerShell History" {
            Write-Host "Collecting PowerShell history..."
            $PSFolder = "$FolderCreation\PowerShellHistory"
            mkdir -Force $PSFolder | Out-Null
            $CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name.Split('\')[1]
            $PSHistoryPath = "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
            if (Test-Path $PSHistoryPath) {
                Copy-Item $PSHistoryPath -Destination "$PSFolder\$CurrentUser`_PowerShell_History.txt"
                Get-Content $PSHistoryPath | ConvertTo-Csv -NoTypeInformation | Out-File "$CSVOutputFolder\PowerShellHistory.csv" -Encoding UTF8
            }
            if ($IsAdmin) {
                $UsersDir = "C:\Users"
                $UserDirs = Get-ChildItem -Path $UsersDir -Directory
                foreach ($UserDir in $UserDirs) {
                    $HistoryPath = Join-Path -Path $UserDir.FullName -ChildPath "AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
                    if (Test-Path $HistoryPath) {
                        $UserName = $UserDir.Name
                        Copy-Item $HistoryPath -Destination "$PSFolder\${UserName}_PowerShell_History.txt" -Force
                    }
                }
            }
        }
        "Additional System Info" {
            Write-Host "Collecting additional system information..."
            Run-OsqueryQuery -Query "SELECT * FROM os_version" -OutputFile "OSVersion.txt" -CsvFile "OSVersion.csv"
            Run-OsqueryQuery -Query "SELECT * FROM system_info" -OutputFile "SystemInfo.txt" -CsvFile "SystemInfo.csv"
            Run-OsqueryQuery -Query "SELECT * FROM patches" -OutputFile "Patches.txt" -CsvFile "Patches.csv"
        }
    }
}

# Collect data based on selected headers
foreach ($Header in $SelectedHeaders) {
    Collect-Data -Header $Header
}

# Compress results
Write-Host "Writing results to $FolderCreation.zip..."
Compress-Archive -Force -LiteralPath $FolderCreation -DestinationPath "$FolderCreation.zip"

Write-Log "OSForensicator data collection completed."
Write-Host "OSForensicator data collection completed."
Write-Host "Results are available in $FolderCreation and $FolderCreation.zip"
Write-Host "Detailed log can be found in $LogFile"
