param(
    [int]$Days = 14,
    [switch]$Help
)

if ($Help) {
    Write-Output @"
~~ NanoWall ~~

DESCRIPTION:
    NanoWall analyzes Windows Firewall blocked connection events and prints commands
    to create firewall rules for applications that do not already have them.

    1. Gets all enabled outbound firewall rules from Windows Firewall
    2. Retrieves Windows Event ID 5157 (blocked connections) from Security log
    3. Filters events for 'Default Outbound' and 'Query User Default' origins
    4. Excludes events for applications that already have firewall rules
    5. Lists unique applications and provides PowerShell commands to create rules

PARAMETERS:
    -Days <int>     Number of days to search back for events (default: 14)
                    Examples: -Days 7 (last week), -Days 30 (last month)
    
    -Help           Display this help message

USAGE EXAMPLES:
    .\nanowall_windows.ps1
    .\nanowall_windows.ps1 -Days 30
    .\nanowall_windows.ps1 -Help

OUTPUT:
    - List of blocked connection events without existing firewall rules
    - PowerShell commands to create Allow/Block rules for each unique application

REQUIREMENTS:
    - Run as Administrator (required to read Security event log)
    - Windows with Windows Firewall enabled
    - PowerShell execution policy allowing script execution

"@
    exit 0
}

Write-Output "~~ NanoWall ~~"
# Add P/Invoke for QueryDosDeviceW - only if not already loaded
if (-not ([System.Management.Automation.PSTypeName]'DosDeviceApi').Type) {
    Add-Type -TypeDefinition @"
        using System;
        using System.Runtime.InteropServices;
        using System.Text;

        public class DosDeviceApi
        {
            [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
            public static extern uint QueryDosDevice(string lpDeviceName, StringBuilder lpTargetPath, uint ucchMax);
        }
"@
}

# Build volume to drive letter mapping once at startup
Write-Output "Building volume to drive letter mapping..."
$script:volumeToDriverLetter = @{}
$driveLetters = @('a:', 'b:', 'c:', 'd:', 'e:', 'f:', 'g:', 'h:', 'i:', 'j:', 'k:', 'l:', 'm:', 'n:', 'o:', 'p:', 'q:', 'r:', 's:', 't:', 'u:', 'v:', 'w:', 'x:', 'y:', 'z:')

foreach ($drive in $driveLetters) {
    try {
        $buffer = New-Object System.Text.StringBuilder 260
        $result = [DosDeviceApi]::QueryDosDevice($drive, $buffer, 260)
        
        if ($result -gt 0) {
            $devicePath = $buffer.ToString()
            if ($devicePath -match '\\Device\\HarddiskVolume(\d+)') {
                $volumeNumber = $matches[1]
                $script:volumeToDriverLetter[$volumeNumber] = $drive.Substring(0,1).ToUpper()
            }
        }
    }
    catch {
        # Skip this drive if query fails
    }
}

Write-Output "Volume mapping complete. Found $($script:volumeToDriverLetter.Count) volumes."
$script:volumeToDriverLetter.GetEnumerator() | ForEach-Object {
    Write-Output "$($_.Key) : $($_.Value)"
}

# Function to convert NT device paths to standard Windows paths
function Convert-NTPathToWinPath {
    param([string]$NTPath)
    
    if ([string]::IsNullOrEmpty($NTPath)) {
        return $NTPath
    }
    
    # Handle SystemRoot paths
    if ($NTPath.StartsWith('\SystemRoot\', [StringComparison]::OrdinalIgnoreCase)) {
        return $NTPath.Replace('\SystemRoot\', "$env:SystemRoot\")
    }
    
    # Handle Device paths using pre-built mapping
    if ($NTPath -match '\\Device\\HarddiskVolume(\d+)\\(.*)') {
        $volumeNumber = $matches[1]
        $remainingPath = $matches[2]
        
        # Use pre-built mapping for fast lookup
        if ($script:volumeToDriverLetter.ContainsKey($volumeNumber)) {
            $driveLetter = $script:volumeToDriverLetter[$volumeNumber]
            return "${driveLetter}:\$remainingPath"
        }
        
        # Fallback: assume Volume1 = C:, Volume2 = D:, etc.
        $driveIndex = [int]$volumeNumber - 1
        if ($driveIndex -ge 0 -and $driveIndex -lt 26) {
            $driveLetter = [char](65 + $driveIndex) # A=65, B=66, etc.
            return "${driveLetter}:\$remainingPath"
        }
    }
    
    # Return original path if no conversion needed
    return $NTPath
}

Write-Output "Getting outbound firewall rules..."
# Get all enabled outbound firewall rules with their application filters
$outboundRules = Get-NetFirewallRule -Direction Outbound -Enabled True | ForEach-Object {
    $rule = $_
    $appFilter = Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $rule
    [PSCustomObject]@{
        Name = $rule.Name
        ApplicationName = if ($appFilter.Program -and $appFilter.Program -ne "Any") { 
            $appFilter.Program.ToLower() 
        } else { 
            $null 
        }
    }
} | Where-Object { $_.ApplicationName -ne $null }

Write-Output "Getting recent blocked firewall events..."
$startDate = (Get-Date).AddDays(-$Days)
Write-Output "Searching events from $startDate to now ($Days days)..."
$events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5157; StartTime=$startDate} | ForEach-Object {
    $xml = [xml]$_.ToXml()
    $rawAppName = $xml.Event.EventData.Data | Where-Object { $_.Name -eq 'Application' } | Select-Object -ExpandProperty '#text'
    $convertedAppName = Convert-NTPathToWinPath -NTPath $rawAppName
    [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        ApplicationName = $convertedAppName
        FilterOrigin = $xml.Event.EventData.Data | Where-Object { $_.Name -eq 'FilterOrigin' } | Select-Object -ExpandProperty '#text'
    }
}
$eventsCount = $events.Count

Write-Output "Filtering events..."
# Filter for FilterOrigin 'Default Outbound' or 'Query User Default'
$events = $events | Where-Object { $_.FilterOrigin -eq 'Default Outbound' -or $_.FilterOrigin -eq 'Query User Default' }

# Only keep events without an enabled outbound rule for the application
$finalEvents = $events | Where-Object {
    $appName = if ($_.ApplicationName) { $_.ApplicationName.ToLower() } else { $null }
    -not ($outboundRules | Where-Object { $_.ApplicationName -eq $appName })
}
$finalEventsCount = $finalEvents.Count


# Print the results
foreach ($event in $finalEvents) {
    Write-Output "Time: $($event.TimeCreated) | Application: $($event.ApplicationName) | FilterOrigin: $($event.FilterOrigin)"
}

Write-Output ""
Write-Output "Found $eventsCount events."
Write-Output "Found $finalEventsCount events without existing firewall rules."

# Get unique Application Names from the final events
$uniqueApps = $finalEvents | Select-Object -ExpandProperty ApplicationName | Where-Object { $_ -and $_.Trim() -ne "" } | Sort-Object -Unique

Write-Output ""
Write-Output "Commands to block outbound traffic for each unique application:"
Write-Output ""
foreach ($app in $uniqueApps) {
    $binaryName = if ($app) { [System.IO.Path]::GetFileName($app) } else { $null }
    $escapedApp = $app.Replace('`', '``').Replace('"', '`"')
    Write-Output "## $escapedApp"
    Write-Output ""
    Write-Output "$ New-NetFirewallRule -DisplayName '$binaryName' -Direction Outbound -Action Allow -Program '$escapedApp' -Enabled True"
    Write-Output ""
    Write-Output "$ New-NetFirewallRule -DisplayName '$binaryName' -Direction Outbound -Action Block -Program '$escapedApp' -Enabled True"
    Write-Output ""
    Write-Output ""
}
