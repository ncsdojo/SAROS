<#
.SYNOPSIS
    SAROS v2.0 — Secure Autonomous Recovery OS builder.

.DESCRIPTION
    Single-file, cross-platform tool that builds hardened Windows 10/11
    Privileged Access Workstation media.

    No external dependencies — all hardening content and the ISO creation
    engine are embedded in this script.  Completely offline.

    Requires: PowerShell 7+, elevated privileges (Admin / sudo).

    Source folder layout:
      SourcePath/
        ISO/        <- Windows 10/11 ISO from VLSC
        Drivers/    <- (optional) extracted device drivers
        Updates/    <- (optional) .msu cumulative updates
        SSU/        <- (optional) .msu servicing stack updates
        Autopilot/  <- (optional) AutopilotConfigurationFile.json

.PARAMETER Edition
    Pro or Enterprise.
.PARAMETER Language
    Setup locale (e.g. en-US, en-GB, de-DE, es-ES).
.PARAMETER TimeZone
    Windows timezone ID (e.g. "Pacific Standard Time").
.PARAMETER PAWType
    LOCAL (standalone, local accounts) or CLOUD (Autopilot + Entra ID, cloud identity).
.PARAMETER OutputType
    ISO or USB.  Windows only.
.PARAMETER SourcePath
    Folder containing an ISO/ subfolder with a Windows ISO.
.PARAMETER BuildPath
    Output folder (must not already exist).
.PARAMETER Silent
    No prompts.  Requires SourcePath and BuildPath.
.PARAMETER AutoConfirmUSB
    Auto-select first eligible USB disk.  Windows only.
.PARAMETER CreateTestVM
    Create and boot a Hyper-V test VM after ISO build.  Windows only.
.PARAMETER AnswerFileOnly
    Generate just the autounattend.xml.
.PARAMETER ManageVMs
    List and delete SAROS test VMs.  Windows only.

.EXAMPLE
    # Interactive (Windows — full build):
    ./SAROS.ps1

.EXAMPLE
    # Headless ISO build (Windows):
    ./SAROS.ps1 -Edition Enterprise -Language en-US -SourcePath C:\Source `
                -BuildPath D:\Build -OutputType ISO -Silent

.EXAMPLE
    # Answer file only:
    ./SAROS.ps1 -AnswerFileOnly -Edition Pro -Language en-GB -BuildPath ~/Desktop/PAW

.EXAMPLE
    # Manage test VMs (Windows):
    ./SAROS.ps1 -ManageVMs
#>


[CmdletBinding()]
param(
    [ValidateSet('Pro','Enterprise')][string]$Edition,
    [string]$Language,
    [string]$TimeZone,
    [ValidateSet('LOCAL','CLOUD')][string]$PAWType,
    [ValidateSet('ISO','USB')][string]$OutputType,
    [string]$SourcePath,
    [string]$BuildPath,
    [switch]$Silent,
    [switch]$AutoConfirmUSB,
    [switch]$CreateTestVM,
    [switch]$AnswerFileOnly,
    [switch]$ManageVMs
)

#region ── Pre-flight: environment checks ─────────────────────────────────────

# OS detection

# PowerShell version check
if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Host ''
    Write-Host '  ══════════════════════════════════════════════════════════' -ForegroundColor Red
    Write-Host '  SAROS requires PowerShell 7 or later.' -ForegroundColor Red
    Write-Host "  Current version: $($PSVersionTable.PSVersion)" -ForegroundColor Yellow
    Write-Host ''
    Write-Host '  Install PowerShell 7:' -ForegroundColor White
    Write-Host '    winget install Microsoft.PowerShell' -ForegroundColor Gray
    Write-Host '    https://aka.ms/powershell-release?tag=stable' -ForegroundColor Gray
    Write-Host ''
    Write-Host '  Then re-run with: pwsh ./SAROS.ps1' -ForegroundColor White
    Write-Host '  ══════════════════════════════════════════════════════════' -ForegroundColor Red
    Write-Host ''
    exit 1
}

# Administrator check
$isElevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isElevated) {
    Write-Host ''
    Write-Host '  ══════════════════════════════════════════════════════════' -ForegroundColor Red
    Write-Host '  SAROS must run as Administrator.' -ForegroundColor Red
    Write-Host ''
    Write-Host '  Right-click PowerShell > "Run as Administrator"' -ForegroundColor White
    Write-Host '  ══════════════════════════════════════════════════════════' -ForegroundColor Red
    Write-Host ''
    exit 1
}

#endregion

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:Ver         = '2.0'
$script:LogFile     = Join-Path $PSScriptRoot "SAROS-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
$script:MountedISO  = $null
$script:WIMMounted  = $false
$script:HivesLoaded = [System.Collections.Generic.List[string]]::new()
$script:OrigDir     = (Get-Location).Path
$script:StartTime   = $null

# Start logging immediately
@"
================================================================================
  SAROS v$($script:Ver) — Secure Autonomous Recovery OS
  Log started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
  Machine:     $env:COMPUTERNAME
  User:        $env:USERNAME
  PowerShell:  $($PSVersionTable.PSVersion)
  Script:      $PSCommandPath
================================================================================
"@ | Set-Content -Path $script:LogFile -Force


#region ── Embedded hardening content ─────────────────────────────────────────

$script:Content = @{

BlackHoleProxy = @'
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\USR\Software\Policies\Microsoft\Internet Explorer\Control Panel]
"Proxy"=dword:00000001

[HKEY_LOCAL_MACHINE\USR\Software\Microsoft\Windows\CurrentVersion\Internet Settings]
"ProxyEnable"=dword:00000001
"ProxyServer"="127.0.0.2:8080"
"ProxyOverride"="account.live.com;*.msft.net;*.msauth.net;*.msauthimages.net;*.msftauthimages.net;*.msftauth.net;*.azure.com;*.azure.net;*.azureedge.net;*.azurewebsites.net;*.microsoft.com;microsoft.com;*.windowsupdate.com;*.microsoftonline.com;*.microsoftonline.cn;*.microsoftonline-p.net;*.microsoftonline-p.com;*.windows.net;*.windows.com;*.windowsazure.com;*.windowsazure.cn;*.azure.cn;*.loganalytics.io;*.applicationinsights.io;*.vsassets.io;*.azure-automation.net;*.azure-api.net;*.azure-devices.net;*.visualstudio.com;portal.office.com;*.aspnetcdn.com;*.sharepointonline.com;*.msecnd.net;*.msocdn.com;*.webtrends.com;*.aka.ms;*.digicert.com;*.w3.org;*.phonefactor.net;*.nuget.org;*.cloudapp.net;*.trafficmanager.net;login.live.com;clientconfig.passport.net;windowsphone.com;*.wns.windows.com;*.s-microsoft.com;www.msftconnecttest.com;graph.windows.net;*.manage.microsoft.com;*.aadcdn.microsoftonline-p.com;*.azureafd.net;*.azuredatalakestore.net;*.windows-int.net;*.msocdn.com;*.msecnd.net;*.onestore.ms;*.aspnetcdn.com;*.office.net;*.officeapps.live.com;aka.ms;*.powershellgallery.com"
'@

FirewallProfiles = @'
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SYS\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile]
"DisableNotifications"=dword:00000000
"EnableFirewall"=dword:00000001
"DoNotAllowExceptions"=dword:00000001
"DisableInboundAction"=dword:00000001

[HKEY_LOCAL_MACHINE\SYS\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile]
"DisableNotifications"=dword:00000000
"EnableFirewall"=dword:00000001
"DoNotAllowExceptions"=dword:00000001
"DisableInboundAction"=dword:00000001

[HKEY_LOCAL_MACHINE\SYS\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile]
"DisableNotifications"=dword:00000000
"EnableFirewall"=dword:00000001
"DisableInboundAction"=dword:00000001
"DoNotAllowExceptions"=dword:00000001
'@

FirewallRulesReg = @'
Windows Registry Editor Version 5.00

[-HKEY_LOCAL_MACHINE\SYS\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules]

[HKEY_LOCAL_MACHINE\SYS\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules]
"CoreNet-DHCP-Out"="v2.30|Action=Allow|Active=TRUE|Dir=Out|Protocol=17|LPort=68|RPort=67|App=%SystemRoot%\\system32\\svchost.exe|Svc=dhcp|Name=@FirewallAPI.dll,-25302|Desc=@FirewallAPI.dll,-25303|EmbedCtxt=@FirewallAPI.dll,-25000|"
"CoreNet-DHCPV6-Out"="v2.30|Action=Allow|Active=TRUE|Dir=Out|Protocol=17|LPort=546|RPort=547|App=%SystemRoot%\\system32\\svchost.exe|Svc=dhcp|Name=@FirewallAPI.dll,-25305|Desc=@FirewallAPI.dll,-25306|EmbedCtxt=@FirewallAPI.dll,-25000|"
"CoreNet-DNS-Out-UDP"="v2.30|Action=Allow|Active=TRUE|Dir=Out|Protocol=17|RPort=53|App=%SystemRoot%\\system32\\svchost.exe|Svc=dnscache|Name=@FirewallAPI.dll,-25405|Desc=@FirewallAPI.dll,-25406|EmbedCtxt=@FirewallAPI.dll,-25000|"
"DeliveryOptimization-UDP-In"="v2.30|Action=Allow|Active=TRUE|Dir=In|Protocol=17|LPort=7680|App=%SystemRoot%\\system32\\svchost.exe|Svc=dosvc|Name=@%systemroot%\\system32\\dosvc.dll,-103|Desc=@%systemroot%\\system32\\dosvc.dll,-104|EmbedCtxt=@%systemroot%\\system32\\dosvc.dll,-100|Edge=TRUE|"
"{DAB4AF9D-1E33-44FB-8702-2AC7A93301AF}"="v2.30|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=7680|App=%SystemRoot%\\system32\\svchost.exe|Svc=dosvc|Name=@%systemroot%\\system32\\dosvc.dll,-102|Desc=@%systemroot%\\system32\\dosvc.dll,-104|EmbedCtxt=@%systemroot%\\system32\\dosvc.dll,-100|Edge=TRUE|"
"{370A9609-C84A-473C-BCC1-54F930FB1D7D}"="v2.30|Action=Allow|Active=TRUE|Dir=Out|Protocol=6|RPort=80|App=%SystemRoot%\\System32\\svchost.exe|Svc=NlaSvc|Name=NSCI Probe - NLA (TCP-Out)|"
"{FF0D101E-A937-4B65-8391-407955F78E45}"="v2.30|Action=Allow|Active=TRUE|Dir=Out|Protocol=17|RPort=123|App=%SystemRoot%\\System32\\svchost.exe|Svc=W32Time|Name=Windows Time (UDP-Out)|"
"{2AB04F4F-2AC9-4EE5-AF9C-803684894F15}"="v2.30|Action=Allow|Active=TRUE|Dir=Out|Protocol=6|RPort=80|Name=World Wide Web Services (HTTP Traffic-out)|"
"{4B8AF305-8BF2-47A6-9A55-08DC1E17BA15}"="v2.30|Action=Allow|Active=TRUE|Dir=Out|Protocol=6|RPort=443|Name=World Wide Web Services (HTTPS Traffic-out)|"
'@

FirewallRulesPS = @'
Remove-NetFirewallRule
New-NetFirewallRule -DisplayName "Windows Time (UDP Out)" -Direction OutBound -Action Allow -Protocol UDP -RemotePort 123 -Program "%SystemRoot%\system32\svchost.exe"
Set-NetFirewallRule -DisplayName "Windows Time (UDP Out)" -Direction OutBound -Action Allow -Protocol TCP -RemotePort 123 -Service W32Time
New-NetFirewallRule -DisplayName "World Wide Web Services (HTTP Traffic-out)" -Direction Outbound -Action Allow -Protocol TCP -RemotePort 80
New-NetFirewallRule -DisplayName "World Wide Web Services (HTTPS Traffic-out)" -Direction Outbound -Action Allow -Protocol TCP -RemotePort 443
New-NetFirewallRule -DisplayName "Dynamic Host Configuration Protocol for IPv6(DHCPV6-Out)" -Direction Outbound -Action Allow -Program "%SystemRoot%\system32\svchost.exe" -Protocol TCP -LocalPort 546 -RemotePort 547
Set-NetFirewallRule -DisplayName "Dynamic Host Configuration Protocol for IPv6(DHCPV6-Out)" -Direction Outbound -Action Allow -Service DHCP -Protocol TCP -LocalPort 546 -RemotePort 547
New-NetFirewallRule -DisplayName "Dynamic Host Configuration Protocol (DHCP-Out)" -Direction Outbound -Action Allow -Program "%SystemRoot%\system32\svchost.exe" -Protocol TCP -LocalPort 68 -RemotePort 67
Set-NetFirewallRule -DisplayName "Dynamic Host Configuration Protocol (DHCP-Out)" -Direction Outbound -Action Allow -Service DHCP -Protocol TCP -LocalPort 68 -RemotePort 67
New-NetFirewallRule -DisplayName "DNS (UDP-Out)" -Direction Outbound -Action Allow -Program "%SystemRoot%\system32\svchost.exe" -Protocol UDP -RemotePort 53
Set-NetFirewallRule -DisplayName "DNS (UDP-Out)" -Direction Outbound -Action Allow -Service DNSCACHE -Protocol UDP -RemotePort 53
New-NetFirewallRule -DisplayName "DNS (TCP-Out)" -Direction Outbound -Action Allow -Program "%SystemRoot%\system32\svchost.exe" -Protocol TCP -RemotePort 53
Set-NetFirewallRule -DisplayName "DNS (TCP-Out)" -Direction Outbound -Action Allow -Service DNSCACHE -Protocol TCP -RemotePort 53
New-NetFirewallRule -DisplayName "NSCI Probe (TCP-Out)" -Direction Outbound -Action Allow -Program "%SystemRoot%\system32\svchost.exe" -Protocol TCP -RemotePort 80
Set-NetFirewallRule -DisplayName "NSCI Probe (TCP-Out)" -Direction Outbound -Action Allow -Service NLASVC -Protocol TCP -RemotePort 80
Get-AppxProvisionedPackage -Online | Where-Object DisplayName -EQ MicrosoftWindows.Client.Webexperience | Remove-AppxProvisionedPackage -Allusers
'@

SetupComplete = @'
@echo off
REM Disable LMHOSTS
powershell.exe -ex bypass -command "$Arguments = @{DNSEnabledForWINSResolution = $false;WINSEnableLMHostsLookup = $false};Invoke-CimMethod -ClassName Win32_NetworkAdapterConfiguration -MethodName EnableWINS -Arguments $Arguments"
REM Disable NETBIOS over TCP/IP
powershell.exe -ex bypass -command "Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\TCPIP* -Name NetBIOSoptions -Value 2"
'@

W10Apps = @'
Microsoft.549981C3F5F10
Microsoft.BingWeather
Microsoft.GetHelp
Microsoft.Getstarted
Microsoft.HEIFImageExtension
Microsoft.Microsoft3DViewer
Microsoft.MicrosoftEdge.Stable
Microsoft.MicrosoftOfficeHub
Microsoft.MicrosoftSolitaireCollection
Microsoft.MicrosoftStickyNotes
Microsoft.MixedReality.Portal
Microsoft.Mspaint
Microsoft.Office.OneNote
Microsoft.People
Microsoft.ScreenSketch
Microsoft.SkypeApp
Microsoft.StorePurchaseApp
Microsoft.VCLibs.140.00
Microsoft.VP9VideoExtensions
Microsoft.Wallet
Microsoft.WebMediaExtensions
Microsoft.WebpImageExtension
Microsoft.Windows.Photos
Microsoft.WindowsAlarms
Microsoft.WindowsCamera
microsoft.windowscommunicationsapps
Microsoft.WindowsFeedbackHub
Microsoft.WindowsMaps
Microsoft.WindowsSoundRecorder
Microsoft.WindowsStore
Microsoft.Xbox.TCUI
Microsoft.XboxApp
Microsoft.XboxGameOverlay
Microsoft.XboxGamingOverlay
Microsoft.XboxIdentityProvider
Microsoft.XboxSpeechToTextOverlay
Microsoft.YourPhone
Microsoft.ZuneMusic
Microsoft.ZuneVideo
'@

W11Apps = @'
Microsoft.BingNews
Microsoft.BingWeather
Microsoft.GamingApp
Microsoft.GetHelp
Microsoft.Getstarted
Microsoft.Messaging
Microsoft.Microsoft3DViewer
Microsoft.MicrosoftEdge.Stable
Microsoft.MicrosoftOfficeHub
Microsoft.MicrosoftSolitaireCollection
Microsoft.MicrosoftStickyNotes
Microsoft.MixedReality.Portal
Microsoft.MPEG2VideoExtension
Microsoft.MSpaint
MicrosoftTeams
Microsoft.Office.OneNote
Microsoft.OneConnect
Microsoft.OutlookDesktopIntegrationServices
Microsoft.People
Microsoft.PowerAutomateDesktop
Microsoft.Print3D
Microsoft.ScreenSketch
Microsoft.SecHealthUI
Microsoft.SkypeApp
Microsoft.StorePurchaseApp
Microsoft.SurfaceDiagnostics
Microsoft.SurfaceHub
Microsoft.Todos
Microsoft.Wallet
Microsoft.WebMediaExtensions
Microsoft.WebpImageExtension
Microsoft.Whiteboard
Microsoft.Windows.Photos
Microsoft.WindowsAlarms
Microsoft.WindowsCamera
Microsoft.windowscommunicationsapps
Microsoft.WindowsFeedbackHub
Microsoft.WindowsMaps
Microsoft.WindowsNotepad
Microsoft.WindowsSoundRecorder
Microsoft.WindowsStore
Microsoft.WindowsTerminal
Microsoft.Xbox.TCUI
Microsoft.XboxApp
Microsoft.XboxGameOverlay
Microsoft.XboxGamingOverlay
Microsoft.XboxIdentityProvider
Microsoft.XboxSpeechToTextOverlay
Microsoft.YourPhone
Microsoft.ZuneMusic
Microsoft.ZuneVideo
MicrosoftWindows.Client.WebExperience
'@

W11AppRemovalScript = @'
if ((Test-Path -LiteralPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced") -ne $true) {
    New-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Force -ErrorAction Stop
}
New-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'TaskbarMn' -Value 0 -PropertyType DWord -Force -ErrorAction Stop
$Apps = Get-Content C:\SAROS\W11Apps.txt
foreach ($app in $Apps) {
    Get-AppxPackage -AllUsers | Where-Object Name -EQ $app | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
}
'@

AdvancedHardening = @'
Windows Registry Editor Version 5.00

; Credential Guard (VBS + Secure Launch)
[HKEY_LOCAL_MACHINE\SOFT\Policies\Microsoft\Windows\DeviceGuard]
"EnableVirtualizationBasedSecurity"=dword:00000001
"RequirePlatformSecurityFeatures"=dword:00000003
"LsaCfgFlags"=dword:00000001

; NTLM restriction — NTLMv2 only, refuse LM and NTLMv1
[HKEY_LOCAL_MACHINE\SYS\ControlSet001\Control\Lsa]
"LmCompatibilityLevel"=dword:00000005
"NoLMHash"=dword:00000001

; SMB signing — require on both client and server
[HKEY_LOCAL_MACHINE\SYS\ControlSet001\Services\LanmanServer\Parameters]
"RequireSecuritySignature"=dword:00000001
"EnableSecuritySignature"=dword:00000001

[HKEY_LOCAL_MACHINE\SYS\ControlSet001\Services\LanmanWorkstation\Parameters]
"RequireSecuritySignature"=dword:00000001
"EnableSecuritySignature"=dword:00000001
'@

}

#endregion ────────────────────────────────────────────────────────

$script:Locales = @(
    @{L='ar-SA';N='Arabic (Saudi Arabia)';K='0401:00000401'}
    @{L='bg-BG';N='Bulgarian (Bulgaria)';K='0402:00030402'}
    @{L='zh-cn';N='Chinese (PRC)';K='0804:{81D4E9C9-1D3B-41BC-9E6C-4B40BF79E35E}{FA550B04-5AD7-411f-A5AC-CA038EC515D7}'}
    @{L='zh-tw';N='Chinese (Taiwan)';K='0404:{531FDEBF-9B4C-4A43-A2AA-960E8FCDC732}{B2F9C502-1742-11D4-9790-0080C882687E}'}
    @{L='hr-HR';N='Croatian (Croatia)';K='041a:0000041a'}
    @{L='cs-CZ';N='Czech (Czech Republic)';K='0405:00000405'}
    @{L='da-DK';N='Danish (Denmark)';K='0406:00000406'}
    @{L='nl-NL';N='Dutch (Netherlands)';K='0413:00020409'}
    @{L='en-GB';N='English (United Kingdom)';K='0809:00000809'}
    @{L='en-US';N='English (United States)';K='0409:00000409'}
    @{L='et-EE';N='Estonian (Estonia)';K='0425:00000425'}
    @{L='fi-FI';N='Finnish (Finland)';K='040b:0000040b'}
    @{L='fr-FR';N='French (France)';K='040c:0000040c'}
    @{L='fr-CA';N='French (Canada)';K='0c0c:00011009'}
    @{L='de-DE';N='German (Germany)';K='0407:00000407'}
    @{L='gr-GR';N='Greek (Greece)';K='0408:00000408'}
    @{L='he-IL';N='Hebrew (Israel)';K='040d:0002040d'}
    @{L='hu-HU';N='Hungarian (Hungary)';K='040e:0000040e'}
    @{L='it-IT';N='Italian (Italy)';K='0410:00000410'}
    @{L='ja-JP';N='Japanese (Japan)';K='0411:{03B5835F-F03C-411B-9CE2-AA23E1171E36}{A76C93D9-5523-4E90-AAFA-4DB112F9AC76}'}
    @{L='ko-kr';N='Korean (Korea)';K='0412:{A028AE76-01B1-46C2-99C4-ACD9858AE02F}{B5FE1F02-D5F2-4445-9C03-C568F23C99A1}'}
    @{L='lv-LV';N='Latvian (Latvia)';K='0426:00010426'}
    @{L='lt-LT';N='Lithuanian (Lithuania)';K='0427:00010427'}
    @{L='nb-NO';N='Norwegian Bokmal (Norway)';K='0414:00000414'}
    @{L='pl-pl';N='Polish (Poland)';K='0415:00000415'}
    @{L='pt-BR';N='Portuguese (Brazil)';K='0416:00000416'}
    @{L='pt-PT';N='Portuguese (Portugal)';K='0816:00000816'}
    @{L='ro-RO';N='Romanian (Romania)';K='0418:00010418'}
    @{L='ru-RU';N='Russian (Russia)';K='0419:00000419'}
    @{L='sr-Latn-RS';N='Serbian Latin (Serbia)';K='241a:0000081a'}
    @{L='sk-SK';N='Slovak (Slovakia)';K='041b:0000041b'}
    @{L='sl-SI';N='Slovenian (Slovenia)';K='0424:00000424'}
    @{L='es-ES';N='Spanish (Spain)';K='0c0a:0000040a'}
    @{L='es-MX';N='Spanish (Mexico)';K='080a:0000080a'}
    @{L='sv-SE';N='Swedish (Sweden)';K='041d:0000041d'}
)

# ID|Display — every timezone from the original tool
$script:TZList = @(
    'Dateline Standard Time|(UTC-12:00) International Date Line West'
    'UTC-11|(UTC-11:00) Midway Island, Samoa'
    'Hawaiian Standard Time|(UTC-10:00) Hawaii'
    'Alaskan Standard Time|(UTC-09:00) Alaska'
    'Pacific Standard Time|(UTC-08:00) Pacific Time (US & Canada)'
    'Pacific Standard Time (Mexico)|(UTC-08:00) Tijuana - Baja California'
    'US Mountain Standard Time|(UTC-07:00) Arizona'
    'Mountain Standard Time (Mexico)|(UTC-07:00) Chihuahua - La Paz - Mazatlan'
    'Mountain Standard Time|(UTC-07:00) Mountain Time (US & Canada)'
    'Central America Standard Time|(UTC-06:00) Central America'
    'Central Standard Time|(UTC-06:00) Central Time (US & Canada)'
    'Central Standard Time (Mexico)|(UTC-06:00) Guadalajara - Mexico City'
    'Canada Central Standard Time|(UTC-06:00) Saskatchewan'
    'SA Pacific Standard Time|(UTC-05:00) Bogota - Lima - Quito'
    'Eastern Standard Time|(UTC-05:00) Eastern Time (US & Canada)'
    'US Eastern Standard Time|(UTC-05:00) Indiana (East)'
    'Venezuela Standard Time|(UTC-04:30) Caracas'
    'Paraguay Standard Time|(UTC-04:00) Asuncion'
    'Atlantic Standard Time|(UTC-04:00) Atlantic Time (Canada)'
    'SA Western Standard Time|(UTC-04:00) Georgetown - La Paz - San Juan'
    'Pacific SA Standard Time|(UTC-04:00) Santiago'
    'Newfoundland Standard Time|(UTC-03:30) Newfoundland'
    'E. South America Standard Time|(UTC-03:00) Brasilia'
    'Argentina Standard Time|(UTC-03:00) Buenos Aires'
    'SA Eastern Standard Time|(UTC-03:00) Cayenne'
    'Greenland Standard Time|(UTC-03:00) Greenland'
    'Montevideo Standard Time|(UTC-03:00) Montevideo'
    'Mid-Atlantic Standard Time|(UTC-02:00) Mid-Atlantic'
    'Azores Standard Time|(UTC-01:00) Azores'
    'Cape Verde Standard Time|(UTC-01:00) Cape Verde Is.'
    'Morocco Standard Time|(UTC) Casablanca'
    'UTC|(UTC) Coordinated Universal Time'
    'GMT Standard Time|(UTC) Dublin - Edinburgh - Lisbon - London'
    'Greenwich Standard Time|(UTC) Monrovia - Reykjavik'
    'W. Europe Standard Time|(UTC+01:00) Amsterdam - Berlin - Rome - Vienna'
    'Central Europe Standard Time|(UTC+01:00) Belgrade - Budapest - Prague'
    'Romance Standard Time|(UTC+01:00) Brussels - Copenhagen - Madrid - Paris'
    'Central European Standard Time|(UTC+01:00) Sarajevo - Skopje - Warsaw'
    'W. Central Africa Standard Time|(UTC+01:00) West Central Africa'
    'Jordan Standard Time|(UTC+02:00) Amman'
    'GTB Standard Time|(UTC+02:00) Athens - Bucharest - Istanbul'
    'Middle East Standard Time|(UTC+02:00) Beirut'
    'Egypt Standard Time|(UTC+02:00) Cairo'
    'South Africa Standard Time|(UTC+02:00) Harare - Pretoria'
    'FLE Standard Time|(UTC+02:00) Helsinki - Kyiv - Riga - Tallinn'
    'Israel Standard Time|(UTC+02:00) Jerusalem'
    'Kaliningrad Standard Time|(UTC+02:00) Minsk'
    'Namibia Standard Time|(UTC+02:00) Windhoek'
    'Arabic Standard Time|(UTC+03:00) Baghdad'
    'Arab Standard Time|(UTC+03:00) Kuwait - Riyadh'
    'Russian Standard Time|(UTC+03:00) Moscow - St. Petersburg'
    'E. Africa Standard Time|(UTC+03:00) Nairobi'
    'Georgian Standard Time|(UTC+03:00) Tbilisi'
    'Iran Standard Time|(UTC+03:30) Tehran'
    'Arabian Standard Time|(UTC+04:00) Abu Dhabi - Muscat'
    'Azerbaijan Standard Time|(UTC+04:00) Baku'
    'Mauritius Standard Time|(UTC+04:00) Port Louis'
    'Caucasus Standard Time|(UTC+04:00) Yerevan'
    'Afghanistan Standard Time|(UTC+04:30) Kabul'
    'Ekaterinburg Standard Time|(UTC+05:00) Ekaterinburg'
    'Pakistan Standard Time|(UTC+05:00) Islamabad - Karachi'
    'West Asia Standard Time|(UTC+05:00) Tashkent'
    'India Standard Time|(UTC+05:30) Chennai - Kolkata - Mumbai'
    'Nepal Standard Time|(UTC+05:45) Kathmandu'
    'N. Central Asia Standard Time|(UTC+06:00) Almaty - Novosibirsk'
    'Central Asia Standard Time|(UTC+06:00) Astana - Dhaka'
    'Myanmar Standard Time|(UTC+06:30) Yangon (Rangoon)'
    'SE Asia Standard Time|(UTC+07:00) Bangkok - Hanoi - Jakarta'
    'North Asia Standard Time|(UTC+07:00) Krasnoyarsk'
    'China Standard Time|(UTC+08:00) Beijing - Hong Kong - Urumqi'
    'North Asia East Standard Time|(UTC+08:00) Irkutsk - Ulaan Bataar'
    'Singapore Standard Time|(UTC+08:00) Kuala Lumpur - Singapore'
    'W. Australia Standard Time|(UTC+08:00) Perth'
    'Taipei Standard Time|(UTC+08:00) Taipei'
    'Tokyo Standard Time|(UTC+09:00) Osaka - Sapporo - Tokyo'
    'Korea Standard Time|(UTC+09:00) Seoul'
    'Yakutsk Standard Time|(UTC+09:00) Yakutsk'
    'Cen. Australia Standard Time|(UTC+09:30) Adelaide'
    'AUS Central Standard Time|(UTC+09:30) Darwin'
    'E. Australia Standard Time|(UTC+10:00) Brisbane'
    'AUS Eastern Standard Time|(UTC+10:00) Canberra - Melbourne - Sydney'
    'West Pacific Standard Time|(UTC+10:00) Guam - Port Moresby'
    'Tasmania Standard Time|(UTC+10:00) Hobart'
    'Vladivostok Standard Time|(UTC+10:00) Vladivostok'
    'Central Pacific Standard Time|(UTC+11:00) Magadan - Solomon Is.'
    'New Zealand Standard Time|(UTC+12:00) Auckland - Wellington'
    'Fiji Standard Time|(UTC+12:00) Fiji - Marshall Is.'
    'UTC+12|(UTC+12:00) Petropavlovsk-Kamchatsky'
    'Tonga Standard Time|(UTC+13:00) Nuku''alofa'
)

$script:KMSKeys = @{ PRO = 'W269N-WFGWX-YVC9B-4J6C9-T83GX'; ENT = 'NPPR9-FWDCX-D2C8J-H872K-2YT43' }

#endregion

#region ── Helpers ─────────────────────────────────────────────────────────────

function Write-Log ([string]$Msg, [ValidateSet('Info','Warn','Error')][string]$Lvl = 'Info') {
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $tag = @{Info='INFO ';Warn='WARN ';Error='ERROR'}[$Lvl]
    if ($script:LogFile) { Add-Content -Value "$ts  [$tag]  $Msg" -Path $script:LogFile -EA SilentlyContinue }
    Write-Host "$(@{Info='  [+]';Warn='  [!]';Error='  [x]'}[$Lvl]) $Msg" -ForegroundColor @{Info='Cyan';Warn='Yellow';Error='Red'}[$Lvl]
}

function Write-SplashBanner {
    $art = @'

   ____    __    ____   ___   ____
  / ___|  / _\  |  _ \ / _ \ / ___|
  \___ \ /    \ | |_) | | | |\___ \
   ___) /  /\  \|  _ <| |_| | ___) |
  |____/\_/  \_/|_| \_\\___/ |____/

  Secure Autonomous Recovery OS  v{VER}
'@
    $art = $art -replace '\{VER\}', $script:Ver
    Write-Host $art -ForegroundColor Cyan
    Write-Host "  $([string]::new([char]0x2500, 46))" -ForegroundColor DarkCyan
    Write-Host ''
    Write-Log "SAROS v$($script:Ver)"
}

function Write-Banner ([string]$T) {
    $b = [string]::new([char]0x2500, 46)
    Write-Host "`n  $b" -ForegroundColor DarkCyan; Write-Host "  $T" -ForegroundColor White; Write-Host "  $b`n" -ForegroundColor DarkCyan
    Write-Log $T
}

function Write-Step ([int]$N, [int]$Tot, [string]$T) {
    Write-Host "`n  [$N/$Tot] ($([math]::Round($N/$Tot*100))%) $T" -ForegroundColor Green; Write-Log "STEP $N/$Tot - $T"
}

function Select-FromList ([string]$Prompt, [string[]]$Items, [string]$Default, [int]$WindowSize = 12) {
    # Scrolling arrow-key selector with type-ahead
    Write-Host "`n  $Prompt" -ForegroundColor White
    $hint = if ($Items.Count -gt $WindowSize) { '  ↑↓ scroll, type to jump, Enter to confirm' } else { '  ↑↓ or Tab to select, Enter to confirm' }
    Write-Host $hint -ForegroundColor DarkGray
    $sel = 0
    if ($Default) { for ($i=0;$i -lt $Items.Count;$i++) { if ($Items[$i] -eq $Default) { $sel=$i; break } } }
    $vis = [math]::Min($Items.Count, $WindowSize)
    $top = [Console]::CursorTop
    $draw = {
        [Console]::SetCursorPosition(0, $top)
        # Calculate visible window
        $start = [math]::Max(0, $sel - [math]::Floor($vis / 2))
        $start = [math]::Min($start, [math]::Max(0, $Items.Count - $vis))
        $end   = [math]::Min($start + $vis, $Items.Count)
        if ($start -gt 0) { Write-Host '    ...' -ForegroundColor DarkGray } else { Write-Host '       ' }
        for ($i = $start; $i -lt $end; $i++) {
            $pad = $Items[$i].PadRight(60)
            if ($i -eq $sel) { Write-Host "  > $pad" -ForegroundColor Green }
            else             { Write-Host "    $pad" -ForegroundColor Gray }
        }
        if ($end -lt $Items.Count) { Write-Host '    ...' -ForegroundColor DarkGray } else { Write-Host '       ' }
    }
    & $draw
    while ($true) {
        $k = [Console]::ReadKey($true)
        switch ($k.Key) {
            'UpArrow'   { $sel = ($sel -le 0) ? ($Items.Count-1) : ($sel-1) }
            'DownArrow' { $sel = ($sel -ge $Items.Count-1) ? 0 : ($sel+1) }
            'Tab'       { $sel = ($sel -ge $Items.Count-1) ? 0 : ($sel+1) }
            'Home'      { $sel = 0 }
            'End'       { $sel = $Items.Count - 1 }
            'Enter'     { Write-Host ''; return $Items[$sel] }
            default {
                # Type-ahead: jump to first item containing the typed character
                $ch = $k.KeyChar
                if ($ch -and [char]::IsLetterOrDigit($ch)) {
                    $found = $false
                    for ($i = $sel + 1; $i -lt $Items.Count; $i++) {
                        if ($Items[$i] -match "(?i)$([regex]::Escape("$ch"))") { $sel = $i; $found = $true; break }
                    }
                    if (-not $found) {
                        for ($i = 0; $i -lt $sel; $i++) {
                            if ($Items[$i] -match "(?i)$([regex]::Escape("$ch"))") { $sel = $i; break }
                        }
                    }
                }
            }
        }
        & $draw
    }
}

function Read-Choice ([string]$P, [string[]]$O, [string]$D) {
    return Select-FromList $P $O $D
}

function Read-Searchable ([string]$P, [string[]]$O, [string]$D) {
    return Select-FromList $P $O $D
}

function Read-FolderPath ([string]$P, [switch]$MustExist) {
    Write-Host "`n  $P" -ForegroundColor White
    do { $v = Read-Host '  Path'
        if ([string]::IsNullOrWhiteSpace($v)) { Write-Host '    Required.' -ForegroundColor Red; continue }
        if ($MustExist -and -not (Test-Path $v)) { Write-Host "    Not found: $v" -ForegroundColor Red; continue }
        if (-not $MustExist -and -not [IO.Path]::IsPathRooted($v)) { Write-Host '    Full absolute path required.' -ForegroundColor Red; continue }
        return $v
    } while ($true)
}

function Write-RegFile ([string]$Path, [string]$Content) {
    [IO.File]::WriteAllText($Path, $Content, [Text.Encoding]::Unicode)
}

function Invoke-Cleanup {
    foreach ($h in [string[]]$script:HivesLoaded) { try { & reg.exe UNLOAD $h 2>$null } catch {} }
    $script:HivesLoaded.Clear()
    if ($script:WIMMounted) { try { Dismount-WindowsImage -Path '.\DISM-Offline' -Discard -EA SilentlyContinue } catch {}; $script:WIMMounted = $false }
    if ($script:MountedISO) { try { $i = Get-DiskImage $script:MountedISO -EA SilentlyContinue; if ($i.Attached) { Dismount-DiskImage $script:MountedISO -EA SilentlyContinue | Out-Null } } catch {}; $script:MountedISO = $null }
    Set-Location $script:OrigDir -EA SilentlyContinue
}

function Invoke-VMManager {
    Write-Banner 'SAROS VM Manager'
    $vms = Get-VM | Where-Object Name -Like 'SAROS-*' | Select-Object Name, State, @{N='Created';E={$_.CreationTime}}
    if (-not $vms) { Write-Host '  No SAROS VMs found.' -ForegroundColor Yellow; return }
    for ($i=0;$i -lt $vms.Count;$i++) { Write-Host "    $($i+1). $($vms[$i].Name)  [$($vms[$i].State)]  $($vms[$i].Created)" -ForegroundColor Gray }
    $r = Read-Host '  Number to delete (Enter to cancel)'
    if ($r -match '^\d+$' -and [int]$r -ge 1 -and [int]$r -le $vms.Count) {
        $vm=$vms[[int]$r-1]; Write-Host "  Removing $($vm.Name)..." -ForegroundColor Yellow
        Stop-VM $vm.Name -Force -TurnOff -Confirm:$false -EA SilentlyContinue; Start-Sleep 3
        $loc=(Get-VM $vm.Name|Get-VMHardDiskDrive).Path|Split-Path; Remove-VM $vm.Name -Force -EA SilentlyContinue
        if ($loc -and (Test-Path $loc)) { Remove-Item $loc -Recurse -Force -EA SilentlyContinue }
        Write-Host "  Deleted." -ForegroundColor Green
    }
}

#region ── Platform abstraction layer ─────────────────────────────────────────

# ISO mounting
function Mount-SourceISO ([string]$Path) {
    $script:MountedISO = $Path
    $drv = Mount-DiskImage -ImagePath $Path -PassThru
    return ($drv | Get-Volume).DriveLetter + ":\"
}

function Dismount-SourceISO {
    if (-not $script:MountedISO) { return }
    try { if ((Get-DiskImage $script:MountedISO -EA SilentlyContinue).Attached) { Dismount-DiskImage $script:MountedISO -EA SilentlyContinue | Out-Null } } catch {}
    $script:MountedISO = $null
}

# WIM operations
function Get-WimEditions ([string]$WimPath) {
    return Get-WindowsImage -ImagePath $WimPath | Select-Object ImageIndex, ImageName
}

function Export-WimEdition ([string]$Src, [int]$Index, [string]$Dest, [string]$Name) {
    Export-WindowsImage -SourceImagePath $Src -SourceIndex $Index -DestinationImagePath $Dest -DestinationName $Name -CompressionType Max | Out-Null
}

function Mount-WimImage ([string]$WimPath, [string]$MountDir) {
    $script:WIMMounted = $true
    Mount-WindowsImage -ImagePath $WimPath -Index 1 -Path $MountDir | Out-Null
}

function Save-WimImage ([string]$MountDir, [string]$WimPath) {
    $script:WIMMounted = $false
    & dism.exe /Image:$MountDir /Cleanup-Image /StartComponentCleanup /ResetBase 2>&1 | Where-Object { $_ -match '\S' } | ForEach-Object { Write-Log $_ }
    Dismount-WindowsImage -Path $MountDir -Save | Out-Null
}

function Discard-WimImage ([string]$MountDir) {
    $script:WIMMounted = $false
    try { Dismount-WindowsImage -Path $MountDir -Discard -EA SilentlyContinue } catch {}
}

# Offline content injection
function Add-OfflineDrivers ([string]$MountDir, [string]$DriverPath) {
    Add-WindowsDriver -Path $MountDir -Driver $DriverPath -Recurse | Out-Null
}

function Add-OfflinePackage ([string]$MountDir, [string]$PkgPath, [string]$Label) {
    Add-WindowsPackage -PackagePath $PkgPath -Path $MountDir | Out-Null
}

function Remove-OfflineApps ([string]$MountDir, [string]$AppListFile) {
    $removed = 0; $skipped = 0
    foreach ($app in (Get-Content $AppListFile)) {
        try {
            $pkg = Get-AppxProvisionedPackage -Path $MountDir | Where-Object DisplayName -EQ $app
            if ($pkg) { $pkg | Remove-AppxProvisionedPackage | Out-Null; $removed++ }
        } catch { $skipped++; Write-Log "Skipped $app (protected or not present)" -Lvl Warn }
    }
    Write-Log "Apps removed: $removed, skipped: $skipped"
}

# Registry hive editing
function Mount-Hive ([string]$Name, [string]$File) {
    & reg.exe load "HKLM\$Name" $File 2>$null | Out-Null
    $script:HivesLoaded.Add("HKLM\$Name")
}

function Dismount-Hive ([string]$Name) {
    [gc]::Collect(); Start-Sleep -Milliseconds 200
    & reg.exe UNLOAD "HKLM\$Name" 2>$null | Out-Null
    $script:HivesLoaded.Remove("HKLM\$Name") | Out-Null
}

function Import-RegToHive ([string]$HiveFile, [string]$Prefix, [string]$RegFile) {
    & reg.exe import $RegFile 2>$null | Out-Null
}

function Set-HiveValue ([string]$HiveFile, [string]$Prefix, [string]$KeyPath, [string]$ValueName, $Value, [string]$Type = 'REG_DWORD') {
    $fullPath = "HKLM:\$Prefix\$KeyPath" -replace '\\\\', '\'
    $psType = @{ REG_DWORD = 'DWord'; REG_SZ = 'String'; REG_EXPAND_SZ = 'ExpandString' }[$Type]
    New-ItemProperty -LiteralPath $fullPath -Name $ValueName -Value $Value -PropertyType $psType -Force -EA SilentlyContinue | Out-Null
}


# ISO creation
function New-BootableISO ([string]$SourceDir, [string]$OutputISO) {
    $efi = Join-Path $SourceDir 'efi' 'microsoft' 'boot' 'efisys.bin'
    if (-not (Test-Path $efi)) { throw 'efisys.bin not found — is this a valid UEFI Windows ISO?' }
    $adkPaths = @(
        "${env:ProgramFiles(x86)}\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\amd64\Oscdimg\oscdimg.exe"
        "$env:ProgramFiles\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\amd64\Oscdimg\oscdimg.exe"
    )
    $osc = $adkPaths | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $osc) { $osc = (Get-Command oscdimg.exe -EA SilentlyContinue).Source }
    if (-not $osc) { throw "oscdimg.exe not found. Install Windows ADK: https://go.microsoft.com/fwlink/?linkid=2243390" }
    Write-Log "Using ADK oscdimg: $osc"
    & $osc -b"$((Resolve-Path $efi).Path)" -pEF -u1 -udfver102 "$((Resolve-Path $SourceDir).Path)" "$OutputISO" 2>&1 |
        Where-Object { $_ -match '\S' } | ForEach-Object { Write-Log $_ }
    Get-FileHash $OutputISO | Out-File (Join-Path (Split-Path $OutputISO) 'HASHES.txt') -Force
}

# USB formatting
function Write-ToUSB ([string]$SourceDir, [switch]$Auto, [switch]$Quiet) {
    do {
        $usbAll = Get-Disk | Where-Object { $_.BusType -eq 'USB' -and $_.Size -gt 7GB -and $_.Size -lt 32GB }
        if (-not $usbAll) { throw 'No USB drives found (8-32 GB).' }
        $usbDisk = if (($usbAll | Measure-Object).Count -gt 1 -and -not $Auto) {
            $usbAll | ForEach-Object { Write-Host "    Disk $($_.Number): $($_.FriendlyName) - $([math]::Round($_.Size/1GB,1)) GB" -ForegroundColor Gray }
            $usbAll | Where-Object Number -EQ (Read-Host '  Disk number')
        } else { $usbAll | Select-Object -First 1 }
        if (-not $usbDisk) { throw 'No USB disk selected.' }
        if (-not $Auto) { Write-Host "  ALL DATA on Disk $($usbDisk.Number) ($($usbDisk.FriendlyName)) will be ERASED." -ForegroundColor Red; if ((Read-Host '  Type YES') -ne 'YES') { throw 'Cancelled.' } }
        $usbDisk | Clear-Disk -RemoveData -Confirm:$false
        if ($usbDisk.PartitionStyle -eq 'RAW') { $usbDisk | Initialize-Disk -PartitionStyle GPT } else { $usbDisk | Set-Disk -PartitionStyle GPT }
        $part = $usbDisk | New-Partition -UseMaximumSize -AssignDriveLetter
        Format-Volume -Partition $part -FileSystem FAT32 -NewFileSystemLabel 'SAROS' -Confirm:$false | Out-Null
        Copy-Item "$SourceDir/*" "$($part.DriveLetter):\" -Recurse -Force
        Write-Log "USB $($part.DriveLetter): complete"
        if ($Quiet) { break }
        $again = Read-Host '  Write another USB? (y/N)'
    } while ($again -in 'y','Y','yes')
}

#endregion

#region ── Fetch: catalog scraping and patch download ─────────────────────────

function Search-UpdateCatalog ([string]$Query, [int]$Max = 10) {
    $url = "https://www.catalog.update.microsoft.com/Search.aspx?q=$([uri]::EscapeDataString($Query))"
    Write-Log "Catalog query: $Query"
    $response = Invoke-WebRequest -Uri $url -UseBasicParsing -ErrorAction Stop
    $html = $response.Content
    $results = @()

    # The catalog HTML: <a ... onclick="goToDetails('ID');" ...>TITLE</a>
    # Note the semicolon after goToDetails() — must allow for it
    $pattern = "goToDetails\(['""]([a-f0-9\-]+)['""]\)[^>]*>\s*([^<]+?)\s*</a>"
    $ms = [regex]::Matches($html, $pattern, [Text.RegularExpressions.RegexOptions]'IgnoreCase,Singleline')

    Write-Log "Catalog returned: $($ms.Count) results"

    for ($i = 0; $i -lt [math]::Min($ms.Count, $Max); $i++) {
        $results += [PSCustomObject]@{
            UpdateID = $ms[$i].Groups[1].Value
            Title    = $ms[$i].Groups[2].Value.Trim()
        }
    }
    if ($results.Count -gt 0) { Write-Log "Top result: $($results[0].Title)" }
    return $results
}

function Get-UpdateDownloadURL ([string]$UpdateID) {
    $body = @{ updateIDs = "[{`"uidInfo`":`"$UpdateID`",`"updateID`":`"$UpdateID`"}]" }
    $resp = Invoke-WebRequest -Uri 'https://www.catalog.update.microsoft.com/DownloadDialog.aspx' -Method Post -Body $body -UseBasicParsing -ErrorAction Stop
    $m = [regex]::Match($resp.Content, "https?://[^'`"]+\.(?:msu|cab)")
    if ($m.Success) { return $m.Value }
    $m = [regex]::Match($resp.Content, "url\s*=\s*'([^']+)'")
    if ($m.Success) { return $m.Groups[1].Value }
    return $null
}

function Invoke-AutoFetch ([string]$SrcPath, [string]$WinVer, [int]$BuildNum) {
    # Map build to version label
    $verLabel = switch ($BuildNum) {
        { $_ -ge 26100 } { '24H2'; break }
        { $_ -ge 22631 } { '23H2'; break }
        { $_ -ge 22621 } { '22H2'; break }
        { $_ -ge 22000 } { '21H2'; break }
        { $_ -ge 19045 } { '22H2'; break }
        { $_ -ge 19044 } { '21H2'; break }
        default { $null }
    }
    if (-not $verLabel) { Write-Log "Unknown build $BuildNum — skipping patch download" -Lvl Warn; return }

    # Connectivity check — quick probe, don't hang
    try {
        $null = Invoke-WebRequest -Uri 'https://www.catalog.update.microsoft.com' -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
    } catch {
        Write-Log 'No internet — skipping patch download (offline build)' -Lvl Warn
        return
    }

    Write-Log "Online — checking for patches (Windows $WinVer $verLabel x64)"

    $updDir = Join-Path $SrcPath 'Updates'; New-Item $updDir -ItemType Directory -Force -EA SilentlyContinue | Out-Null
    $ssuDir = Join-Path $SrcPath 'SSU';     New-Item $ssuDir -ItemType Directory -Force -EA SilentlyContinue | Out-Null
    $count = 0

    # Helper: search, filter, download
    $doFetch = {
        param([string]$BaseQuery, [string]$Dest, [string]$Label, [string]$Exclude)
        try {
            # Search without date first (broader, more reliable)
            $results = Search-UpdateCatalog $BaseQuery
            $filtered = @($results | Where-Object {
                $_.Title -match 'x64' -and
                $_.Title -notmatch "Dynamic|Preview|ARM64|Delta$(if($Exclude){"|$Exclude"})"
            })

            if ($filtered.Count -eq 0) {
                Write-Log "No $Label found matching filter" -Lvl Warn
                return 0
            }

            # Pick newest: sort by YYYY-MM in title descending
            $best = $filtered | Sort-Object {
                if ($_.Title -match '(\d{4}-\d{2})') { $Matches[1] } else { '0000-00' }
            } -Descending | Select-Object -First 1

            Write-Log "Selected: $($best.Title)"
            $url = Get-UpdateDownloadURL $best.UpdateID
            if (-not $url) { Write-Log "Could not resolve download for $Label" -Lvl Warn; return 0 }
            $fn = [IO.Path]::GetFileName(([uri]$url).LocalPath)
            $destFile = Join-Path $Dest $fn
            if (Test-Path $destFile) { Write-Log "$fn already present — skipping"; return 0 }
            Write-Host "  [>] Downloading: $fn" -ForegroundColor White
            $ProgressPreference = 'SilentlyContinue'
            Invoke-WebRequest -Uri $url -OutFile $destFile -UseBasicParsing
            Write-Log "Saved $Label ($([math]::Round((Get-Item $destFile).Length/1MB))MB)"
            return 1
        } catch { Write-Log "Catalog search failed for ${Label}: $_" -Lvl Warn; return 0 }
    }

    # LCU — latest cumulative update
    $lcuBase = "Cumulative Update for Windows $WinVer Version $verLabel for x64"
    $count += (& $doFetch $lcuBase $updDir 'LCU' '')
    # SSU — servicing stack (usually bundled with LCU on modern Windows)
    $ssuBase = "Servicing Stack Update for Windows $WinVer Version $verLabel for x64"
    $count += (& $doFetch $ssuBase $ssuDir 'SSU' 'Cumulative')
    # .NET Framework
    $dnBase = "Cumulative Update for .NET Framework for Windows $WinVer Version $verLabel for x64"
    $count += (& $doFetch $dnBase $updDir '.NET' '')

    if ($count -gt 0) { Write-Log "Downloaded $count patch(es)" }
    else { Write-Log 'No new patches to download' }
}

#endregion

#region ── Answer file ────────────────────────────────────────────────────────

function New-AnswerFile ([string]$Lang, [string]$KB, [string]$TZ, [string]$Key, [string]$Ed, [string]$Type, [string]$Dir) {
    $c='processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS"'
    $n='xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"'
    $ppc = ($Type -eq 'CLOUD') ? '1' : '3'
    $accts = if ($Type -eq 'LOCAL') { @"

    <UserAccounts><LocalAccounts>
      <LocalAccount wcm:action="add"><DisplayName>PAWUSER</DisplayName><Group>Users</Group><Name>PAWUSER</Name></LocalAccount>
      <LocalAccount wcm:action="add"><DisplayName>PAWADMIN</DisplayName><Group>Administrators</Group><Name>PAWADMIN</Name></LocalAccount>
    </LocalAccounts></UserAccounts><RegisteredOwner>PAWUSER</RegisteredOwner>
"@ } else { '' }
    @"
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
  <settings pass="windowsPE">
    <component name="Microsoft-Windows-International-Core-WinPE" $c $n>
      <SetupUILanguage><UILanguage>$Lang</UILanguage></SetupUILanguage>
      <InputLocale>$KB</InputLocale><SystemLocale>$Lang</SystemLocale><UILanguage>$Lang</UILanguage><UILanguageFallback>$Lang</UILanguageFallback><UserLocale>$Lang</UserLocale>
    </component>
    <component name="Microsoft-Windows-Setup" $c $n>
      <DiskConfiguration><Disk wcm:action="add"><DiskID>0</DiskID><WillWipeDisk>true</WillWipeDisk>
        <CreatePartitions>
          <CreatePartition wcm:action="add"><Order>1</Order><Type>Primary</Type><Size>300</Size></CreatePartition>
          <CreatePartition wcm:action="add"><Order>2</Order><Type>EFI</Type><Size>100</Size></CreatePartition>
          <CreatePartition wcm:action="add"><Order>3</Order><Type>MSR</Type><Size>128</Size></CreatePartition>
          <CreatePartition wcm:action="add"><Order>4</Order><Type>Primary</Type><Extend>true</Extend></CreatePartition>
        </CreatePartitions>
        <ModifyPartitions>
          <ModifyPartition wcm:action="add"><Order>1</Order><PartitionID>1</PartitionID><Label>WINRE</Label><Format>NTFS</Format><TypeID>DE94BBA4-06D1-4D40-A16A-BFD50179D6AC</TypeID></ModifyPartition>
          <ModifyPartition wcm:action="add"><Order>2</Order><PartitionID>2</PartitionID><Label>System</Label><Format>FAT32</Format></ModifyPartition>
          <ModifyPartition wcm:action="add"><Order>3</Order><PartitionID>3</PartitionID></ModifyPartition>
          <ModifyPartition wcm:action="add"><Order>4</Order><PartitionID>4</PartitionID><Label>OS</Label><Letter>C</Letter><Format>NTFS</Format></ModifyPartition>
        </ModifyPartitions>
      </Disk></DiskConfiguration>
      <ImageInstall><OSImage><InstallTo><DiskID>0</DiskID><PartitionID>4</PartitionID></InstallTo></OSImage></ImageInstall>
      <RunSynchronous><RunSynchronousCommand><Order>1</Order><Path>cmd /c PowerCfg.exe /s 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c</Path></RunSynchronousCommand></RunSynchronous>
      <UserData><ProductKey><Key>$Key</Key><WillShowUI>Never</WillShowUI></ProductKey><AcceptEula>true</AcceptEula></UserData>
    </component>
  </settings>
  <settings pass="offlineServicing"><component name="Microsoft-Windows-PnpCustomizationsNonWinPE" $c $n>
    <DriverPaths>
      <PathAndCredentials wcm:action="add" wcm:keyValue="1"><Path>C:\Drivers</Path></PathAndCredentials>
      <PathAndCredentials wcm:action="add" wcm:keyValue="2"><Path>D:\Drivers</Path></PathAndCredentials>
      <PathAndCredentials wcm:action="add" wcm:keyValue="3"><Path>E:\Drivers</Path></PathAndCredentials>
      <PathAndCredentials wcm:action="add" wcm:keyValue="4"><Path>F:\Drivers</Path></PathAndCredentials>
    </DriverPaths>
  </component></settings>
  <settings pass="specialize">
    <component name="Microsoft-Windows-Deployment" $c $n>
      <RunSynchronous><RunSynchronousCommand wcm:action="add"><Order>1</Order><Path>cmd /c powercfg.exe /overlaysetactive overlay_scheme_max</Path></RunSynchronousCommand></RunSynchronous>
    </component>
    <component name="Microsoft-Windows-Shell-Setup" $c $n><TimeZone>$TZ</TimeZone><ComputerName></ComputerName><ProductKey>$Key</ProductKey></component>
  </settings>
  <settings pass="oobeSystem">
    <component name="Microsoft-Windows-Shell-Setup" $c $n>
      <OOBE><HideEULAPage>true</HideEULAPage><HideOEMRegistrationScreen>true</HideOEMRegistrationScreen><HideOnlineAccountScreens>true</HideOnlineAccountScreens><HideWirelessSetupInOOBE>false</HideWirelessSetupInOOBE><ProtectYourPC>$ppc</ProtectYourPC></OOBE>$accts
    </component>
    <component name="Microsoft-Windows-International-Core" $c $n><InputLocale>$KB</InputLocale><SystemLocale>$Lang</SystemLocale><UILanguage>$Lang</UILanguage><UserLocale>$Lang</UserLocale></component>
  </settings>
</unattend>
<!-- SAROS $Type | $Ed | $Lang | $(Get-Date -f 'yyyy-MM-dd HH:mm') -->
"@ | Set-Content (Join-Path $Dir 'autounattend.xml') -Encoding UTF8 -Force
    Write-Log "Answer file generated ($Type)"
}

#endregion

#region ── Build pipeline ─────────────────────────────────────────────────────

function Start-SAROSBuild {
    $script:StartTime = Get-Date
    $tot = 12
    Write-SplashBanner

    $interactive = -not $Silent

    # ── Source path ────────────────────────────────────────────────
    $sp = $SourcePath
    if (-not $sp -and $interactive) { $sp = Read-FolderPath 'Source folder (contains the Windows ISO)' -MustExist }
    if (-not $sp -or -not (Test-Path $sp)) { throw "Source path required and must exist: $sp" }

    # ── Read ISO to discover available editions ──────────────────────
    $isoFile = $null
    foreach ($candidate in @((Join-Path $sp '*.iso'), (Join-Path $sp 'ISO' '*.iso'), (Join-Path $sp 'iso' '*.iso'))) {
        if (Test-Path $candidate) { $isoFile = (Get-ChildItem $candidate | Select-Object -First 1).FullName; break }
    }
    if (-not $isoFile) { throw "No .iso found in $sp (or $sp/ISO/)" }
    Write-Log "ISO: $(Split-Path $isoFile -Leaf)"

    $isoRoot = Mount-SourceISO $isoFile
    $wimSrc = Join-Path $isoRoot 'sources' 'install.wim'
    if (-not (Test-Path $wimSrc)) { Dismount-SourceISO; throw 'No install.wim in ISO.' }
    $allEditions = Get-WimEditions $wimSrc
    Dismount-SourceISO

    $available = @($allEditions | Where-Object { $_.ImageName -notmatch ' N$| N ' -and $_.ImageName -notmatch 'Single Language' })
    if ($available.Count -eq 0) { $available = @($allEditions) }

    # ── Edition: from ISO ────────────────────────────────────────────
    $match = $null
    if ($Edition) {
        $match = $available | Where-Object { $_.ImageName -match $Edition } | Select-Object -First 1
    }
    if (-not $match -and $interactive) {
        $names = $available | ForEach-Object { $_.ImageName }
        $picked = Select-FromList 'Select edition' $names $null
        $match = $available | Where-Object { $_.ImageName -eq $picked } | Select-Object -First 1
    }
    if (-not $match) { throw "Edition not found in ISO. Available: $(($allEditions.ImageName) -join ', ')" }

    $wv = ($match.ImageName -match '11') ? '11' : '10'
    $kmsMap = @{
        'Enterprise'       = 'NPPR9-FWDCX-D2C8J-H872K-2YT43'
        'Education'        = 'NW6C2-QMPVW-D7KKK-3GKT6-VCFB2'
        'Pro for Workst'   = 'NRG8B-VKK3Q-CXVCJ-9G2XF-6Q84J'
        'Pro Education'    = '6TP4R-GNPTD-KYYHQ-7B7DP-J447Y'
        'Pro'              = 'W269N-WFGWX-YVC9B-4J6C9-T83GX'
        'Home'             = 'TX9XD-98N7V-6WMQ6-BX7FG-H8Q99'
    }
    $keyMatch = $kmsMap.GetEnumerator() | Where-Object { $match.ImageName -match $_.Key } | Select-Object -First 1
    $key = if ($keyMatch) { $keyMatch.Value } else { 'W269N-WFGWX-YVC9B-4J6C9-T83GX' }

    # Edition short name for folder and ISO naming
    $edShort = ($match.ImageName -replace 'Windows\s+\d+\s+', '').Trim() -replace '\s+', ''
    Write-Log "Matched: $($match.ImageName) (index $($match.ImageIndex), Win $wv)"

    # ── Language, timezone, PAW type, output ─────────────────────────
    $lang = $Language
    if (-not $lang -and $interactive) {
        $picked = Read-Searchable 'Setup language' (($script:Locales | Sort-Object N).N) 'English (United Kingdom)'
        $lang = ($script:Locales | Where-Object N -EQ $picked).L
    }
    $lr = $script:Locales | Where-Object L -EQ $lang
    if (-not $lr) { throw "Unknown locale: $lang" }

    $tz = $TimeZone
    if (-not $tz -and $interactive) {
        $tzD = $script:TZList | ForEach-Object { ($_ -split '\|')[1] }
        $picked = Read-Searchable 'Time zone' $tzD '(UTC) Dublin - Edinburgh - Lisbon - London'
        $tz = ($script:TZList | Where-Object { ($_ -split '\|')[1] -eq $picked } | ForEach-Object { ($_ -split '\|')[0] })
    }
    if (-not ($script:TZList | Where-Object { ($_ -split '\|')[0] -eq $tz })) { throw "Unknown timezone: $tz" }

    $pt = $PAWType
    if (-not $pt -and $interactive) { $pt = Read-Choice 'PAW type' @('LOCAL','CLOUD') 'LOCAL' }
    if (-not $pt) { $pt = 'LOCAL' }

    $ot = $OutputType
    if (-not $ot -and $interactive) { $ot = Read-Choice 'Output type' @('ISO','USB') 'ISO' }
    if (-not $ot) { $ot = 'ISO' }



    # ── Build workspace + auto-generated output folder ─────────────
    $workspace = $BuildPath
    if (-not $workspace -and $interactive) {
        Write-Host "`n  Build workspace (builds are created inside this folder)" -ForegroundColor White
        Write-Host "    Default: current directory" -ForegroundColor DarkGray
        $raw = Read-Host '  Path'
        $workspace = if ([string]::IsNullOrWhiteSpace($raw)) { (Get-Location).Path } else { $raw }
    }
    if (-not $workspace) { $workspace = (Get-Location).Path }
    if (-not (Test-Path $workspace)) { New-Item $workspace -ItemType Directory -Force | Out-Null }

    # Auto-generate unique build folder: SAROS_Win11-Pro_20260623_143052
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $buildName = "SAROS_Win${wv}-${edShort}_${stamp}"
    $bp = Join-Path $workspace $buildName

    # ── Config summary ───────────────────────────────────────────────
    Write-Host "`n  SAROS build configuration" -ForegroundColor White
    foreach ($line in @(
        "    Edition  : $($match.ImageName)"
        "    Language : $($lr.L) - $($lr.N)"
        "    TimeZone : $tz"
        "    PAW Type : $pt"
        "    Output   : $ot"
        "    Source   : $sp"
        "    Build    : $bp"
    )) { Write-Host $line -ForegroundColor Gray }
    Write-Host ''
    if ($interactive) { $go = Read-Host '  Proceed? (Y/n)'; if ($go -and $go -notin 'Y','y','yes') { return } }

    # ── 1 — Create folder structure ──────────────────────────────────────
    Write-Step 1 $tot 'Creating build folder structure'
    foreach ($d in 'DISM-Offline','ISO-Files','ISO-Source','ISO-Temp','ISO-Temp\split','SAROS','SAROS\Firewall-Rules','SAROS\W11Apps') {
        New-Item "$bp\$d" -ItemType Directory -Force | Out-Null
    }
    Set-Location $bp

    # ── 2 — Write embedded hardening files to disk ───────────────────────
    Write-Step 2 $tot 'Staging hardening content'
    Write-RegFile "$bp\SAROS\BlackHoleProxy.reg"  $script:Content.BlackHoleProxy
    Write-RegFile "$bp\SAROS\FW.reg"              $script:Content.FirewallProfiles
    Write-RegFile "$bp\SAROS\FWRules.reg"         $script:Content.FirewallRulesReg
    $script:Content.FirewallRulesPS       | Set-Content "$bp\SAROS\Firewall-Rules\FwRules.ps1" -Encoding UTF8
    $script:Content.SetupComplete         | Set-Content "$bp\SAROS\SetupComplete.cmd" -Encoding ASCII
    $script:Content.W10Apps               | Set-Content "$bp\SAROS\W10Apps.txt" -Encoding UTF8
    $script:Content.W11Apps               | Set-Content "$bp\SAROS\W11Apps.txt" -Encoding UTF8
    $script:Content.W11AppRemovalScript   | Set-Content "$bp\SAROS\W11Apps\W11AppRemoval.ps1" -Encoding UTF8
    # Also write the app list for the first-boot script
    $script:Content.W11Apps               | Set-Content "$bp\SAROS\W11Apps\W11Apps.txt" -Encoding UTF8

    # ── 3 — Mount ISO ───────────────────────────────────────────────────
    Write-Step 3 $tot 'Mounting ISO'
    $script:ISOMount = Mount-SourceISO $isoFile
    $wimSrc = Join-Path $script:ISOMount 'sources' 'install.wim'
    Write-Log "Matched: $($match.ImageName) (index $($match.ImageIndex), Win $wv)"

    # ── 3b — Auto-fetch latest patches (silent, best-effort) ─────────
    $buildNum = 0
    try {
        $detail = Get-WindowsImage -ImagePath $wimSrc -Index $match.ImageIndex
        $buildNum = [int]($detail.Version -replace '^[\d]+\.[\d]+\.(\d+).*', '$1')
        Write-Log "Build: $buildNum"
        Invoke-AutoFetch $sp $wv $buildNum
    } catch { Write-Log "Auto-fetch skipped: $_" -Lvl Warn }

    # ── 4 — Copy ISO contents, export edition ────────────────────────────
    Write-Step 4 $tot 'Copying ISO contents and exporting edition'
    $isoFilesDir = Join-Path $bp 'ISO-Files'
    Copy-Item (Join-Path $script:ISOMount '*') $isoFilesDir -Recurse -Force
    # ISO contents inherit read-only — clear it so WIM operations can modify files
    Get-ChildItem $isoFilesDir -Recurse -File | ForEach-Object { $_.IsReadOnly = $false }
    $wimInFiles = Join-Path $isoFilesDir 'sources' 'install.wim'
    $wimExport = Join-Path $bp 'ISO-Temp' 'export.wim'
    Export-WimEdition $wimInFiles $match.ImageIndex $wimExport $match.ImageName
    Move-Item $wimInFiles (Join-Path $bp 'ISO-Temp' 'install-multi.wim')
    Move-Item $wimExport $wimInFiles -Force

    # ── 4b — Patch boot.wim for Win11 24H2 (force legacy Setup) ──────────
    if ($wv -eq '11') {
        Write-Log 'Patching boot.wim for 24H2 compatibility (legacy Setup CmdLine)'
        $bootWim = Join-Path $isoFilesDir 'sources' 'boot.wim'
        if (Test-Path $bootWim) {
            $bootPatch = Join-Path $bp 'ISO-Temp' 'bootpatch'
            New-Item $bootPatch -ItemType Directory -Force | Out-Null
            $bIdx = 1
            Mount-WindowsImage -ImagePath $bootWim -Index $bIdx -Path $bootPatch | Out-Null
            $bootSysHive = Join-Path $bootPatch 'Windows' 'System32' 'config' 'SYSTEM'
            & reg.exe load 'HKLM\BOOT_SYS' $bootSysHive 2>$null | Out-Null
            & reg.exe add 'HKLM\BOOT_SYS\Setup' /v CmdLine /t REG_SZ /d 'X:\sources\setup.exe' /f 2>$null | Out-Null
            [gc]::Collect(); Start-Sleep -Milliseconds 200
            & reg.exe UNLOAD 'HKLM\BOOT_SYS' 2>$null | Out-Null
            Dismount-WindowsImage -Path $bootPatch -Save | Out-Null
            Remove-Item $bootPatch -Recurse -Force -EA SilentlyContinue
            Write-Log 'boot.wim patched'
        }
    }

    # ── 5 — Mount WIM ────────────────────────────────────────────────────
    Write-Step 5 $tot 'Mounting WIM image'
    $dismOffline = Join-Path $bp 'DISM-Offline'
    Mount-WimImage $wimInFiles $dismOffline
    foreach ($d in 'SAROS/Firewall-Rules','SAROS/W11Apps','Windows/Setup/Scripts') {
        New-Item (Join-Path $dismOffline $d) -ItemType Directory -Force -EA SilentlyContinue | Out-Null
    }

    # ── 6 — Inject content ───────────────────────────────────────────────
    Write-Step 6 $tot 'Injecting drivers, updates, and Autopilot config'
    $drvPath = Join-Path $sp 'Drivers'
    $ssuPath = Join-Path $sp 'ssu'
    $updPath = Join-Path $sp 'Updates'
    $apPath  = Join-Path $sp 'Autopilot'
    if (Test-Path "$drvPath/*") { Write-Log 'Drivers';  Add-OfflineDrivers $dismOffline $drvPath }
    if (Test-Path "$ssuPath/*") { Write-Log 'SSU';      Add-OfflinePackage $dismOffline $ssuPath 'SSU' }
    if (Test-Path "$updPath/*") { Write-Log 'Updates';  Add-OfflinePackage $dismOffline $updPath 'Updates' }
    if ((Test-Path "$apPath/*.json") -and $pt -eq 'CLOUD') {
        Write-Log 'Autopilot config'
        $apDest = Join-Path $dismOffline 'Windows' 'Provisioning' 'Autopilot'
        New-Item $apDest -ItemType Directory -Force -EA SilentlyContinue | Out-Null
        Copy-Item "$apPath/*.json" $apDest -Force
    }

    # ── 7 — Registry hardening ───────────────────────────────────────────
    Write-Step 7 $tot 'Applying registry hardening and firewall policy'
    $usrHive  = Join-Path $dismOffline 'Users' 'Default' 'NTUSER.DAT'
    $sysHive  = Join-Path $dismOffline 'Windows' 'System32' 'config' 'SYSTEM'
    $softHive = Join-Path $dismOffline 'Windows' 'System32' 'config' 'SOFTWARE'

    Mount-Hive 'USR' $usrHive
    Import-RegToHive $usrHive 'HKEY_LOCAL_MACHINE\USR' (Join-Path $bp 'SAROS' 'BlackHoleProxy.reg')
    if ($wv -eq '11') { Set-HiveValue $usrHive 'USR' 'Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' 'TaskbarDa' 0 }
    Dismount-Hive 'USR'

    Mount-Hive 'SYS' $sysHive
    Import-RegToHive $sysHive 'HKEY_LOCAL_MACHINE\SYS' (Join-Path $bp 'SAROS' 'FW.reg')
    Import-RegToHive $sysHive 'HKEY_LOCAL_MACHINE\SYS' (Join-Path $bp 'SAROS' 'FWRules.reg')
    Copy-Item (Join-Path $bp 'SAROS' 'Firewall-Rules' 'FwRules.ps1') (Join-Path $dismOffline 'SAROS' 'Firewall-Rules' 'FwRules.ps1') -Force
    # Advanced hardening: NTLM restriction + SMB signing
    Set-HiveValue $sysHive 'SYS' 'ControlSet001\Control\Lsa' 'LmCompatibilityLevel' 5
    Set-HiveValue $sysHive 'SYS' 'ControlSet001\Control\Lsa' 'NoLMHash' 1
    Set-HiveValue $sysHive 'SYS' 'ControlSet001\Services\LanmanServer\Parameters' 'RequireSecuritySignature' 1
    Set-HiveValue $sysHive 'SYS' 'ControlSet001\Services\LanmanServer\Parameters' 'EnableSecuritySignature' 1
    Set-HiveValue $sysHive 'SYS' 'ControlSet001\Services\LanmanWorkstation\Parameters' 'RequireSecuritySignature' 1
    Set-HiveValue $sysHive 'SYS' 'ControlSet001\Services\LanmanWorkstation\Parameters' 'EnableSecuritySignature' 1
    Write-Log 'Applied: NTLM v2 only + SMB signing enforced'
    Dismount-Hive 'SYS'

    Mount-Hive 'SOFT' $softHive
    # Credential Guard (VBS)
    Set-HiveValue $softHive 'SOFT' 'Policies\Microsoft\Windows\DeviceGuard' 'EnableVirtualizationBasedSecurity' 1
    Set-HiveValue $softHive 'SOFT' 'Policies\Microsoft\Windows\DeviceGuard' 'RequirePlatformSecurityFeatures' 3
    Set-HiveValue $softHive 'SOFT' 'Policies\Microsoft\Windows\DeviceGuard' 'LsaCfgFlags' 1
    Write-Log 'Applied: Credential Guard enabled'
    Set-HiveValue $softHive 'SOFT' 'Microsoft\Windows\CurrentVersion\RunOnce' 'SAROS-FW' 'powershell.exe -ExecutionPolicy Bypass -File C:\SAROS\Firewall-Rules\FWrules.ps1' 'REG_SZ'
    if ($wv -eq '11') {
        Copy-Item (Join-Path $bp 'SAROS' 'W11Apps' '*') (Join-Path $dismOffline 'SAROS' 'W11Apps') -Force
        Set-HiveValue $softHive 'SOFT' 'Microsoft\Windows\CurrentVersion\RunOnce' 'SAROS-W11' 'powershell.exe -ExecutionPolicy Bypass -File C:\SAROS\W11Apps\W11AppRemoval.ps1' 'REG_SZ'
    }
    Dismount-Hive 'SOFT'

    Copy-Item (Join-Path $bp 'SAROS' 'SetupComplete.cmd') (Join-Path $dismOffline 'Windows' 'Setup' 'Scripts' 'SetupComplete.cmd') -Force

    # ── 8 — Remove bloatware ─────────────────────────────────────────────
    Write-Step 8 $tot 'Removing provisioned bloatware'
    $appFile = ($wv -eq '10') ? (Join-Path $bp 'SAROS' 'W10Apps.txt') : (Join-Path $bp 'SAROS' 'W11Apps.txt')
    Remove-OfflineApps $dismOffline $appFile

    # WinRE resize
    $wre = Join-Path $dismOffline 'Windows' 'System32' 'Recovery' 'winre.wim'
    if ((Test-Path $wre) -and (Get-Item $wre).Length -gt 400MB) {
        Write-Log 'Shrinking WinRE'
        Export-WindowsImage -SourceImagePath $wre -SourceIndex 1 -DestinationImagePath "${wre}.new" | Out-Null
        Remove-Item $wre; Rename-Item "${wre}.new" 'winre.wim'
    }

    # ── 9 — Answer file ──────────────────────────────────────────────────
    Write-Step 9 $tot "Generating $pt answer file"
    New-AnswerFile -Lang $lr.L -KB $lr.K -TZ $tz -Key $key -Ed $edShort -Type $pt -Dir $isoFilesDir

    # ── 10 — Dismount and recompress ─────────────────────────────────────
    Write-Step 10 $tot 'Saving and recompressing WIM'
    $wimTemp = Join-Path $bp 'ISO-Temp' 'recomp.wim'
    Save-WimImage $dismOffline $wimInFiles

    $destName = $match.ImageName
    Export-WimEdition $wimInFiles 1 $wimTemp $destName
    if ((Get-Item $wimTemp).Length -lt (Get-Item $wimInFiles).Length) {
        Move-Item $wimInFiles (Join-Path $bp 'ISO-Temp' 'install-pre.wim'); Move-Item $wimTemp $wimInFiles -Force
    } else { Remove-Item $wimTemp }

    Dismount-SourceISO

    # Split if > 4 GB (FAT32 limit)
    if ((Get-Item $wimInFiles).Length -gt 4GB) {
        Write-Log 'Splitting WIM for FAT32'
        $splitDir = Join-Path $bp 'ISO-Temp' 'split'
        Move-Item $wimInFiles $splitDir
        Split-WindowsImage -ImagePath (Join-Path $splitDir 'install.wim') -SplitImagePath (Join-Path $splitDir 'install.swm') -FileSize 4096 | Out-Null
        Copy-Item (Join-Path $splitDir '*.swm') (Join-Path $isoFilesDir 'sources')
    }

    # ── 11 — Create output ───────────────────────────────────────────────
    $pfx = ($pt -eq 'CLOUD') ? 'C' : 'L'
    $outISO = "SAROS-${pfx}${edK}${wv}-$($lr.L)-$(Get-Date -f MMyyyy).iso"

    if ($ot -eq 'USB') {
        Write-Step 11 $tot 'Writing to USB drive'
        Write-ToUSB $isoFilesDir -Auto:($AutoConfirmUSB -or $Silent) -Quiet:$Silent
    } else {
        Write-Step 11 $tot 'Creating bootable ISO'
        $outPath = Join-Path $bp $outISO
        New-BootableISO $isoFilesDir $outPath
        Write-Log "ISO: $outPath"
        # Optional test VM (Windows only)
        if ($CreateTestVM) {
            Write-Log 'Creating Hyper-V test VM'
            $vm = "SAROS-$(Get-Date -Format 'yyyyMMdd-HHmm')"; $vd = Join-Path $bp 'VM'
            New-VM -Name $vm -NewVHDPath (Join-Path $vd "$vm.vhdx") -NewVHDSizeBytes 64GB -MemoryStartupBytes 4GB -Path (Join-Path $vd 'VMs' $vm) -Generation 2
            Set-VMMemory $vm -DynamicMemoryEnabled $false; Set-VMProcessor $vm -Count 2 -Confirm:$false
            Set-VMKeyProtector $vm -NewLocalKeyProtector; Enable-VMTPM $vm -Confirm:$false
            Add-VMDvdDrive $vm -Path $outPath; Set-VMFirmware $vm -FirstBootDevice (Get-VMDvdDrive $vm)
            Set-VMHost -EnableEnhancedSessionMode $false; vmconnect $env:COMPUTERNAME $vm; Start-VM $vm
            Start-Sleep 5; Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.SendKeys]::SendWait('{ENTER}')
        }
    }

    # ── 12 — Done ────────────────────────────────────────────────────────
    Write-Step 12 $tot 'Complete'
    Write-Banner 'SAROS BUILD FINISHED'
    if ($ot -eq 'USB') { Write-Host '  USB ready. Boot target device (F12).' -ForegroundColor Green }
    else { Write-Host "  ISO: $outPath" -ForegroundColor Green }
    Write-Host "  Log: $($script:LogFile)" -ForegroundColor DarkGray
    Write-Host "  Elapsed: $((Get-Date).Subtract($script:StartTime).ToString('hh\:mm\:ss'))" -ForegroundColor DarkGray
    Write-Host ''
}

#endregion

try {
    if ($ManageVMs) {
        Invoke-VMManager; return
    }
    if ($AnswerFileOnly) {
        Write-SplashBanner
        $int = -not $Silent
        $ed = $Edition; if (-not $ed -and $int) { $ed = Read-Choice 'Edition' @('Pro','Enterprise') 'Pro' }
        if (-not $ed) { throw 'Edition required.' }
        $edK = ($ed -in 'Enterprise','ENT') ? 'ENT' : 'PRO'
        $lang = $Language; if (-not $lang -and $int) { $lang = ($script:Locales | Where-Object N -EQ (Read-Searchable 'Language' (($script:Locales|Sort-Object N).N) 'English (United Kingdom)')).L }
        $lr = $script:Locales | Where-Object L -EQ $lang; if (-not $lr) { throw "Unknown locale: $lang" }
        $tz = $TimeZone; if (-not $tz -and $int) { $tzD=$script:TZList|ForEach-Object{($_ -split '\|')[1]}; $tz=($script:TZList|Where-Object{($_ -split '\|')[1] -eq (Read-Searchable 'Timezone' $tzD '(UTC) Dublin - Edinburgh - Lisbon - London')}|ForEach-Object{($_ -split '\|')[0]}) }
        $pt = $PAWType; if (-not $pt -and $int) { $pt = Read-Choice 'PAW type' @('LOCAL','CLOUD') 'LOCAL' }; if (-not $pt) { $pt = 'LOCAL' }
        $d = $BuildPath; if (-not $d -and $int) { $d = Read-FolderPath 'Output folder' }; if (-not $d) { throw 'BuildPath required.' }
        New-Item $d -ItemType Directory -Force -EA SilentlyContinue | Out-Null
        New-AnswerFile -Lang $lr.L -KB $lr.K -TZ $tz -Key $script:KMSKeys[$edK] -Ed $edK -Type $pt -Dir $d
        Write-Host "  Created: $(Join-Path $d 'autounattend.xml')" -ForegroundColor Green; return
    }
    Start-SAROSBuild
}
catch {
    Write-Log "FATAL: $_" -Lvl Error
    Write-Log $_.ScriptStackTrace -Lvl Error
    Write-Host "`n  FATAL: $_" -ForegroundColor Red
    Write-Host "  $($_.ScriptStackTrace)" -ForegroundColor DarkRed
    Write-Host "  Log: $($script:LogFile)" -ForegroundColor DarkGray
    exit 1
}
finally { Invoke-Cleanup }
