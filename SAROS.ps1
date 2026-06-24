<#
.SYNOPSIS
    SAROS v3.0 — Secure Autonomous Recovery OS.

.DESCRIPTION
    Builds hardened Windows 10/11 Privileged Access Workstation media from a
    single, self-contained PowerShell script.

    Features:
      - Reads available editions directly from the ISO
      - Auto-fetches latest cumulative updates from Microsoft Update Catalog
      - Offline registry hardening (Credential Guard, NTLM, SMB signing)
      - Firewall lockdown (deny-all inbound, explicit outbound whitelist)
      - Black hole proxy with Microsoft/Azure bypass list
      - Bloatware removal (resilient to protected packages)
      - 24H2 boot.wim compatibility patch
      - Unattended answer file generation (LOCAL or CLOUD PAW types)
      - Bootable ISO output via Windows ADK oscdimg
      - Bootable USB output with FAT32/GPT and WIM splitting
      - Interactive arrow-key selection UI
      - Timestamped, idempotent build folders

    Requires: PowerShell 7+, Administrator, Windows ADK (for ISO output).

.PARAMETER SourcePath
    Folder containing a Windows ISO (directly or in an ISO\ subfolder).
    Optional subfolders: Drivers\, Updates\, SSU\, Autopilot\.

.PARAMETER BuildPath
    Workspace folder where timestamped build subfolders are created.
    Defaults to the current directory if not specified.

.PARAMETER Edition
    Windows edition name to match (e.g. 'Pro', 'Enterprise', 'Education').
    If omitted, an interactive selector shows editions found in the ISO.

.PARAMETER Language
    Windows locale code (e.g. en-US, en-GB, de-DE).
    If omitted, an interactive selector is shown.

.PARAMETER TimeZone
    Windows timezone ID (e.g. 'Pacific Standard Time').
    If omitted, an interactive selector is shown.

.PARAMETER PAWType
    LOCAL  — Standalone hardened OS with local PAWUSER + PAWADMIN accounts.
    CLOUD  — Same hardening plus Autopilot JSON injection for Entra ID join.

.PARAMETER OutputType
    ISO — Bootable ISO file (requires Windows ADK oscdimg.exe).
    USB — Direct write to FAT32/GPT USB drive with optional repeat.

.PARAMETER Silent
    Suppress all interactive prompts.  All parameters become mandatory.

.PARAMETER AutoConfirmUSB
    Skip USB disk confirmation prompt.

.PARAMETER CreateTestVM
    Create and boot a Generation 2 Hyper-V test VM after ISO build.

.PARAMETER AnswerFileOnly
    Generate only the autounattend.xml without building media.

.PARAMETER ManageVMs
    List and delete SAROS test VMs, then exit.

.EXAMPLE
    .\SAROS.ps1
    Interactive mode — walks through every setting with arrow-key selectors.

.EXAMPLE
    .\SAROS.ps1 -SourcePath D:\Source -BuildPath D:\Builds -Edition Pro `
                -Language en-US -TimeZone 'Eastern Standard Time' `
                -PAWType LOCAL -OutputType ISO -Silent

.EXAMPLE
    .\SAROS.ps1 -AnswerFileOnly -Edition Pro -Language en-GB -BuildPath D:\Out

.EXAMPLE
    .\SAROS.ps1 -ManageVMs
#>

[CmdletBinding()]
param(
    [string]$SourcePath,
    [string]$BuildPath,
    [string]$Edition,
    [string]$Language,
    [string]$TimeZone,
    [ValidateSet('LOCAL','CLOUD')][string]$PAWType,
    [ValidateSet('ISO','USB')][string]$OutputType,
    [switch]$Silent,
    [switch]$AutoConfirmUSB,
    [switch]$CreateTestVM,
    [switch]$AnswerFileOnly,
    [switch]$ManageVMs
)


if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Host "`n  SAROS requires PowerShell 7+.  Current: $($PSVersionTable.PSVersion)" -ForegroundColor Red
    Write-Host '  Install: winget install Microsoft.PowerShell' -ForegroundColor Yellow
    Write-Host "  Run:     pwsh .\SAROS.ps1`n" -ForegroundColor Yellow
    exit 1
}

$_principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $_principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "`n  SAROS requires Administrator privileges." -ForegroundColor Red
    Write-Host "  Right-click PowerShell > Run as Administrator`n" -ForegroundColor Yellow
    exit 1
}

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'


$Script:VERSION = '3.0'

$Script:KMS_KEYS = @{
    'Enterprise'       = 'NPPR9-FWDCX-D2C8J-H872K-2YT43'
    'Education'        = 'NW6C2-QMPVW-D7KKK-3GKT6-VCFB2'
    'Pro for Workst'   = 'NRG8B-VKK3Q-CXVCJ-9G2XF-6Q84J'
    'Pro Education'    = '6TP4R-GNPTD-KYYHQ-7B7DP-J447Y'
    'Pro'              = 'W269N-WFGWX-YVC9B-4J6C9-T83GX'
    'Home'             = 'TX9XD-98N7V-6WMQ6-BX7FG-H8Q99'
}

$Script:LOCALES = @(
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

$Script:TIMEZONES = @(
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


$Script:HARDEN = @{

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

FirewallRules = @'
Windows Registry Editor Version 5.00

[-HKEY_LOCAL_MACHINE\SYS\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules]

[HKEY_LOCAL_MACHINE\SYS\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules]
"CoreNet-DHCP-Out"="v2.30|Action=Allow|Active=TRUE|Dir=Out|Protocol=17|LPort=68|RPort=67|App=%SystemRoot%\\system32\\svchost.exe|Svc=dhcp|Name=@FirewallAPI.dll,-25302|EmbedCtxt=@FirewallAPI.dll,-25000|"
"CoreNet-DHCPV6-Out"="v2.30|Action=Allow|Active=TRUE|Dir=Out|Protocol=17|LPort=546|RPort=547|App=%SystemRoot%\\system32\\svchost.exe|Svc=dhcp|Name=@FirewallAPI.dll,-25305|EmbedCtxt=@FirewallAPI.dll,-25000|"
"CoreNet-DNS-Out-UDP"="v2.30|Action=Allow|Active=TRUE|Dir=Out|Protocol=17|RPort=53|App=%SystemRoot%\\system32\\svchost.exe|Svc=dnscache|Name=@FirewallAPI.dll,-25405|EmbedCtxt=@FirewallAPI.dll,-25000|"
"{370A9609}"="v2.30|Action=Allow|Active=TRUE|Dir=Out|Protocol=6|RPort=80|App=%SystemRoot%\\System32\\svchost.exe|Svc=NlaSvc|Name=NSCI Probe - NLA (TCP-Out)|"
"{FF0D101E}"="v2.30|Action=Allow|Active=TRUE|Dir=Out|Protocol=17|RPort=123|App=%SystemRoot%\\System32\\svchost.exe|Svc=W32Time|Name=Windows Time (UDP-Out)|"
"{2AB04F4F}"="v2.30|Action=Allow|Active=TRUE|Dir=Out|Protocol=6|RPort=80|Name=World Wide Web Services (HTTP Traffic-out)|"
"{4B8AF305}"="v2.30|Action=Allow|Active=TRUE|Dir=Out|Protocol=6|RPort=443|Name=World Wide Web Services (HTTPS Traffic-out)|"
'@

FirstBootFirewall = @'
Remove-NetFirewallRule
New-NetFirewallRule -DisplayName "Windows Time (UDP Out)" -Direction OutBound -Action Allow -Protocol UDP -RemotePort 123 -Program "%SystemRoot%\system32\svchost.exe"
Set-NetFirewallRule -DisplayName "Windows Time (UDP Out)" -Direction OutBound -Action Allow -Protocol TCP -RemotePort 123 -Service W32Time
New-NetFirewallRule -DisplayName "World Wide Web Services (HTTP Traffic-out)" -Direction Outbound -Action Allow -Protocol TCP -RemotePort 80
New-NetFirewallRule -DisplayName "World Wide Web Services (HTTPS Traffic-out)" -Direction Outbound -Action Allow -Protocol TCP -RemotePort 443
New-NetFirewallRule -DisplayName "DHCPV6-Out" -Direction Outbound -Action Allow -Program "%SystemRoot%\system32\svchost.exe" -Protocol TCP -LocalPort 546 -RemotePort 547
Set-NetFirewallRule -DisplayName "DHCPV6-Out" -Direction Outbound -Action Allow -Service DHCP -Protocol TCP -LocalPort 546 -RemotePort 547
New-NetFirewallRule -DisplayName "DHCP-Out" -Direction Outbound -Action Allow -Program "%SystemRoot%\system32\svchost.exe" -Protocol TCP -LocalPort 68 -RemotePort 67
Set-NetFirewallRule -DisplayName "DHCP-Out" -Direction Outbound -Action Allow -Service DHCP -Protocol TCP -LocalPort 68 -RemotePort 67
New-NetFirewallRule -DisplayName "DNS (UDP-Out)" -Direction Outbound -Action Allow -Program "%SystemRoot%\system32\svchost.exe" -Protocol UDP -RemotePort 53
Set-NetFirewallRule -DisplayName "DNS (UDP-Out)" -Direction Outbound -Action Allow -Service DNSCACHE -Protocol UDP -RemotePort 53
New-NetFirewallRule -DisplayName "DNS (TCP-Out)" -Direction Outbound -Action Allow -Program "%SystemRoot%\system32\svchost.exe" -Protocol TCP -RemotePort 53
Set-NetFirewallRule -DisplayName "DNS (TCP-Out)" -Direction Outbound -Action Allow -Service DNSCACHE -Protocol TCP -RemotePort 53
New-NetFirewallRule -DisplayName "NSCI Probe (TCP-Out)" -Direction Outbound -Action Allow -Program "%SystemRoot%\system32\svchost.exe" -Protocol TCP -RemotePort 80
Set-NetFirewallRule -DisplayName "NSCI Probe (TCP-Out)" -Direction Outbound -Action Allow -Service NLASVC -Protocol TCP -RemotePort 80
'@

SetupComplete = @'
@echo off
powershell.exe -ex bypass -command "$a=@{DNSEnabledForWINSResolution=$false;WINSEnableLMHostsLookup=$false};Invoke-CimMethod -ClassName Win32_NetworkAdapterConfiguration -MethodName EnableWINS -Arguments $a"
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

W11FirstBoot = @'
if (-not (Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")) {
    New-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Force | Out-Null
}
New-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'TaskbarMn' -Value 0 -PropertyType DWord -Force | Out-Null
$Apps = Get-Content C:\SAROS\W11Apps.txt
foreach ($app in $Apps) { Get-AppxPackage -AllUsers | Where-Object Name -EQ $app | Remove-AppxPackage -AllUsers -EA SilentlyContinue | Out-Null }
'@

}


$Script:LogFile     = Join-Path $PSScriptRoot "SAROS-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
$Script:MountedISO  = $null
$Script:WIMMounted  = $false
$Script:HivesLoaded = [System.Collections.Generic.List[string]]::new()
$Script:OrigDir     = (Get-Location).Path
$Script:StartTime   = $null

# Initialise log
@"
================================================================================
  SAROS v$Script:VERSION
  Log started : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
  Machine     : $env:COMPUTERNAME
  User        : $env:USERNAME
  PowerShell  : $($PSVersionTable.PSVersion)
  Script      : $PSCommandPath
================================================================================
"@ | Set-Content -Path $Script:LogFile -Force


function Write-Log {
    param([string]$Message, [ValidateSet('Info','Warn','Error')][string]$Level = 'Info')
    $stamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $tag   = @{ Info = 'INFO '; Warn = 'WARN '; Error = 'ERROR' }[$Level]
    $color = @{ Info = 'Cyan';  Warn = 'Yellow'; Error = 'Red' }[$Level]
    $icon  = @{ Info = '  [+]'; Warn = '  [!]'; Error = '  [x]' }[$Level]
    Add-Content -Value "$stamp  [$tag]  $Message" -Path $Script:LogFile -EA SilentlyContinue
    Write-Host "$icon $Message" -ForegroundColor $color
}

function Write-SplashBanner {
    Write-Host @'

   ____    __    ____   ___   ____
  / ___|  / _\  |  _ \ / _ \ / ___|
  \___ \ /    \ | |_) | | | |\___ \
   ___) /  /\  \|  _ <| |_| | ___) |
  |____/\_/  \_/|_| \_\\___/ |____/

'@ -ForegroundColor Cyan
    Write-Host "  Secure Autonomous Recovery OS  v$Script:VERSION" -ForegroundColor Cyan
    Write-Host "  $([string]::new([char]0x2500, 46))`n" -ForegroundColor DarkCyan
    Write-Log "SAROS v$Script:VERSION"
}

function Write-Banner ([string]$Text) {
    $bar = [string]::new([char]0x2500, 46)
    Write-Host "`n  $bar" -ForegroundColor DarkCyan
    Write-Host "  $Text" -ForegroundColor White
    Write-Host "  $bar`n" -ForegroundColor DarkCyan
    Write-Log $Text
}

function Write-Step ([int]$Current, [int]$Total, [string]$Text) {
    $pct = [math]::Round($Current / $Total * 100)
    Write-Host "`n  [$Current/$Total] ($pct%) $Text" -ForegroundColor Green
    Write-Log "STEP $Current/$Total - $Text"
}


function Select-FromList {
    param(
        [string]$Prompt,
        [string[]]$Items,
        [string]$Default,
        [int]$WindowSize = 12
    )
    Write-Host "`n  $Prompt" -ForegroundColor White
    $hint = if ($Items.Count -gt $WindowSize) { '  Use arrow keys to scroll, type to jump, Enter to confirm' } else { '  Use arrow keys or Tab, Enter to confirm' }
    Write-Host $hint -ForegroundColor DarkGray

    [int]$sel = 0
    if ($Default) {
        for ($i = 0; $i -lt $Items.Count; $i++) {
            if ($Items[$i] -eq $Default) { $sel = $i; break }
        }
    }

    $vis = [math]::Min($Items.Count, $WindowSize)
    $top = [Console]::CursorTop

    $drawList = {
        [Console]::SetCursorPosition(0, $top)
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

    & $drawList
    while ($true) {
        $k = [Console]::ReadKey($true)
        switch ($k.Key) {
            'UpArrow'   { $sel = if ($sel -le 0) { $Items.Count - 1 } else { $sel - 1 } }
            'DownArrow' { $sel = if ($sel -ge ($Items.Count - 1)) { 0 } else { $sel + 1 } }
            'Tab'       { $sel = if ($sel -ge ($Items.Count - 1)) { 0 } else { $sel + 1 } }
            'Home'      { $sel = 0 }
            'End'       { $sel = $Items.Count - 1 }
            'Enter'     { Write-Host ''; return $Items[$sel] }
            default {
                $ch = $k.KeyChar
                if ($ch -and [char]::IsLetterOrDigit($ch)) {
                    for ($i = $sel + 1; $i -lt $Items.Count; $i++) {
                        if ($Items[$i] -match "(?i)$([regex]::Escape([string]$ch))") { $sel = $i; break }
                    }
                }
            }
        }
        & $drawList
    }
}

function Read-FolderPath {
    param([string]$Prompt, [switch]$MustExist)
    Write-Host "`n  $Prompt" -ForegroundColor White
    do {
        $value = Read-Host '  Path'
        if ([string]::IsNullOrWhiteSpace($value)) { Write-Host '    Required.' -ForegroundColor Red; continue }
        if ($MustExist -and -not (Test-Path $value)) { Write-Host '    Not found.' -ForegroundColor Red; continue }
        if (-not $MustExist -and -not [IO.Path]::IsPathRooted($value)) { Write-Host '    Absolute path required.' -ForegroundColor Red; continue }
        return $value
    } while ($true)
}


function Write-RegFile ([string]$Path, [string]$Content) {
    [IO.File]::WriteAllText($Path, $Content, [Text.Encoding]::Unicode)
}

function Invoke-Cleanup {
    foreach ($hive in [string[]]$Script:HivesLoaded) {
        try { & reg.exe UNLOAD $hive 2>$null } catch { }
    }
    $Script:HivesLoaded.Clear()

    if ($Script:WIMMounted) {
        try { Dismount-WindowsImage -Path '.\DISM-Offline' -Discard -EA SilentlyContinue | Out-Null } catch { }
        $Script:WIMMounted = $false
    }

    if ($Script:MountedISO) {
        try {
            $img = Get-DiskImage $Script:MountedISO -EA SilentlyContinue
            if ($img.Attached) { Dismount-DiskImage $Script:MountedISO -EA SilentlyContinue | Out-Null }
        } catch { }
        $Script:MountedISO = $null
    }

    Set-Location $Script:OrigDir -EA SilentlyContinue
}


function Mount-OfflineHive ([string]$Name, [string]$HiveFile) {
    & reg.exe load "HKLM\$Name" $HiveFile 2>$null | Out-Null
    $Script:HivesLoaded.Add("HKLM\$Name")
}

function Dismount-OfflineHive ([string]$Name) {
    [GC]::Collect()
    Start-Sleep -Milliseconds 300
    & reg.exe UNLOAD "HKLM\$Name" 2>$null | Out-Null
    $Script:HivesLoaded.Remove("HKLM\$Name") | Out-Null
}

function Import-OfflineReg ([string]$RegFile) {
    & reg.exe import $RegFile 2>$null | Out-Null
}

function Set-OfflineRegValue {
    param(
        [string]$HiveName,
        [string]$SubKey,
        [string]$ValueName,
        $Value,
        [ValidateSet('DWord','String','ExpandString')][string]$Type = 'DWord'
    )
    $path = "HKLM:\$HiveName\$SubKey"
    New-ItemProperty -LiteralPath $path -Name $ValueName -Value $Value -PropertyType $Type -Force -EA SilentlyContinue | Out-Null
}


function Mount-SourceISO ([string]$ISOPath) {
    $Script:MountedISO = $ISOPath
    # Reuse existing mount if already attached
    $existing = Get-DiskImage -ImagePath $ISOPath -EA SilentlyContinue
    if ($existing -and $existing.Attached) {
        $volume = $existing | Get-Volume
        Write-Log "ISO already mounted at $($volume.DriveLetter):\"
        return "$($volume.DriveLetter):\"
    }
    $volume = Mount-DiskImage -ImagePath $ISOPath -PassThru | Get-Volume
    return "$($volume.DriveLetter):\"
}

function Dismount-SourceISO {
    if (-not $Script:MountedISO) { return }
    try {
        $img = Get-DiskImage $Script:MountedISO -EA SilentlyContinue
        if ($img.Attached) { Dismount-DiskImage $Script:MountedISO | Out-Null }
    } catch { }
    $Script:MountedISO = $null
}

function Find-ISOFile ([string]$SearchPath) {
    foreach ($candidate in @(
        (Join-Path $SearchPath '*.iso'),
        (Join-Path $SearchPath 'ISO' '*.iso'),
        (Join-Path $SearchPath 'iso' '*.iso')
    )) {
        if (Test-Path $candidate) {
            return (Get-ChildItem $candidate | Select-Object -First 1).FullName
        }
    }
    return $null
}

function Get-WimEditions ([string]$WimPath) {
    return Get-WindowsImage -ImagePath $WimPath | Select-Object ImageIndex, ImageName
}

function Resolve-KMSKey ([string]$EditionName) {
    $entry = $Script:KMS_KEYS.GetEnumerator() | Where-Object { $EditionName -match $_.Key } | Select-Object -First 1
    if ($entry) { return $entry.Value }
    return $Script:KMS_KEYS['Pro']
}

function Get-VersionLabel ([string]$WimPath, [int]$ImageIndex) {
    # Read DisplayVersion directly from the WIM's SOFTWARE registry hive
    # This eliminates the need for a hardcoded build-to-version map
    $tempDir = Join-Path ([IO.Path]::GetTempPath()) "saros-verlabel-$PID"
    try {
        New-Item $tempDir -ItemType Directory -Force | Out-Null
        Mount-WindowsImage -ImagePath $WimPath -Index $ImageIndex -Path $tempDir -ReadOnly | Out-Null
        $softHive = Join-Path $tempDir 'Windows' 'System32' 'config' 'SOFTWARE'
        & reg.exe load 'HKLM\SAROS_VER' $softHive 2>$null | Out-Null
        $verInfo = Get-ItemProperty 'HKLM:\SAROS_VER\Microsoft\Windows NT\CurrentVersion' -EA SilentlyContinue
        $displayVersion = $verInfo.DisplayVersion   # e.g. "24H2", "23H2"
        [GC]::Collect(); Start-Sleep -Milliseconds 200
        & reg.exe UNLOAD 'HKLM\SAROS_VER' 2>$null | Out-Null
        Dismount-WindowsImage -Path $tempDir -Discard | Out-Null
        return $displayVersion
    }
    catch {
        Write-Log "Could not read version from WIM: $_" -Level Warn
        try { & reg.exe UNLOAD 'HKLM\SAROS_VER' 2>$null } catch { }
        try { Dismount-WindowsImage -Path $tempDir -Discard -EA SilentlyContinue | Out-Null } catch { }
        return $null
    }
    finally {
        Remove-Item $tempDir -Recurse -Force -EA SilentlyContinue
    }
}


function Search-UpdateCatalog ([string]$Query) {
    $url = "https://www.catalog.update.microsoft.com/Search.aspx?q=$([uri]::EscapeDataString($Query))"
    Write-Log "Catalog: $Query"
    $response = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 30 -EA Stop
    $html     = $response.Content
    $results  = @()

    # Strategy 1: ID + title from <a onclick="goToDetails('ID');">Title</a>
    $rx1 = "goToDetails\([`"']([a-fA-F0-9\-]+)[`"']\)[^>]*>([^<]+)</a>"
    $ms1 = [regex]::Matches($html, $rx1, [Text.RegularExpressions.RegexOptions]::IgnoreCase)
    if ($ms1.Count -gt 0) {
        foreach ($m in $ms1) {
            $results += [PSCustomObject]@{ UpdateID = $m.Groups[1].Value; Title = $m.Groups[2].Value.Trim() }
        }
        Write-Log "Strategy 1: $($results.Count) results"
    }

    # Strategy 2: IDs found separately, find title text forward from each ID position
    if ($results.Count -eq 0) {
        $rxIDs = [regex]::Matches($html, "goToDetails\([`"']([a-fA-F0-9\-]+)[`"']\)", [Text.RegularExpressions.RegexOptions]::IgnoreCase)
        if ($rxIDs.Count -gt 0) {
            Write-Log "Strategy 2: found $($rxIDs.Count) IDs, extracting titles"
            foreach ($idM in $rxIDs) {
                $chunk = $html.Substring($idM.Index, [math]::Min(600, $html.Length - $idM.Index))
                $titleM = [regex]::Match($chunk, '>\s*(\d{4}-\d{2}\s[^<]{10,}?)\s*</')
                if ($titleM.Success) {
                    $results += [PSCustomObject]@{ UpdateID = $idM.Groups[1].Value; Title = $titleM.Groups[1].Value.Trim() }
                }
            }
            Write-Log "Strategy 2: $($results.Count) titles extracted"
        }
    }

    # Strategy 3: scan <tr> rows for update IDs paired with date-prefixed titles
    if ($results.Count -eq 0) {
        $rxRows = [regex]::Matches($html, '<tr[^>]*>(.+?)</tr>', [Text.RegularExpressions.RegexOptions]'IgnoreCase,Singleline')
        if ($rxRows.Count -gt 0) {
            Write-Log "Strategy 3: parsing $($rxRows.Count) table rows"
            foreach ($row in $rxRows) {
                $r = $row.Groups[1].Value
                $idM = [regex]::Match($r, "goToDetails\([`"']([a-fA-F0-9\-]+)[`"']\)")
                $tM  = [regex]::Match($r, '>\s*(\d{4}-\d{2}\s+(?:Cumulative|Servicing|Security)[^<]+?)\s*<', [Text.RegularExpressions.RegexOptions]::IgnoreCase)
                if ($idM.Success -and $tM.Success) {
                    $results += [PSCustomObject]@{ UpdateID = $idM.Groups[1].Value; Title = $tM.Groups[1].Value.Trim() }
                }
            }
            Write-Log "Strategy 3: $($results.Count) results"
        }
    }

    # Diagnostic: dump HTML sample to log if everything failed
    if ($results.Count -eq 0 -and $html.Length -gt 100) {
        $sample = ($html.Substring(0, [math]::Min(2000, $html.Length))) -replace '\s+', ' '
        Write-Log "All strategies failed. HTML sample (check log): $sample" -Level Warn
    }

    # Filter: x64 only, exclude Dynamic/Preview/ARM64/Delta
    $filtered = @($results | Where-Object {
        $_.Title -match 'x64' -and $_.Title -notmatch 'Dynamic|Preview|ARM64|Delta'
    })

    Write-Log "Catalog: $($results.Count) parsed, $($filtered.Count) after x64 filter"
    if ($filtered.Count -gt 0) { Write-Log "Top: $($filtered[0].Title)" }
    return $filtered
}

function Get-CatalogDownloadURL ([string]$UpdateID) {
    $body = @{ updateIDs = "[{`"uidInfo`":`"$UpdateID`",`"updateID`":`"$UpdateID`"}]" }
    $resp = Invoke-WebRequest -Uri 'https://www.catalog.update.microsoft.com/DownloadDialog.aspx' -Method Post -Body $body -UseBasicParsing -EA Stop
    $m = [regex]::Match($resp.Content, "https?://[^'`"]+\.(?:msu|cab)")
    if ($m.Success) { return $m.Value }
    return $null
}

function Invoke-PatchFetch ([string]$SourcePath, [string]$WinVer, [string]$WimPath, [int]$ImageIndex, [string]$BuildDir) {
    $verLabel = Get-VersionLabel $WimPath $ImageIndex
    if (-not $verLabel) { Write-Log "Could not determine version label — skipping patch check" -Level Warn; return }
    Write-Log "Detected version: $verLabel"

    try {
        $null = Invoke-WebRequest -Uri 'https://www.catalog.update.microsoft.com' -UseBasicParsing -TimeoutSec 5 -EA Stop
    } catch {
        Write-Log 'Offline — skipping patch download' -Level Warn
        return
    }

    Write-Log "Online — checking patches (Windows $WinVer $verLabel x64)"
    # Download to the build folder, not the source folder — source is read-only input
    $updDir = Join-Path $BuildDir 'Updates'; New-Item $updDir -ItemType Directory -Force -EA SilentlyContinue | Out-Null

    $downloaded = 0

    foreach ($search in @(
        @{ Query = "Cumulative Update for Windows $WinVer Version $verLabel for x64"; Label = 'LCU' }
        @{ Query = "Cumulative Update for .NET Framework for Windows $WinVer Version $verLabel for x64"; Label = '.NET' }
    )) {
        try {
            $results = Search-UpdateCatalog $search.Query
            if ($results.Count -eq 0) { Write-Log "No $($search.Label) found" -Level Warn; continue }

            $best = $results | Sort-Object {
                if ($_.Title -match '(\d{4}-\d{2})') { $Matches[1] } else { '0000-00' }
            } -Descending | Select-Object -First 1

            Write-Log "Selected: $($best.Title)"
            $url = Get-CatalogDownloadURL $best.UpdateID
            if (-not $url) { Write-Log "No download URL for $($search.Label)" -Level Warn; continue }

            $fileName = [IO.Path]::GetFileName(([uri]$url).LocalPath)
            $destFile = Join-Path $updDir $fileName
            if (Test-Path $destFile) { Write-Log "$fileName already present"; continue }

            Write-Host "  [>] Downloading $fileName" -ForegroundColor White
            $ProgressPreference = 'SilentlyContinue'
            Invoke-WebRequest -Uri $url -OutFile $destFile -UseBasicParsing
            $fileSize = (Get-Item $destFile).Length
            if ($fileSize -lt 1MB) {
                Remove-Item $destFile -Force -EA SilentlyContinue
                Write-Log "Download appears truncated ($([math]::Round($fileSize/1KB)) KB) — removed" -Level Warn
                continue
            }
            $sizeMB = [math]::Round($fileSize / 1MB)
            Write-Log "Saved $($search.Label) (${sizeMB} MB)"
            $downloaded++
        } catch {
            Write-Log "Patch fetch failed for $($search.Label): $_" -Level Warn
        }
    }

    if ($downloaded -gt 0) { Write-Log "Downloaded $downloaded patch(es)" }
    else { Write-Log 'No new patches to download' }
}


function New-AnswerFile {
    param(
        [string]$Locale, [string]$Keyboard, [string]$TZ, [string]$ProductKey,
        [string]$EditionLabel, [string]$PAW, [string]$OutputDir
    )
    $c = 'processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS"'
    $n = 'xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"'
    $ppc = if ($PAW -eq 'CLOUD') { '1' } else { '3' }
    $accounts = if ($PAW -eq 'LOCAL') { @"

    <UserAccounts><LocalAccounts>
      <LocalAccount wcm:action="add"><DisplayName>PAWUSER</DisplayName><Group>Users</Group><Name>PAWUSER</Name></LocalAccount>
      <LocalAccount wcm:action="add"><DisplayName>PAWADMIN</DisplayName><Group>Administrators</Group><Name>PAWADMIN</Name></LocalAccount>
    </LocalAccounts></UserAccounts><RegisteredOwner>PAWUSER</RegisteredOwner>
"@ } else { '' }

    $xml = @"
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
  <settings pass="windowsPE"><component name="Microsoft-Windows-International-Core-WinPE" $c $n>
    <SetupUILanguage><UILanguage>$Locale</UILanguage></SetupUILanguage>
    <InputLocale>$Keyboard</InputLocale><SystemLocale>$Locale</SystemLocale><UILanguage>$Locale</UILanguage><UILanguageFallback>$Locale</UILanguageFallback><UserLocale>$Locale</UserLocale>
  </component><component name="Microsoft-Windows-Setup" $c $n>
    <DiskConfiguration><Disk wcm:action="add"><DiskID>0</DiskID><WillWipeDisk>true</WillWipeDisk>
      <CreatePartitions>
        <CreatePartition wcm:action="add"><Order>1</Order><Type>Primary</Type><Size>300</Size></CreatePartition>
        <CreatePartition wcm:action="add"><Order>2</Order><Type>EFI</Type><Size>260</Size></CreatePartition>
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
    <UserData><ProductKey><Key>$ProductKey</Key><WillShowUI>Never</WillShowUI></ProductKey><AcceptEula>true</AcceptEula></UserData>
  </component></settings>
  <settings pass="offlineServicing"><component name="Microsoft-Windows-PnpCustomizationsNonWinPE" $c $n><DriverPaths>
    <PathAndCredentials wcm:action="add" wcm:keyValue="1"><Path>C:\Drivers</Path></PathAndCredentials>
    <PathAndCredentials wcm:action="add" wcm:keyValue="2"><Path>D:\Drivers</Path></PathAndCredentials>
    <PathAndCredentials wcm:action="add" wcm:keyValue="3"><Path>E:\Drivers</Path></PathAndCredentials>
  </DriverPaths></component></settings>
  <settings pass="specialize"><component name="Microsoft-Windows-Shell-Setup" $c $n>
    <TimeZone>$TZ</TimeZone><ComputerName></ComputerName><ProductKey>$ProductKey</ProductKey>
  </component></settings>
  <settings pass="oobeSystem"><component name="Microsoft-Windows-Shell-Setup" $c $n>
    <OOBE><HideEULAPage>true</HideEULAPage><HideOEMRegistrationScreen>true</HideOEMRegistrationScreen><HideOnlineAccountScreens>true</HideOnlineAccountScreens><HideWirelessSetupInOOBE>false</HideWirelessSetupInOOBE><ProtectYourPC>$ppc</ProtectYourPC></OOBE>$accounts
  </component><component name="Microsoft-Windows-International-Core" $c $n>
    <InputLocale>$Keyboard</InputLocale><SystemLocale>$Locale</SystemLocale><UILanguage>$Locale</UILanguage><UserLocale>$Locale</UserLocale>
  </component></settings>
</unattend>
<!-- SAROS $PAW | $EditionLabel | $Locale | $(Get-Date -f 'yyyy-MM-dd HH:mm') -->
"@
    $xml | Set-Content (Join-Path $OutputDir 'autounattend.xml') -Encoding UTF8 -Force
    Write-Log "Answer file generated ($PAW / $EditionLabel)"
}


function New-BootableISO ([string]$SourceDir, [string]$OutputPath) {
    $efi = Join-Path $SourceDir 'efi' 'microsoft' 'boot' 'efisys.bin'
    if (-not (Test-Path $efi)) { throw 'efisys.bin not found. Is this a valid UEFI Windows ISO?' }

    $adkPaths = @(
        "${env:ProgramFiles(x86)}\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\amd64\Oscdimg\oscdimg.exe"
        "$env:ProgramFiles\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\amd64\Oscdimg\oscdimg.exe"
    )
    $oscdimg = $adkPaths | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $oscdimg) { $oscdimg = (Get-Command oscdimg.exe -EA SilentlyContinue).Source }
    if (-not $oscdimg) { throw 'oscdimg.exe not found. Install Windows ADK: https://go.microsoft.com/fwlink/?linkid=2243390' }

    Write-Log "oscdimg: $oscdimg"
    & $oscdimg -b"$((Resolve-Path $efi).Path)" -pEF -u1 -udfver102 "$((Resolve-Path $SourceDir).Path)" "$OutputPath" 2>&1 |
        Where-Object { $_ -match '\S' } | ForEach-Object { Write-Log $_ }
    Get-FileHash $OutputPath | Out-File (Join-Path (Split-Path $OutputPath) 'HASHES.txt') -Force
}

function Write-ToUSB ([string]$SourceDir, [switch]$Auto, [switch]$Quiet) {
    do {
        $usbDisks = @(Get-Disk | Where-Object { $_.BusType -eq 'USB' -and $_.Size -gt 7GB -and $_.Size -lt 128GB })
        if ($usbDisks.Count -eq 0) { throw 'No USB drives found (8-128 GB).' }

        $usbDisk = if ($usbDisks.Count -gt 1 -and -not $Auto) {
            $usbDisks | ForEach-Object { Write-Host "    Disk $($_.Number): $($_.FriendlyName) — $([math]::Round($_.Size/1GB,1)) GB" -ForegroundColor Gray }
            $usbDisks | Where-Object Number -EQ (Read-Host '  Disk number')
        } else { $usbDisks | Select-Object -First 1 }

        if (-not $usbDisk) { throw 'No USB disk selected.' }
        if (-not $Auto) {
            Write-Host "  ALL DATA on Disk $($usbDisk.Number) ($($usbDisk.FriendlyName)) will be ERASED." -ForegroundColor Red
            if ((Read-Host '  Type YES to confirm') -ne 'YES') { throw 'USB write cancelled.' }
        }

        $usbDisk | Clear-Disk -RemoveData -Confirm:$false
        $usbDisk | Initialize-Disk -PartitionStyle GPT
        $partition = $usbDisk | New-Partition -UseMaximumSize -AssignDriveLetter
        Format-Volume -Partition $partition -FileSystem FAT32 -NewFileSystemLabel 'SAROS' -Confirm:$false | Out-Null
        Copy-Item "$SourceDir\*" "$($partition.DriveLetter):\" -Recurse -Force
        Write-Log "USB $($partition.DriveLetter): complete"

        if ($Quiet) { break }
        $again = Read-Host '  Write another USB? (y/N)'
    } while ($again -in 'y', 'Y', 'yes')
}


function Invoke-VMManager {
    Write-Banner 'SAROS VM Manager'
    $vms = @(Get-VM | Where-Object Name -Like 'SAROS-*')
    if ($vms.Count -eq 0) { Write-Host '  No SAROS VMs found.' -ForegroundColor Yellow; return }

    $names = $vms | ForEach-Object { "$($_.Name)  [$($_.State)]  $($_.CreationTime)" }
    $picked = Select-FromList 'Select VM to delete' $names $null
    $vm = $vms | Where-Object { $picked -match $_.Name } | Select-Object -First 1
    if (-not $vm) { return }

    Stop-VM -Name $vm.Name -Force -TurnOff -Confirm:$false -EA SilentlyContinue
    Start-Sleep 3
    $vhdPath = (Get-VM $vm.Name | Get-VMHardDiskDrive).Path | Split-Path
    Remove-VM -Name $vm.Name -Force -EA SilentlyContinue
    if ($vhdPath -and (Test-Path $vhdPath)) { Remove-Item $vhdPath -Recurse -Force -EA SilentlyContinue }
    Write-Log "Deleted VM: $($vm.Name)"
}


function Start-SAROSBuild {
    $Script:StartTime = Get-Date
    $totalSteps = 12
    $interactive = -not $Silent

    Write-SplashBanner

    # ── Resolve source path ──────────────────────────────────────────
    $srcPath = $SourcePath
    if (-not $srcPath -and $interactive) { $srcPath = Read-FolderPath -Prompt 'Source folder (contains the Windows ISO)' -MustExist }
    if (-not $srcPath -or -not (Test-Path $srcPath)) { throw "Source path required: $srcPath" }

    # ── Find and read ISO ────────────────────────────────────────────
    $isoFile = Find-ISOFile $srcPath
    if (-not $isoFile) { throw "No .iso found in $srcPath" }
    Write-Log "ISO: $(Split-Path $isoFile -Leaf)"

    $isoMount = Mount-SourceISO $isoFile
    $wimPath  = Join-Path $isoMount 'sources' 'install.wim'
    if (-not (Test-Path $wimPath)) { Dismount-SourceISO; throw 'No install.wim in ISO.' }

    $allEditions = Get-WimEditions $wimPath
    # Keep ISO mounted — reused in step 3+

    # ── Select edition from ISO ──────────────────────────────────────
    $editions = @($allEditions | Where-Object { $_.ImageName -notmatch ' N$| N ' -and $_.ImageName -notmatch 'Single Language' })
    if ($editions.Count -eq 0) { $editions = @($allEditions) }

    $selectedEdition = $null
    if ($Edition) {
        $selectedEdition = $editions | Where-Object { $_.ImageName -match $Edition } | Select-Object -First 1
    }
    if (-not $selectedEdition -and $interactive) {
        $editionNames = $editions | ForEach-Object { $_.ImageName }
        $pickedName = Select-FromList -Prompt 'Select edition' -Items $editionNames
        $selectedEdition = $editions | Where-Object { $_.ImageName -eq $pickedName } | Select-Object -First 1
    }
    if (-not $selectedEdition) { throw "Edition not found. Available: $(($allEditions.ImageName) -join ', ')" }

    $winVer    = if ($selectedEdition.ImageName -match '11') { '11' } else { '10' }
    $edShort   = ($selectedEdition.ImageName -replace 'Windows\s+\d+\s+', '').Trim() -replace '\s+', ''
    $kmsKey    = Resolve-KMSKey $selectedEdition.ImageName
    Write-Log "Edition: $($selectedEdition.ImageName) (index $($selectedEdition.ImageIndex), Win $winVer)"

    # ── Select remaining settings ────────────────────────────────────
    $selLang = $Language
    if (-not $selLang -and $interactive) {
        $langNames = ($Script:LOCALES | Sort-Object N).N
        $pickedLang = Select-FromList -Prompt 'Setup language (keyboard + locale)' -Items $langNames -Default 'English (United Kingdom)'
        $selLang = ($Script:LOCALES | Where-Object N -EQ $pickedLang).L
    }
    $localeRec = $Script:LOCALES | Where-Object L -EQ $selLang
    if (-not $localeRec) { throw "Unknown locale: $selLang" }

    $selTZ = $TimeZone
    if (-not $selTZ -and $interactive) {
        $tzDisplays = $Script:TIMEZONES | ForEach-Object { ($_ -split '\|')[1] }
        $pickedTZ = Select-FromList -Prompt 'Time zone' -Items $tzDisplays -Default '(UTC) Dublin - Edinburgh - Lisbon - London'
        $selTZ = ($Script:TIMEZONES | Where-Object { ($_ -split '\|')[1] -eq $pickedTZ } | ForEach-Object { ($_ -split '\|')[0] })
    }
    if (-not ($Script:TIMEZONES | Where-Object { ($_ -split '\|')[0] -eq $selTZ })) { throw "Unknown timezone: $selTZ" }

    $selPAW = $PAWType
    if (-not $selPAW -and $interactive) { $selPAW = Select-FromList -Prompt 'PAW type' -Items @('LOCAL','CLOUD') -Default 'LOCAL' }
    if (-not $selPAW) { $selPAW = 'LOCAL' }

    $selOutput = $OutputType
    if (-not $selOutput -and $interactive) { $selOutput = Select-FromList -Prompt 'Output type' -Items @('ISO','USB') -Default 'ISO' }
    if (-not $selOutput) { $selOutput = 'ISO' }

    # ── Build workspace ──────────────────────────────────────────────
    $workspace = $BuildPath
    if (-not $workspace -and $interactive) {
        Write-Host "`n  Build workspace (builds are created inside this folder)" -ForegroundColor White
        Write-Host '    Press Enter for current directory' -ForegroundColor DarkGray
        $raw = Read-Host '  Path'
        $workspace = if ([string]::IsNullOrWhiteSpace($raw)) { (Get-Location).Path } else { $raw }
    }
    if (-not $workspace) { $workspace = (Get-Location).Path }
    if (-not (Test-Path $workspace)) { New-Item $workspace -ItemType Directory -Force | Out-Null }

    $buildStamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $buildName  = "SAROS_Win${winVer}-${edShort}_${buildStamp}"
    $buildDir   = Join-Path $workspace $buildName

    # ── Confirm ──────────────────────────────────────────────────────
    Write-Host "`n  SAROS build configuration" -ForegroundColor White
    Write-Host "    Edition  : $($selectedEdition.ImageName)" -ForegroundColor Gray
    Write-Host "    Language : $($localeRec.L) — $($localeRec.N)" -ForegroundColor Gray
    Write-Host "    TimeZone : $selTZ" -ForegroundColor Gray
    Write-Host "    PAW Type : $selPAW" -ForegroundColor Gray
    Write-Host "    Output   : $selOutput" -ForegroundColor Gray
    Write-Host "    Source   : $srcPath" -ForegroundColor Gray
    Write-Host "    Build    : $buildDir" -ForegroundColor Gray
    Write-Host ''
    if ($interactive) {
        $confirm = Read-Host '  Proceed? (Y/n)'
        if ($confirm -and $confirm -notin 'Y', 'y', 'yes') { return }
    }

    # ── Pre-flight: disk space ───────────────────────────────────────
    $buildDrive = (Split-Path $buildDir -Qualifier)
    $freeGB = [math]::Round((Get-PSDrive ($buildDrive -replace ':') | Select-Object -Expand Free) / 1GB, 1)
    if ($freeGB -lt 15) {
        throw "Insufficient disk space on ${buildDrive}. Need 15 GB, have $freeGB GB."
    }
    Write-Log "Disk space: $freeGB GB free on $buildDrive"

        # STEP 1 — Create folder structure
        Write-Step 1 $totalSteps 'Creating build structure'
    foreach ($dir in 'DISM-Offline','ISO-Files','ISO-Temp','ISO-Temp\split','SAROS','SAROS\Firewall-Rules','SAROS\W11Apps') {
        New-Item (Join-Path $buildDir $dir) -ItemType Directory -Force | Out-Null
    }
    Set-Location $buildDir

        # STEP 2 — Stage hardening content
        Write-Step 2 $totalSteps 'Staging hardening content'
    Write-RegFile (Join-Path $buildDir 'SAROS\BlackHoleProxy.reg') $Script:HARDEN.BlackHoleProxy
    Write-RegFile (Join-Path $buildDir 'SAROS\FW.reg')             $Script:HARDEN.FirewallProfiles
    Write-RegFile (Join-Path $buildDir 'SAROS\FWRules.reg')        $Script:HARDEN.FirewallRules
    $Script:HARDEN.FirstBootFirewall | Set-Content (Join-Path $buildDir 'SAROS\Firewall-Rules\FwRules.ps1') -Encoding UTF8
    $Script:HARDEN.SetupComplete     | Set-Content (Join-Path $buildDir 'SAROS\SetupComplete.cmd') -Encoding ASCII
    $Script:HARDEN.W10Apps           | Set-Content (Join-Path $buildDir 'SAROS\W10Apps.txt') -Encoding UTF8
    $Script:HARDEN.W11Apps           | Set-Content (Join-Path $buildDir 'SAROS\W11Apps.txt') -Encoding UTF8
    $Script:HARDEN.W11Apps           | Set-Content (Join-Path $buildDir 'SAROS\W11Apps\W11Apps.txt') -Encoding UTF8
    $Script:HARDEN.W11FirstBoot      | Set-Content (Join-Path $buildDir 'SAROS\W11Apps\W11AppRemoval.ps1') -Encoding UTF8

        # STEP 3 — Mount ISO
        Write-Step 3 $totalSteps 'Reading ISO metadata'
    $wimSrc = Join-Path $isoMount 'sources' 'install.wim'

    # Auto-fetch patches (best-effort, silent failure)
    try {
        $wimDetail  = Get-WindowsImage -ImagePath $wimSrc -Index $selectedEdition.ImageIndex
        $buildNum   = [int]($wimDetail.Version -replace '^[\d]+\.[\d]+\.(\d+).*', '$1')
        Write-Log "Build: $buildNum"
        Invoke-PatchFetch $srcPath $winVer $wimSrc $selectedEdition.ImageIndex $buildDir
    } catch {
        Write-Log "Auto-fetch skipped: $_" -Level Warn
    }

        # STEP 4 — Copy ISO contents, export edition
        Write-Step 4 $totalSteps 'Copying ISO and exporting edition'
    $isoFilesDir = Join-Path $buildDir 'ISO-Files'
    Copy-Item (Join-Path $isoMount '*') $isoFilesDir -Recurse -Force
    Get-ChildItem $isoFilesDir -Recurse -File | ForEach-Object { $_.IsReadOnly = $false }

    $wimInFiles = Join-Path $isoFilesDir 'sources' 'install.wim'
    $wimExport  = Join-Path $buildDir 'ISO-Temp' 'export.wim'
    Export-WindowsImage -SourceImagePath $wimInFiles -SourceIndex $selectedEdition.ImageIndex -DestinationImagePath $wimExport -DestinationName $selectedEdition.ImageName -CompressionType Max | Out-Null
    Move-Item $wimInFiles (Join-Path $buildDir 'ISO-Temp' 'install-multi.wim')
    Move-Item $wimExport $wimInFiles -Force

    # Patch boot.wim for Win11 24H2 compatibility
    if ($winVer -eq '11') {
        Write-Log 'Patching boot.wim for 24H2 (legacy Setup CmdLine)'
        $bootWim = Join-Path $isoFilesDir 'sources' 'boot.wim'
        if (Test-Path $bootWim) {
            $bootDir = Join-Path $buildDir 'ISO-Temp' 'bootpatch'
            New-Item $bootDir -ItemType Directory -Force | Out-Null
            Mount-WindowsImage -ImagePath $bootWim -Index 1 -Path $bootDir | Out-Null
            $bootHive = Join-Path $bootDir 'Windows' 'System32' 'config' 'SYSTEM'
            & reg.exe load 'HKLM\BOOT_SYS' $bootHive 2>$null | Out-Null
            & reg.exe add 'HKLM\BOOT_SYS\Setup' /v CmdLine /t REG_SZ /d 'X:\sources\setup.exe' /f 2>$null | Out-Null
            [GC]::Collect(); Start-Sleep -Milliseconds 300
            & reg.exe UNLOAD 'HKLM\BOOT_SYS' 2>$null | Out-Null
            Dismount-WindowsImage -Path $bootDir -Save | Out-Null
            Remove-Item $bootDir -Recurse -Force -EA SilentlyContinue
            Write-Log 'boot.wim patched'
        }
    }

        # STEP 5 — Mount WIM
        Write-Step 5 $totalSteps 'Mounting WIM for servicing'
    $dismDir = Join-Path $buildDir 'DISM-Offline'
    Mount-WindowsImage -ImagePath $wimInFiles -Index 1 -Path $dismDir | Out-Null
    $Script:WIMMounted = $true
    foreach ($dir in 'SAROS\Firewall-Rules', 'SAROS\W11Apps', 'Windows\Setup\Scripts') {
        New-Item (Join-Path $dismDir $dir) -ItemType Directory -Force -EA SilentlyContinue | Out-Null
    }

        # STEP 6 — Inject drivers, updates, Autopilot
        Write-Step 6 $totalSteps 'Injecting offline content'
    $drvPath = Join-Path $srcPath 'Drivers'
    $ssuPath = Join-Path $srcPath 'SSU'
    $updPath = Join-Path $srcPath 'Updates'
    $apPath  = Join-Path $srcPath 'Autopilot'
    $fetchedPath = Join-Path $buildDir 'Updates'

    if (Test-Path "$drvPath\*") { Write-Log 'Injecting drivers'; Add-WindowsDriver -Path $dismDir -Driver $drvPath -Recurse | Out-Null }

    # SSU and Updates — source folder (user-provided) + build folder (auto-fetched)
    $packageSummary = @{ Applied = 0; Superseded = 0; Failed = 0 }

    foreach ($folder in @($ssuPath, $updPath, $fetchedPath)) {
        foreach ($msuFile in @(Get-ChildItem (Join-Path $folder '*.msu') -EA SilentlyContinue)) {
            # Pre-validate: skip truncated files
            if ($msuFile.Length -lt 1MB) {
                Write-Log "Removing truncated file: $($msuFile.Name) ($([math]::Round($msuFile.Length/1KB)) KB)" -Level Warn
                Remove-Item $msuFile.FullName -Force -EA SilentlyContinue
                $packageSummary.Failed++
                continue
            }

            try {
                Write-Log "Applying: $($msuFile.Name) ($([math]::Round($msuFile.Length/1MB)) MB)"
                $warnMsg = $null
                Add-WindowsPackage -PackagePath $msuFile.FullName -Path $dismDir -WarningVariable warnMsg -WarningAction SilentlyContinue -EA Stop | Out-Null
                $packageSummary.Applied++
            }
            catch {
                $errorMsg = $_.Exception.Message
                $allText  = "$errorMsg $warnMsg"
                $hresult  = if ($allText -match '(0x[0-9a-fA-F]{8})') { $Matches[1] } else { 'unknown' }

                switch -Regex ($hresult) {
                    '0x800f081e|0x800f0823' {
                        # Package not applicable / already superseded
                        Write-Log "Superseded: $($msuFile.Name) — a newer update is already applied" -Level Warn
                        $packageSummary.Superseded++
                    }
                    '0x8007000d' {
                        # Invalid data — corrupted or wrong format
                        Write-Log "Corrupted or incompatible: $($msuFile.Name) — removing" -Level Warn
                        Remove-Item $msuFile.FullName -Force -EA SilentlyContinue
                        $packageSummary.Failed++
                    }
                    '0x80070002' {
                        # File not found (race condition or bad path)
                        Write-Log "File not found: $($msuFile.Name)" -Level Warn
                        $packageSummary.Failed++
                    }
                    default {
                        # Unknown error — log full detail but don't crash
                        Write-Log "Failed: $($msuFile.Name) — $errorMsg" -Level Warn
                        $packageSummary.Failed++
                    }
                }
            }
        }
    }

    if (($packageSummary.Applied + $packageSummary.Superseded + $packageSummary.Failed) -gt 0) {
        Write-Log "Updates: $($packageSummary.Applied) applied, $($packageSummary.Superseded) superseded, $($packageSummary.Failed) failed"
    }
    if ((Test-Path "$apPath\*.json") -and $selPAW -eq 'CLOUD') {
        $apDest = Join-Path $dismDir 'Windows' 'Provisioning' 'Autopilot'
        New-Item $apDest -ItemType Directory -Force -EA SilentlyContinue | Out-Null
        Copy-Item "$apPath\*.json" $apDest -Force
        Write-Log 'Injected Autopilot config'
    }

        # STEP 7 — Registry hardening
        Write-Step 7 $totalSteps 'Applying registry hardening'
    $usrHive  = Join-Path $dismDir 'Users' 'Default' 'NTUSER.DAT'
    $sysHive  = Join-Path $dismDir 'Windows' 'System32' 'config' 'SYSTEM'
    $softHive = Join-Path $dismDir 'Windows' 'System32' 'config' 'SOFTWARE'

    # User hive — proxy lockdown
    Mount-OfflineHive 'USR' $usrHive
    Import-OfflineReg (Join-Path $buildDir 'SAROS\BlackHoleProxy.reg')
    if ($winVer -eq '11') { Set-OfflineRegValue -HiveName 'USR' -SubKey 'Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -ValueName 'TaskbarDa' -Value 0 }
    Dismount-OfflineHive 'USR'

    # System hive — firewall + NTLM + SMB signing
    Mount-OfflineHive 'SYS' $sysHive
    Import-OfflineReg (Join-Path $buildDir 'SAROS\FW.reg')
    Import-OfflineReg (Join-Path $buildDir 'SAROS\FWRules.reg')
    Copy-Item (Join-Path $buildDir 'SAROS\Firewall-Rules\FwRules.ps1') (Join-Path $dismDir 'SAROS\Firewall-Rules\FwRules.ps1') -Force
    Set-OfflineRegValue -HiveName 'SYS' -SubKey 'ControlSet001\Control\Lsa' -ValueName 'LmCompatibilityLevel' -Value 5
    Set-OfflineRegValue -HiveName 'SYS' -SubKey 'ControlSet001\Control\Lsa' -ValueName 'NoLMHash' -Value 1
    Set-OfflineRegValue -HiveName 'SYS' -SubKey 'ControlSet001\Services\LanmanServer\Parameters' -ValueName 'RequireSecuritySignature' -Value 1
    Set-OfflineRegValue -HiveName 'SYS' -SubKey 'ControlSet001\Services\LanmanServer\Parameters' -ValueName 'EnableSecuritySignature' -Value 1
    Set-OfflineRegValue -HiveName 'SYS' -SubKey 'ControlSet001\Services\LanmanWorkstation\Parameters' -ValueName 'RequireSecuritySignature' -Value 1
    Set-OfflineRegValue -HiveName 'SYS' -SubKey 'ControlSet001\Services\LanmanWorkstation\Parameters' -ValueName 'EnableSecuritySignature' -Value 1
    Write-Log 'Applied: NTLMv2 only + SMB signing enforced'
    Dismount-OfflineHive 'SYS'

    # Software hive — Credential Guard + RunOnce scripts
    Mount-OfflineHive 'SOFT' $softHive
    Set-OfflineRegValue -HiveName 'SOFT' -SubKey 'Policies\Microsoft\Windows\DeviceGuard' -ValueName 'EnableVirtualizationBasedSecurity' -Value 1
    Set-OfflineRegValue -HiveName 'SOFT' -SubKey 'Policies\Microsoft\Windows\DeviceGuard' -ValueName 'RequirePlatformSecurityFeatures' -Value 3
    Set-OfflineRegValue -HiveName 'SOFT' -SubKey 'Policies\Microsoft\Windows\DeviceGuard' -ValueName 'LsaCfgFlags' -Value 1
    Write-Log 'Applied: Credential Guard enabled'
    Set-OfflineRegValue -HiveName 'SOFT' -SubKey 'Microsoft\Windows\CurrentVersion\RunOnce' -ValueName 'SAROS-FW' -Value 'powershell.exe -ExecutionPolicy Bypass -File C:\SAROS\Firewall-Rules\FwRules.ps1' -Type String
    if ($winVer -eq '11') {
        Copy-Item (Join-Path $buildDir 'SAROS\W11Apps\*') (Join-Path $dismDir 'SAROS\W11Apps\') -Force
        Set-OfflineRegValue -HiveName 'SOFT' -SubKey 'Microsoft\Windows\CurrentVersion\RunOnce' -ValueName 'SAROS-W11' -Value 'powershell.exe -ExecutionPolicy Bypass -File C:\SAROS\W11Apps\W11AppRemoval.ps1' -Type String
    }
    Dismount-OfflineHive 'SOFT'

    Copy-Item (Join-Path $buildDir 'SAROS\SetupComplete.cmd') (Join-Path $dismDir 'Windows\Setup\Scripts\SetupComplete.cmd') -Force

        # STEP 8 — Remove bloatware
        Write-Step 8 $totalSteps 'Removing provisioned bloatware'
    $appListFile = if ($winVer -eq '10') { Join-Path $buildDir 'SAROS\W10Apps.txt' } else { Join-Path $buildDir 'SAROS\W11Apps.txt' }
    $removedCount = 0; $skippedCount = 0
    foreach ($appName in (Get-Content $appListFile)) {
        try {
            $pkg = Get-AppxProvisionedPackage -Path $dismDir | Where-Object DisplayName -EQ $appName
            if ($pkg) { $pkg | Remove-AppxProvisionedPackage | Out-Null; $removedCount++ }
        } catch {
            $skippedCount++
        }
    }
    Write-Log "Apps removed: $removedCount, skipped: $skippedCount"

    # Shrink WinRE if oversized
    $wrePath = Join-Path $dismDir 'Windows\System32\Recovery\winre.wim'
    if ((Test-Path $wrePath) -and (Get-Item $wrePath).Length -gt 400MB) {
        Write-Log 'Shrinking WinRE'
        Export-WindowsImage -SourceImagePath $wrePath -SourceIndex 1 -DestinationImagePath "${wrePath}.new" | Out-Null
        Remove-Item $wrePath; Rename-Item "${wrePath}.new" 'winre.wim'
    }

        # STEP 9 — Answer file
        Write-Step 9 $totalSteps "Generating $selPAW answer file"
    New-AnswerFile -Locale $localeRec.L -Keyboard $localeRec.K -TZ $selTZ -ProductKey $kmsKey -EditionLabel $edShort -PAW $selPAW -OutputDir $isoFilesDir

        # STEP 10 — Save and recompress WIM
        Write-Step 10 $totalSteps 'Saving and recompressing WIM'
    & dism.exe /Image:$dismDir /Cleanup-Image /StartComponentCleanup /ResetBase 2>&1 | Where-Object { $_ -match '\S' -and $_ -notmatch 'LogPath' } | ForEach-Object { Write-Log $_ }
    Dismount-WindowsImage -Path $dismDir -Save | Out-Null
    $Script:WIMMounted = $false

    $recompWim = Join-Path $buildDir 'ISO-Temp\recomp.wim'
    Export-WindowsImage -SourceImagePath $wimInFiles -SourceIndex 1 -DestinationImagePath $recompWim -DestinationName $selectedEdition.ImageName -CompressionType Max | Out-Null
    if ((Get-Item $recompWim).Length -lt (Get-Item $wimInFiles).Length) {
        Move-Item $wimInFiles (Join-Path $buildDir 'ISO-Temp\install-pre.wim')
        Move-Item $recompWim $wimInFiles -Force
    } else {
        Remove-Item $recompWim
    }

    Dismount-SourceISO

    # Split WIM if >4GB (FAT32 limit)
    if ((Get-Item $wimInFiles).Length -gt 4GB) {
        Write-Log 'Splitting WIM for FAT32'
        $splitDir = Join-Path $buildDir 'ISO-Temp\split'
        Move-Item $wimInFiles $splitDir
        Split-WindowsImage -ImagePath (Join-Path $splitDir 'install.wim') -SplitImagePath (Join-Path $splitDir 'install.swm') -FileSize 4096 | Out-Null
        Copy-Item (Join-Path $splitDir '*.swm') (Join-Path $isoFilesDir 'sources')
    }

        # STEP 11 — Create output
        $isoName = "SAROS_${edShort}_Win${winVer}_$($localeRec.L)_${buildStamp}.iso"

    if ($selOutput -eq 'USB') {
        Write-Step 11 $totalSteps 'Writing to USB'
        Write-ToUSB -SourceDir $isoFilesDir -Auto:($AutoConfirmUSB -or $Silent) -Quiet:$Silent
    } else {
        Write-Step 11 $totalSteps 'Creating bootable ISO'
        $isoPath = Join-Path $buildDir $isoName
        New-BootableISO -SourceDir $isoFilesDir -OutputPath $isoPath
        Write-Log "ISO: $isoPath"

        if ($CreateTestVM) {
            Write-Log 'Creating Hyper-V test VM'
            $vmName = "SAROS-$(Get-Date -Format 'yyyyMMdd-HHmm')"
            $vmDir  = Join-Path $buildDir 'VM'
            New-VM -Name $vmName -NewVHDPath (Join-Path $vmDir "$vmName.vhdx") -NewVHDSizeBytes 64GB -MemoryStartupBytes 4GB -Path (Join-Path $vmDir 'VMs' $vmName) -Generation 2
            Set-VMMemory $vmName -DynamicMemoryEnabled $false
            Set-VMProcessor $vmName -Count 2 -Confirm:$false
            Set-VMKeyProtector $vmName -NewLocalKeyProtector
            Enable-VMTPM $vmName -Confirm:$false
            Add-VMDvdDrive $vmName -Path $isoPath
            Set-VMFirmware $vmName -FirstBootDevice (Get-VMDvdDrive $vmName)
            Start-VM $vmName
        }
    }

        # STEP 12 — Done
        Write-Step 12 $totalSteps 'Complete'
    $elapsed = (Get-Date).Subtract($Script:StartTime).ToString('hh\:mm\:ss')
    Write-Banner 'SAROS BUILD FINISHED'
    if ($selOutput -eq 'USB') {
        Write-Host '  USB ready. Boot target device (F12).' -ForegroundColor Green
    } else {
        Write-Host "  ISO: $(Join-Path $buildDir $isoName)" -ForegroundColor Green
    }
    Write-Host "  Log: $Script:LogFile" -ForegroundColor DarkGray
    Write-Host "  Elapsed: $elapsed`n" -ForegroundColor DarkGray
}


try {
    if ($ManageVMs) {
        Invoke-VMManager
        return
    }

    if ($AnswerFileOnly) {
        Write-SplashBanner
        $int = -not $Silent
        $ed = $Edition
        if (-not $ed -and $int) { $ed = Select-FromList -Prompt 'Edition' -Items @('Pro','Enterprise','Education') -Default 'Pro' }
        if (-not $ed) { throw 'Edition required.' }
        $edK = if ($ed -in 'Enterprise','ENT') { 'ENT' } else { 'PRO' }

        $lang = $Language
        if (-not $lang -and $int) {
            $pickedLang = Select-FromList -Prompt 'Language' -Items (($Script:LOCALES | Sort-Object N).N) -Default 'English (United Kingdom)'
            $lang = ($Script:LOCALES | Where-Object N -EQ $pickedLang).L
        }
        $lr = $Script:LOCALES | Where-Object L -EQ $lang
        if (-not $lr) { throw "Unknown locale: $lang" }

        $tz = $TimeZone
        if (-not $tz -and $int) {
            $tzD = $Script:TIMEZONES | ForEach-Object { ($_ -split '\|')[1] }
            $pickedTZ = Select-FromList -Prompt 'Time zone' -Items $tzD -Default '(UTC) Dublin - Edinburgh - Lisbon - London'
            $tz = ($Script:TIMEZONES | Where-Object { ($_ -split '\|')[1] -eq $pickedTZ } | ForEach-Object { ($_ -split '\|')[0] })
        }

        $pt = $PAWType
        if (-not $pt -and $int) { $pt = Select-FromList -Prompt 'PAW type' -Items @('LOCAL','CLOUD') -Default 'LOCAL' }
        if (-not $pt) { $pt = 'LOCAL' }

        $outDir = $BuildPath
        if (-not $outDir -and $int) { $outDir = Read-FolderPath -Prompt 'Output folder' }
        if (-not $outDir) { throw 'BuildPath required.' }
        New-Item $outDir -ItemType Directory -Force -EA SilentlyContinue | Out-Null

        $key = if ($edK -eq 'ENT') { $Script:KMS_KEYS['Enterprise'] } else { $Script:KMS_KEYS['Pro'] }
        New-AnswerFile -Locale $lr.L -Keyboard $lr.K -TZ $tz -ProductKey $key -EditionLabel $edK -PAW $pt -OutputDir $outDir
        Write-Host "  Created: $(Join-Path $outDir 'autounattend.xml')" -ForegroundColor Green
        return
    }

    Start-SAROSBuild
}
catch {
    Write-Log "FATAL: $_" -Level Error
    Write-Log $_.ScriptStackTrace -Level Error
    Write-Host "`n  FATAL: $_" -ForegroundColor Red
    Write-Host "  $($_.ScriptStackTrace)" -ForegroundColor DarkRed
    Write-Host "  Log: $Script:LogFile" -ForegroundColor DarkGray

    # Rollback: offer to remove partial build folder
    $partialDir = Get-Variable -Name 'buildDir' -ValueOnly -Scope 1 -EA SilentlyContinue
    if ($partialDir -and (Test-Path $partialDir) -and -not $Silent) {
        Write-Host "`n  Partial build folder: $partialDir" -ForegroundColor Yellow
        $cleanup = Read-Host '  Delete partial build? (Y/n)'
        if (-not $cleanup -or $cleanup -in 'Y', 'y', 'yes') {
            Invoke-Cleanup
            Remove-Item $partialDir -Recurse -Force -EA SilentlyContinue
            Write-Log "Removed partial build: $partialDir"
            Write-Host '  Cleaned up.' -ForegroundColor Green
        }
    }
    Write-Host ''
    exit 1
}
finally {
    Invoke-Cleanup
}
