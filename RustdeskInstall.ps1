<#
  .SYNOPSIS
  Install and configure Rustdesk Client

  .DESCRIPTION
  Deployment script to deploy the latest Rustdesk (https://rustdesk.com/) client on a windows computer. Use described parameters to configure the client.

  .PARAMETER rdServer
  The IP address or FQDN of the RustDesk ID Server and Relay Server

  .PARAMETER rdKey
  Specifies the key of ID/Relay Server

  .PARAMETER pwLength
  Specifies the length of the password to connect to the RustDesk client

  .PARAMETER enableAudio
  EnableAudio in RustDesk client.

  .EXAMPLE
  PS> .\RustdeskInstall.ps1 -rdServer "somehost.example.tld" -rdKey "KeyFromServer="
    Install RustDesk Client by defining a different ID/Relay server and corresponding key

  .EXAMPLE
  PS> .\RustdeskInstall.ps1 -rdServer "somehost.example.tld" -rdKey "KeyFromServer=" -pwLength 24
    Optionally define length for client password

  .EXAMPLE
  PS> .\RustdeskInstall.ps1 -rdServer "somehost.example.tld" -rdKey "KeyFromServer=" -enableAudio 0
    Optionally disable audio

  .EXAMPLE
  PS> .\RustdeskInstall.ps1 -toNextcloudPassword 1 -ncBaseUrl "https://some.nextcloud.url/index.php/apps/passwords" -ncUsername "user.name" -ncToken "12345-abcde-67890" -ncFolder "NextcloudPasswordFolderUUID"
#>

param(
  [string]$rdServer = "rs-ny.rustdesk.com",
  [string]$rdKey = $null,
  [int]$pwLength = 8,
  [bool]$enableAudio = $True,
  [bool]$toNextcloudPassword = $False,
  [string]$ncBaseUrl,
  [string]$ncUsername,
  [string]$ncToken,
  [string]$ncFolder
)

if ($rdServer -ne "rs-ny.rustdesk.com") {
  if (!($rdKey)) {
    Write-Host("Required parameter '-rdKey' was not set! Exiting!")
    exit 1
  }
}

if ($toNextcloudPassword) {
  if (!($ncBaseUrl)) {
    Write-Host("Required parameter '-ncBaseUrl' was not set! Exiting!")
    exit 1
  }
  if (!($ncUsername)) {
    Write-Host("Required parameter '-ncUsername' was not set! Exiting!")
    exit 1
  }
  if (!($ncToken)) {
    Write-Host("Required parameter '-ncToken' was not set! Exiting!")
    exit 1
  }
  if (!($ncFolder)) {
    Write-Host("Require parameter '-ncFolder' was not set! Exiting!")
    exit 1
  }
}

$ErrorActionPreference = 'silentlycontinue'
#Run as administrator and stays in the current directory
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  if ([int](Get-CimInstance -Class Win32_OperatingSystem | Select-Object -ExpandProperty BuildNumber) -ge 6000) {
    Start-Process PowerShell -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -Command `"cd '$pwd'; & '$PSCommandPath';`"";
    exit;
  }
}

$rustdeskURL = 'https://github.com/rustdesk/rustdesk/releases/latest'
$rustdeskReg = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\RustDesk\'

function PreqRustdeskUpstreamVersion([string]$rustdeskURL) {
  #Get latest upstream version number
  $upstream_rustdesk_version = [System.Net.WebRequest]::Create($rustdeskURL).GetResponse().ResponseUri.OriginalString.split('/')[-1].Trim('v')
  return $upstream_rustdesk_version
}

function PreqRustdeskInstalledVersion([string]$rustdeskReg) {
  #Check if Rustdesk is already installed and get version number
  if (Test-Path $rustdeskReg) {
    $installed_rustdesk_version = ((Get-ItemProperty $rustdeskReg).Version)
    return $installed_rustdesk_version
  } else {
    return 0
  }
}

function Prerequisites([string]$VersionInstalled, [string]$VersionUpstream) {
  if (!(Test-Path $env:Temp)) {
    New-Item -ItemType Directory -Force -Path $env:Temp | Out-Null
  }

  if (!([System.Version]$VersionUpstream -gt [System.Version]$VersionInstalled)) {
    Write-Output("Rustdesk version $VersionUpstream is already installed!")
    exit
  }
}

function DownloadRustdesk([string]$version) {
  Write-Output("Download Rustdesk client https://github.com/rustdesk/rustdesk/releases/download/$version/rustdesk-$version-x86_64.exe")
  Invoke-WebRequest "https://github.com/rustdesk/rustdesk/releases/download/$version/rustdesk-$version-x86_64.exe" -Outfile "$env:Temp\rustdesk.exe"
}

function InstallRustdesk {
  Write-Output("Silently install Rustdesk client")
  cmd /c ""$env:Temp\rustdesk.exe --silent-install""
  # Workaround: --silent-install does not quit process
  Start-Sleep 30
  Stop-Process -Name Rustdesk -Force | Out-Null
}

function StartRustdesk([string]$serviceName) {
  Write-Output("Start Rustdesk service")
  Start-Service $serviceName
}

function StopRustdesk([string]$serviceName) {
  Write-Output("Stop Rustdesk service")
  $serviceState = Get-Service -Name $serviceName -ErrorAction SilentlyContinue

  if ($serviceState -eq $null) {
    Start-Sleep -seconds 20
  }

  while ($serviceState.Status -ne 'Running') {
    Start-Service $serviceName
    Start-Sleep -seconds 5
    $serviceState.Refresh()
  }

  Stop-Service $serviceName
  Stop-Process -Name $serviceName -Force | Out-Null
}

function ConfigureRustdesk([string]$rdServer, [string]$rdKey, [bool]$enableAudio, [string]$serviceName) {
  Write-Output("Configure Rustdesk client and service")

  $ipAddress = (Get-NetIPConfiguration | Where-Object {$_.IPv4DefaultGateway -ne $null -and $_.NetAdapter.status -ne "Disconnected"}).IPv4Address.IPAddress

  # RustDesk2.toml
  $rd2Toml = @"
rendezvous_server = '$rdServer'
nat_type = 2
serial = 0

[options]
local-ip-addr = '$ipAddress'
"@

  if ($rdServer -ne "rs-ny.rustdesk.com") {
    $rd2Toml += "`ncustom-rendezvous-server = '$rdServer'"
    $rd2Toml += "`nrelay-server = '$rdServer'"
    $rd2Toml += "`napi-server = 'https://$rdServer'"
    if ($rdKey) {
      $rd2Toml += "`nkey = '$rdKey'"
    }
  }

  if (!($enableAudio)) {
    $rd2Toml += "`nenable-audio = 'N'"
  }

  #Workaround: Copy permanent password settings from:
  #    $env:Appdata\RustDesk\config\RustDesk.toml
  #  to:
  #    $env:WinDir\ServiceProfiles\LocalService\AppData\Roaming\RustDesk\config\RustDesk\RustDesk.toml
  #
  # but not if running as SYSTEM
  #
  if ("$env:AppData" -ne "$env:WinDir\ServiceProfiles\LocalService\AppData\Roaming") {
    if ("$env:AppData" -ne "$env:WinDir\system32\config\systemprofile\AppData\Roaming" ) {
      if (!(Test-Path $env:AppData\RustDesk\config\RustDesk2.toml)) {
        New-Item $env:AppData\RustDesk\config\RustDesk2.toml
      }
      Set-Content $env:AppData\RustDesk\config\RustDesk2.toml $rd2Toml | Out-Null
    }
  }


  if (!(Test-Path $env:WinDir\ServiceProfiles\LocalService\AppData\Roaming\RustDesk\config\RustDesk2.toml)) {
    New-Item $env:WinDir\ServiceProfiles\LocalService\AppData\Roaming\RustDesk\config\RustDesk2.toml
  }
  Set-Content $env:WinDir\ServiceProfiles\LocalService\AppData\Roaming\RustDesk\config\RustDesk2.toml $rd2Toml | Out-Null
}

function SetRustdeskPW([int]$pwLength) {
  $rustdeskPW = (-join ((65..90) + (97..122) | Get-Random -Count $pwLength | % {[char]$_}))
  if ($env:ProgramW6432) {
    cmd /c ""$env:ProgramW6432\Rustdesk\rustdesk.exe --password $rustdeskPW"" | Out-Null
  } else {
    cmd /c ""$env:ProgramFiles\Rustdesk\rustdesk.exe --password $rustdeskPW"" | Out-Null
  }

  #Workaround: Copy permanent password settings from:
  #    $env:Appdata\RustDesk\config\RustDesk.toml 
  #  to:
  #    $env:WinDir\ServiceProfiles\LocalService\AppData\Roaming\RustDesk\config\RustDesk\RustDesk.toml
  #
  # but not if running as SYSTEM
  #
  if ("$env:AppData" -ne "$env:WinDir\ServiceProfiles\LocalService\AppData\Roaming") {
    if ("$env:AppData" -ne "$env:WinDir\system32\config\systemprofile\AppData\Roaming" ) {
      Copy-Item -Path "$env:Appdata\RustDesk\config\RustDesk.toml" -Destination "$env:WinDir\ServiceProfiles\LocalService\AppData\Roaming\RustDesk\config\RustDesk.toml" -Force
    }
  }

  return $rustdeskPW
}

function GetRustdeskID {
  if ($env:ProgramW6432) {
    $rustdeskID = cmd /c ""$env:ProgramW6432\Rustdesk\rustdesk.exe --get-id""
  } else {
    $rustdeskID = cmd /c ""$env:ProgramFiles\Rustdesk\rustdesk.exe --get-id""
  }
  return $rustdeskID
}

function OutputIDAndPW([string]$rustdeskID, [string]$rustdeskPW) {
  Write-Output("######################################################")
  Write-Output("#                                                    #")
  Write-Output("# CONNECTION PARAMETERS:                             #")
  Write-Output("#                                                    #")
  Write-Output("######################################################")
  Write-Output("")
  Write-Output("  RustDesk-ID:       $rustdeskID")
  Write-Output("  RustDesk-Password: $rustdeskPW")
  Write-Output("")
}

function WriteRustdeskCredsToNextcloudPasswords([string]$ncBaseUrl, [string]$ncUsername, [string]$ncToken, [string]$ncFolder, [string]$rustdeskID, [string]$rustdeskPW) {
  #
  # API documentation can be found here https://git.mdns.eu/nextcloud/passwords/-/wikis/Developers/Index
  #
  $computerName = $env:ComputerName.ToUpper()
  $pair = "$($ncUsername):$($ncToken)"
  $encodedCreds = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($pair))
  $basicAuthValue = "Basic $encodedCreds"
  $Headers = @{"Authorization" = "$basicAuthValue"}

  $openNCPwSession = Invoke-WebRequest -Uri "$ncBaseUrl/api/1.0/session/open" -Headers $Headers -UseBasicParsing -Method Post -SessionVariable Cookie
  $listNCPasswords = Invoke-WebRequest -Uri "$ncBaseUrl/api/1.0/password/list" -Headers $Headers -UseBasicParsing -WebSession $Cookie
  $pwEntries = ConvertFrom-Json($listNCPasswords.Content)

  # Find record by label
  foreach ($pwEntry in $pwEntries) {
    if ($pwEntry.folder -eq "$ncFolder") {
      if ($pwEntry.label -eq $computerName) {
          $pwID = $pwEntry.id
      }
    }
  }

  $rustdeskPWStream = [IO.MemoryStream]::new([byte[]][char[]]$rustdeskPW)
  $rustdeskPWHash = Get-FileHash -InputStream $rustdeskPWStream -Algorithm SHA1
  $rustdeskHash = $rustdeskPWHash.Hash.ToLower()

  if ($pwID -eq $null) {
    #create entry
    $JSON = @{
      "password" = "$rustdeskPW";
      "label" = "$computerName";
      "username" = "$rustdeskID";
      "folder" = "$ncFolder";
      "hash" = "$rustdeskHash";
      "url" = "rustdesk://connection/new/$rustdeskID";
    } | ConvertTo-Json
    $createNCPassword = Invoke-WebRequest -Uri "$ncBaseUrl/api/1.0/password/create" -Headers $Headers -UseBasicParsing -WebSession $Cookie -Body $JSON -ContentType application/json -Method Post
  } else {
    #update entry
    $JSON = @{
      "id" = "$pwID";
      "password" = "$rustdeskPW";
      "label" = "$computerName";
      "username" = "$rustdeskID";
      "folder" = "$ncFolder";
      "hash" = "$rustdeskHash";
      "url" = "rustdesk://connection/new/$rustdeskID";
    } | ConvertTo-Json
    $updateNCPassword = Invoke-WebRequest -Uri "$ncBaseUrl/api/1.0/password/update" -Headers $Headers -UseBasicParsing -WebSession $Cookie -Body $JSON -ContentType application/json -Method Patch
  }
}

# Run all functions
$rdUpstreamVersion = PreqRustdeskUpstreamVersion -rustdeskURL $rustdeskURL
$rdInstalledVersion = PreqRustdeskInstalledVersion -rustdeskReg $rustdeskReg
$serviceName = 'Rustdesk'

Prerequisites -VersionInstalled $rdInstalledVersion -VersionUpstream $rdUpstreamVersion

DownloadRustdesk -version $rdUpstreamVersion

InstallRustdesk

StopRustdesk -serviceName $serviceName

ConfigureRustdesk -rdServer $rdServer -rdKey $rdKey -enableAudio $enableAudio -serviceName $serviceName

$rustdeskPW = SetRustdeskPW -pwLength $pwLength

$rustdeskID = GetRustdeskID

OutputIDAndPW -rustdeskID $rustdeskID -rustdeskPW $rustdeskPW

StartRustdesk -serviceName $serviceName

if ($toNextcloudPassword) {
  Write-Output("Send Rustdesk credentials to Nextcloud Passwords app")
  WriteRustdeskCredsToNextcloudPasswords -ncBaseUrl "$ncBaseUrl" -ncUsername "$ncUsername" -ncToken "$ncToken" -ncFolder "$ncFolder" -rustdeskID "$rustdeskID" -rustdeskPW "$rustdeskPW"
}
