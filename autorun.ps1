# ===========================================
#  Elevatie naar Administrator (robuust, 1 regel typecast)
# ===========================================
function Confirm-Administrator {
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {

        $exe  = (Get-Process -Id $PID).Path
        $args = @('-NoProfile','-ExecutionPolicy','Bypass','-File', "`"$PSCommandPath`"") +
                ($MyInvocation.UnboundArguments)

        Start-Process -FilePath $exe -Verb RunAs -ArgumentList ($args -join ' ')
        exit
    }
}
Confirm-Administrator

# ===========================================
#  Lokale admin gebruiker (let op: security)
# ===========================================
function Add-LocalAdminUser {
    param (
        [string]$Username = "Admin",
        [string]$Password = "L0c@l"
    )
    $SecurePassword = $Password | ConvertTo-SecureString -AsPlainText -Force
    $userExists = Get-LocalUser -Name $Username -ErrorAction SilentlyContinue

    if ($userExists) {
        Write-Output "User '$Username' already exists."
    } else {
        try {
            New-LocalUser -Name $Username -Password $SecurePassword -FullName "Admin" -Description "Local Admin User" -PasswordNeverExpires -UserMayNotChangePassword
            Add-LocalGroupMember -Group "Administrators" -Member $Username
            Write-Output "User '$Username' has been created and added to the Administrators group."
        } catch {
            Write-Output "Error creating user: $_"
        }
    }
}
Add-LocalAdminUser -Username "Admin" -Password "L0c@l"

# ===========================================
#  HP-detectie (CIM i.p.v. verouderde WMI)
# ===========================================
function Is-HPDevice {
    $manufacturer = (Get-CimInstance -ClassName Win32_ComputerSystem).Manufacturer
    return $manufacturer -like "*Hewlett-Packard*" -or $manufacturer -like "*HP*"
}

# ===========================================
#  Registry instellingen
# ===========================================
function Set-RegistryValues {
    $registryChanges = @{
        "HKLM:\Software\Policies\Microsoft\Dsh" = @{ "AllowNewsAndInterests" = 0 }
        "HKLM:\Software\Policies\Microsoft\Windows\Explorer" = @{
            "ShowTaskViewButton" = 0
            "SearchboxTaskbarMode" = 1
        }
    }

    foreach ($path in $registryChanges.Keys) {
        if (-Not (Test-Path $path)) {
            New-Item -Path $path -Force | Out-Null
        }
        foreach ($name in $registryChanges[$path].Keys) {
            Set-ItemProperty -Path $path -Name $name -Value $registryChanges[$path][$name]
        }
    }
    gpupdate /force | Out-Null
    Write-Output "Registry values updated."
}
Set-RegistryValues

# ===========================================
#  ScreenConnect (ConnectWise Control)
# ===========================================
$url    = "https://rmmeu-geeconitsolutions.screenconnect.com/Bin/ScreenConnect.ClientSetup.exe?e=Access&y=Guest"
$output = "$env:TEMP\ScreenConnect.ClientSetup.exe"
Invoke-WebRequest -Uri $url -OutFile $output
Start-Process -FilePath $output -ArgumentList "/silent" -Wait

# ===========================================
#  Chocolatey + pakketten (zonder --ignore-checksums)
# ===========================================
function Test-Configure-Chocolatey {
    $chocoInstalled = Get-Command choco -ErrorAction SilentlyContinue

    if (-not $chocoInstalled) {
        Write-Output "Chocolatey is not installed. Installing..."
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
            Write-Output "Chocolatey installed successfully."
        } catch {
            Write-Output "Error installing Chocolatey: $_"
            return
        }
    } else {
        Write-Output "Chocolatey is already installed."
    }

    Start-Sleep -Seconds 5

    $packages = @(
        "greenshot", "googlechrome", "adobereader",
        "eid-belgium", "eid-belgium-viewer", "winrar",
        "javaruntime", "firefox"
    )

    foreach ($package in $packages) {
        try {
            Write-Output "Installing $package..."
            choco install $package -y --force
            Write-Output "$package installed successfully."
        } catch {
            Write-Output "Error installing $($package): $_"
        }
    }

    if (Is-HPDevice) {
        Write-Output "HP system detected. Installing HP-specific tools..."
        try {
            choco install hpimageassistant -y --force
            choco install hpsupportassistant -y --params "/S /L=1033" --force
            Write-Output "HP packages installed successfully."
        } catch {
            Write-Output "Error installing HP packages: $_"
        }
    } else {
        Write-Output "Non-HP system detected. Skipping HP-specific installations."
    }
}
Test-Configure-Chocolatey

# ===========================================
#  Office Deployment Tool + externe XML
# ===========================================
$xmlUrl         = "https://geecon.be/voorbereiding/Configuratie.xml"
$odtUrl         = "https://download.microsoft.com/download/6c1eeb25-cf8b-41d9-8d0d-cc1dbc032140/officedeploymenttool_18925-20138.exe"
$odtExe         = Join-Path $env:TEMP "ODTSetup.exe"
$odtExtractPath = "C:\OfficeDeploymentTool"
$configFile     = Join-Path $odtExtractPath "Configuratie.xml"

try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}
Write-Host "Downloading Office Deployment Tool..." -ForegroundColor Cyan
Invoke-WebRequest -Uri $odtUrl -OutFile $odtExe

if (!(Test-Path $odtExtractPath)) { New-Item -Path $odtExtractPath -ItemType Directory | Out-Null }

Write-Host "Extracting Office Deployment Tool to $odtExtractPath ..." -ForegroundColor Cyan
Start-Process -FilePath $odtExe -ArgumentList "/quiet /extract:`"$odtExtractPath`"" -Wait

Write-Host "Downloading configuration XML from $xmlUrl ..." -ForegroundColor Cyan
Invoke-WebRequest -Uri $xmlUrl -OutFile $configFile

if (!(Test-Path $configFile)) {
    Write-Host "ERROR: Failed to download configuration XML to $configFile" -ForegroundColor Red
    exit 1
}

$setupExe = Join-Path $odtExtractPath "setup.exe"
if (!(Test-Path $setupExe)) {
    Write-Host "ERROR: setup.exe not found in $odtExtractPath" -ForegroundColor Red
    exit 1
}

Write-Host "ODT: Downloading Office files (this can take a while)..." -ForegroundColor Cyan
Start-Process -FilePath $setupExe -ArgumentList "/download `"$configFile`"" -WorkingDirectory $odtExtractPath -Wait

Write-Host "ODT: Installing Office with your configuration..." -ForegroundColor Cyan
Start-Process -FilePath $setupExe -ArgumentList "/configure `"$configFile`"" -WorkingDirectory $odtExtractPath -Wait

Write-Host "✔ Office installation complete." -ForegroundColor Green

# ===========================================
#  Systeeminstellingen
# ===========================================
function Set-SystemSettings {
    try {
        Set-WinUserLanguageList -LanguageList "nl-BE" -Force
        Set-TimeZone -Id "W. Europe Standard Time"
        New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAl" -Value 0 -Force
        Write-Output "System settings updated."
    } catch {
        Write-Output "Error updating settings: $_"
    }
}
Set-SystemSettings

# ===========================================
#  Desktop/taakbalk opschonen
# ===========================================
function Set-NoshowDesktopAndTaskbar {
    # Verwijderen van desktop-snelkoppelingen
    $desktopPath = [Environment]::GetFolderPath("Desktop")
    $shortcuts = @(
        "VLC media player.lnk",
        "Microsoft Edge.lnk",
        "TeamViewer.lnk",
        "HP Support Assistant.lnk"
    )
    foreach ($shortcut in $shortcuts) {
        $shortcutPath = Join-Path -Path $desktopPath -ChildPath $shortcut
        if (Test-Path $shortcutPath) {
            Remove-Item -Path $shortcutPath -Force
            Write-Output "$shortcut removed from desktop."
        }
    }

    # Taakbalk unpin (standaard cmdlet bestaat niet --> uitgezet)
    # Get-StartApps | Where-Object { $_.AppID -like "*Microsoft.Edge*" } | ForEach-Object { Unpin-AppFromTaskbar -AppId $_.AppID }

    # Zoekveld als icoon
    try {
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Value 1
        Write-Output "Search bar configured to icon-only."
    } catch {
        Write-Output "Error configuring search bar: $_"
    }
}
Set-NoshowDesktopAndTaskbar

# ===========================================
#  IPv6 uitschakelen (alle actieve adapters)
# ===========================================
function Disable-IPv6 {
    try {
        $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
        foreach ($adapter in $adapters) {
            Disable-NetAdapterBinding -Name $adapter.Name -ComponentID ms_tcpip6 -Confirm:$false
        }
        Write-Output "IPv6 disabled on all active network adapters."
    } catch {
        Write-Output "Error disabling IPv6: $_"
    }
}
Disable-IPv6

# ===========================================
#  Greenshot configuratie vervangen
# ===========================================
$scriptDirectory = Split-Path -Path $PSCommandPath
$appDataPath     = [Environment]::GetFolderPath("ApplicationData")
$greenshotPath   = Join-Path -Path $appDataPath -ChildPath "Greenshot"

if (Test-Path -Path $greenshotPath) {
    try {
        $sourceConfigPath = Join-Path -Path $scriptDirectory -ChildPath "Greenshot2.ini"
        $oldConfigPath    = Join-Path -Path $greenshotPath -ChildPath "Greenshot.ini"
        $newConfigPath    = Join-Path -Path $greenshotPath -ChildPath "Greenshot2.ini"

        if (-Not (Test-Path -Path $sourceConfigPath)) {
            Write-Output "Greenshot2.ini not found in script directory: $scriptDirectory"
            exit 1
        }

        Copy-Item -Path $sourceConfigPath -Destination $greenshotPath -Force
        Write-Output "Greenshot2.ini copied to Greenshot folder."

        if (Test-Path -Path $oldConfigPath) {
            Remove-Item -Path $oldConfigPath -Force
            Write-Output "Old Greenshot.ini removed."
        }

        Rename-Item -Path $newConfigPath -NewName "Greenshot.ini"
        Write-Output "Greenshot2.ini renamed to Greenshot.ini."
    } catch {
        Write-Output "Error processing Greenshot configuration: $_"
    }
} else {
    Write-Output "Greenshot folder does not exist in AppData."
}

# ===========================================
#  Windows Update module + updates
# ===========================================
function Install-PSWindowsUpdateModule {
    if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
        Write-Output "Installing NuGet provider silently..."
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
    }

    if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
        try {
            Install-Module -Name PSWindowsUpdate -Force -Scope CurrentUser
            Write-Output "PSWindowsUpdate module installed."
        } catch {
            Write-Output "Error installing PSWindowsUpdate: $_"
        }
    } else {
        Write-Output "PSWindowsUpdate module already installed."
    }
}
function Test-AndInstallUpdates {
    try {
        Import-Module PSWindowsUpdate
        $updates = Get-WindowsUpdate -AcceptAll -Verbose
        if ($updates) {
            Install-WindowsUpdate -AcceptAll -Verbose
        } else {
            Write-Output "No updates available."
        }
    } catch {
        Write-Output "Error updating: $_"
    }
}
Install-PSWindowsUpdateModule
Test-AndInstallUpdates

# ===========================================
#  Opruimen
# ===========================================
function Clear-System {
    try {
        $TempPaths = @("$env:Temp", "C:\Windows\Temp")
        foreach ($path in $TempPaths) {
            if (Test-Path $path) {
                Get-ChildItem -Path $path -Recurse | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
            }
        }
        Clear-RecycleBin -Force -ErrorAction SilentlyContinue
        Write-Output "System cleanup completed."
    } catch {
        Write-Output "Error during cleanup: $_"
    }
}
Clear-System

# ===========================================
#  Reboot & hervatten (RunOnce → geen quote-gedoe)
# ===========================================
$stateFile = "C:\Temp\PostInstall_Rebooted.txt"
$thisScript = $PSCommandPath

if (Test-Path $stateFile) {
    Write-Output "Systeem is opnieuw opgestart. Voer post-reboot taken uit..."

    Remove-Item $stateFile -Force -ErrorAction SilentlyContinue

    Test-AndInstallUpdates

    if (Is-HPDevice) {
        # Run-HPIA-InstallCoreOnly   # <-- definieer deze functie of laat uit
    }

    Write-Output "Post-reboot taken voltooid."
    exit
}
else {
    Write-Output "Voorbereiden op herstart..."

    if (!(Test-Path "C:\Temp")) {
        New-Item -Path "C:\Temp" -ItemType Directory | Out-Null
    }

    Set-Content -Path $stateFile -Value "pending"

    # RunOnce vermijdt alle ingewikkelde quoting
    $escaped = "`"$PSCommandPath`""
    New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" `
      -Name "ResumeAfterReboot" -Value "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File $escaped" -Force | Out-Null

    Restart-Computer -Force
}
