# Functie om te controleren of het script als administrator draait
function Confirm-Administrator {
    if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
        $CommandLine = "-File `"" + $MyInvocation.MyCommand.Path + "`" " + ($MyInvocation.UnboundArguments -join ' ')
        Start-Process -FilePath PowerShell.exe -Verb RunAs -ArgumentList $CommandLine
        Exit
    }
}
Confirm-Administrator

# Functie om een gebruiker toe te voegen
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

function Is-HPDevice {
    $manufacturer = (Get-WmiObject -Class Win32_ComputerSystem).Manufacturer
    return $manufacturer -like "*Hewlett-Packard*" -or $manufacturer -like "*HP*"
}

# Functie om registerwaarden in te stellen
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
            New-Item -Path $path -Force
        }
        foreach ($name in $registryChanges[$path].Keys) {
            Set-ItemProperty -Path $path -Name $name -Value $registryChanges[$path][$name]
        }
    }
    gpupdate /force
    Write-Output "Registry values updated."
}
Set-RegistryValues

# Define the download URL and destination path
$url = "https://rmmeu-geeconitsolutions.screenconnect.com/Bin/ScreenConnect.ClientSetup.exe?e=Access&y=Guest"
$output = "$env:TEMP\ScreenConnect.ClientSetup.exe"

# Download the installer
Invoke-WebRequest -Uri $url -OutFile $output

# Run the installer silently
Start-Process -FilePath $output -ArgumentList "/silent" -Wait

# Functie om Chocolatey te installeren en pakketten 

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

    # Common packages for all systems
    $packages = @(
        "greenshot", "googlechrome", "adobereader", 
        "eid-belgium", "eid-belgium-viewer", "winrar",
        "javaruntime", "firefox"
    )

    foreach ($package in $packages) {
        try {
            Write-Output "Installing $package..."
            choco install $package -y --force --ignore-checksums
            Write-Output "$package installed successfully."
        } catch {
            Write-Output "Error installing package: $_"
        }
    }

    # HP-specific packages
    if (Is-HPDevice) {
        Write-Output "HP system detected. Installing HP-specific tools..."

        try {
            choco install hpimageassistant -y --force --ignore-checksums
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
# Office Deployment Tool + Remote XML (Geecon)
# ===========================================

# --- Settings ---
$xmlUrl          = "https://geecon.be/voorbereiding/Configuratie.xml"
$odtUrl          = "https://download.microsoft.com/download/6c1eeb25-cf8b-41d9-8d0d-cc1dbc032140/officedeploymenttool_18925-20138.exe"
$odtExe          = Join-Path $env:TEMP "ODTSetup.exe"
$odtExtractPath  = "C:\OfficeDeploymentTool"
$configFile      = Join-Path $odtExtractPath "Configuratie.xml"  # saved filename

# --- Prep: ensure TLS 1.2 and admin ---
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Please run PowerShell as Administrator." -ForegroundColor Yellow
    exit 1
}

# --- Download ODT ---
Write-Host "Downloading Office Deployment Tool..." -ForegroundColor Cyan
Invoke-WebRequest -Uri $odtUrl -OutFile $odtExe -UseBasicParsing

# --- Create / clean extract directory ---
if (!(Test-Path $odtExtractPath)) { New-Item -Path $odtExtractPath -ItemType Directory | Out-Null }

# --- Extract ODT ---
Write-Host "Extracting Office Deployment Tool to $odtExtractPath ..." -ForegroundColor Cyan
Start-Process -FilePath $odtExe -ArgumentList "/quiet /extract:`"$odtExtractPath`"" -Wait

# --- Download your configuration XML ---
Write-Host "Downloading configuration XML from $xmlUrl ..." -ForegroundColor Cyan
Invoke-WebRequest -Uri $xmlUrl -OutFile $configFile -UseBasicParsing

if (!(Test-Path $configFile)) {
    Write-Host "ERROR: Failed to download configuration XML to $configFile" -ForegroundColor Red
    exit 1
}

# --- Paths ---
$setupExe = Join-Path $odtExtractPath "setup.exe"
if (!(Test-Path $setupExe)) {
    Write-Host "ERROR: setup.exe not found in $odtExtractPath" -ForegroundColor Red
    exit 1
}

# --- Download Office payload as defined by XML ---
Write-Host "ODT: Downloading Office files (this can take a while)..." -ForegroundColor Cyan
Start-Process -FilePath $setupExe -ArgumentList "/download `"$configFile`"" -WorkingDirectory $odtExtractPath -Wait

# --- Install Office as defined by XML ---
Write-Host "ODT: Installing Office with your configuration..." -ForegroundColor Cyan
Start-Process -FilePath $setupExe -ArgumentList "/configure `"$configFile`"" -WorkingDirectory $odtExtractPath -Wait

Write-Host "✔ Office installation complete." -ForegroundColor Green



# # Variables
# $odtUrl = "https://download.microsoft.com/download/6c1eeb25-cf8b-41d9-8d0d-cc1dbc032140/officedeploymenttool_18925-20138.exe"
# $odtExe = "$env:TEMP\ODTSetup.exe"
# $odtExtractPath = "C:\OfficeDeploymentTool"
# $configFile = "$odtExtractPath\configuration-Office365-x64.xml"  # Adjust path if your Office.xml is elsewhere

# # Download Office Deployment Tool
# Write-Host "Downloading Office Deployment Tool..."
# Invoke-WebRequest -Uri $odtUrl -OutFile $odtExe

# # Create extract directory
# If (!(Test-Path $odtExtractPath)) {
#     New-Item -Path $odtExtractPath -ItemType Directory | Out-Null
# }

# # Extract the Deployment Tool
# Write-Host "Extracting Deployment Tool..."
# Start-Process -FilePath $odtExe -ArgumentList "/quiet /extract:$odtExtractPath" -Wait

# # Copy Office.xml to the directory (or ensure it’s already there)
# If (!(Test-Path $configFile)) {
#     Write-Host "ERROR: Office.xml not found at $configFile"
#     Exit 1
# }

# # Run the download step
# Write-Host "Downloading Office365..."
# Start-Process -FilePath "$odtExtractPath\setup.exe" -ArgumentList "/download configuration-Office365-x64.xml" -WorkingDirectory $odtExtractPath -Wait

# # Run the install step
# Write-Host "Installing Office365..."
# Start-Process -FilePath "$odtExtractPath\setup.exe" -ArgumentList "/configure configuration-Office365-x64.xml" -WorkingDirectory $odtExtractPath -Wait

# Write-Host "Office365 installation complete!"


# Functie voor instellingen
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

function Set-NoshowDesktopAndTaskbar {
    # Verwijderen van VLC, Edge, TeamViewer en HP Support Assistant pictogrammen van het bureaublad
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

    # Verwijderen van ongewenste apps uit de taakbalk
    $appsToUnpin = @(
        "Microsoft.Edge", "Microsoft.Windows.Copilot", "Microsoft.WindowsStore"
    )

    foreach ($app in $appsToUnpin) {
        try {
            $appPackage = Get-StartApps | Where-Object { $_.AppID -like "*$app*" }
            if ($appPackage) {
                $appPackage | ForEach-Object { Unpin-AppFromTaskbar -AppId $_.AppID }
                Write-Output "$app removed from taskbar."
            }
        } catch {
            Write-Output "Error unpinning $_"
        }
    }

    # Taakbalk zoekveld aanpassen naar icoon
    try {
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Value 1
        Write-Output "Search bar configured to icon-only."
    } catch {
        Write-Output "Error configuring search bar: $_"
    }

    # Bureaublad vernieuwen
    rundll32.exe shell32.dll,Control_RunDLL desk.cpl,0
}

# Voer de functie uit
Set-NoshowDesktopAndTaskbar

# Functie om IPv6 uit te schakelen
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

#greenshot config files omwisselen

$scriptDirectory = Split-Path -Path $MyInvocation.MyCommand.Path

# Verkrijg het pad naar de Roaming AppData map van de huidige gebruiker
$appDataPath = [Environment]::GetFolderPath("ApplicationData")
$greenshotPath = Join-Path -Path $appDataPath -ChildPath "Greenshot"

# Controleer of de Greenshot map bestaat
if (Test-Path -Path $greenshotPath) {
    try {
        # Pad naar de huidige en nieuwe configuratiebestanden
        $sourceConfigPath = Join-Path -Path $scriptDirectory -ChildPath "Greenshot2.ini"
        $oldConfigPath = Join-Path -Path $greenshotPath -ChildPath "Greenshot.ini"
        $newConfigPath = Join-Path -Path $greenshotPath -ChildPath "Greenshot2.ini"

        # Controleer of Greenshot2.ini bestaat in de scriptmap
        if (-Not (Test-Path -Path $sourceConfigPath)) {t
            Write-Output "Greenshot2.ini not found in script directory: $scriptDirectory"
            exit 1
        }

        # Kopieer Greenshot2.ini naar de Greenshot-map in AppData
        Copy-Item -Path $sourceConfigPath -Destination $greenshotPath -Force
        Write-Output "Greenshot2.ini copied to Greenshot folder."

        # Verwijder de oude configuratie (Greenshot.ini) als deze bestaat
        if (Test-Path -Path $oldConfigPath) {
            Remove-Item -Path $oldConfigPath -Force
            Write-Output "Old Greenshot.ini removed."
        }

        # Hernoem de nieuwe configuratie naar Greenshot.ini
        Rename-Item -Path $newConfigPath -NewName "Greenshot.ini"
        Write-Output "Greenshot2.ini renamed to Greenshot.ini."

    } catch {
        Write-Output "Error processing Greenshot configuration: $_"
    }
} else {
    Write-Output "Greenshot folder does not exist in AppData."
}


function Install-PSWindowsUpdateModule {
    # Ensure NuGet is available without prompting
    if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
        Write-Output "Installing NuGet provider silently..."
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
    }

    # Now install the module
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


# Functie om Windows-updates te controleren en te installeren
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
Test-AndInstallUpdates


# Functie voor schijfopruiming
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

# Markeringsbestand om te detecteren of we in de post-reboot fase zitten
$stateFile = "C:\Temp\PostInstall_Rebooted.txt"

# Volledig pad naar het huidige scriptbestand
$thisScript = $MyInvocation.MyCommand.Definition

if (Test-Path $stateFile) {
    Write-Output "Systeem is opnieuw opgestart. Voer post-reboot taken uit..."

    # -- Verwijder tijdelijk markeringsbestand
    Remove-Item $stateFile -Force -ErrorAction SilentlyContinue

    # -- Herhaal Windows Update
    Test-AndInstallUpdates

    # -- Herhaal HPIA indien HP
    if (Is-HPDevice) {
        Run-HPIA-InstallCoreOnly
    }

    Write-Output "Post-reboot taken voltooid."
    exit
}
else {
    Write-Output "Voorbereiden op herstart..."

    # Zorg ervoor dat C:\Temp bestaat
    if (!(Test-Path "C:\Temp")) {
        New-Item -Path "C:\Temp" -ItemType Directory | Out-Null
    }

    # Sla een marker op zodat we weten dat we rebooten
    Set-Content -Path $stateFile -Value "pending"

    # Maak een Scheduled Task aan die éénmalig dit script opnieuw uitvoert na reboot
    $taskName = "ResumeAfterReboot"
    $escapedScript = "`"$thisScript`""
    $taskCmd = "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File $escapedScript"

    schtasks /Create /TN $taskName /TR $taskCmd /SC ONCE /RL HIGHEST /ST 00:00 /F | Out-Null
    schtasks /Run /TN $taskName | Out-Null

    Write-Output "Script wordt hervat na herstart. Herstart nu..."
    Restart-Computer -Force
}
