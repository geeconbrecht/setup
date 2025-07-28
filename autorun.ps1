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

    $packages = @(
        "greenshot", "googlechrome", "adobereader", 
        "eid-belgium", "eid-belgium-viewer", "winrar",
        "javaruntime", "firefox", "hpimageassistant"
    )
    choco install vlc -y --params "/S /L=1033" --force
    choco install hpsupportassistant -y --params "/S /L=1033" --force



    foreach ($package in $packages) {
        try {
            Write-Output "Installing $package..."
            choco install $package -y --force --ignore-checksums
            Write-Output "$package installed successfully."
        } catch {
            Write-Output "Error installing package: $_"
        }
    }
}
Test-Configure-Chocolatey

function Run-HPIA-InstallCoreOnly {
    $hpiaPath = "C:\ProgramData\chocolatey\lib\hpimageassistant\tools\HPImageAssistant.exe"
    $reportFolder = "C:\HPIA\Reports"

    if (!(Test-Path $reportFolder)) {
        New-Item -Path $reportFolder -ItemType Directory -Force | Out-Null
    }

    if (Test-Path $hpiaPath) {
        Write-Output "Running HPIA to install BIOS, Drivers, Firmware, Security, and Diagnostics only..."
        Start-Process -FilePath $hpiaPath `
            -ArgumentList "/Operation:Analyze /Action:Install /Category:BIOS,Drivers,Firmware,Accessories /Silent" `
            -Wait
    } else {
        Write-Output "HPImageAssistant.exe not found at $hpiaPath"
    }
}
Run-HPIA-InstallCoreOnly

# Variables
$odtUrl = "https://download.microsoft.com/download/2/d/c/2dc90f4a-3c92-4d31-bb8f-d2b0f11e430d/officedeploymenttool_16130.20306.20248.0.exe"
$odtExe = "$env:TEMP\ODTSetup.exe"
$odtExtractPath = "C:\OfficeDeploymentTool"
$configFile = "$odtExtractPath\configuration-Office365-x64.xml"  # Adjust path if your Office.xml is elsewhere

# Download Office Deployment Tool
Write-Host "Downloading Office Deployment Tool..."
Invoke-WebRequest -Uri $odtUrl -OutFile $odtExe

# Create extract directory
If (!(Test-Path $odtExtractPath)) {
    New-Item -Path $odtExtractPath -ItemType Directory | Out-Null
}

# Extract the Deployment Tool
Write-Host "Extracting Deployment Tool..."
Start-Process -FilePath $odtExe -ArgumentList "/quiet /extract:$odtExtractPath" -Wait

# Copy Office.xml to the directory (or ensure it’s already there)
If (!(Test-Path $configFile)) {
    Write-Host "ERROR: Office.xml not found at $configFile"
    Exit 1
}

# Run the download step
Write-Host "Downloading Office365..."
Start-Process -FilePath "$odtExtractPath\setup.exe" -ArgumentList "/download configuration-Office365-x64.xml" -WorkingDirectory $odtExtractPath -Wait

# Run the install step
Write-Host "Installing Office365..."
Start-Process -FilePath "$odtExtractPath\setup.exe" -ArgumentList "/configure configuration-Office365-x64.xml" -WorkingDirectory $odtExtractPath -Wait

Write-Host "Office365 installation complete!"


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


# pictogrammen desktop
function Show-DesktopIcons {
    $desktopIcons = @{
        "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" = 0  # Deze computer
        "{645FF040-5081-101B-9F08-00AA002F954E}" = 0  # Prullenbak
        "{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}" = 0  # Netwerk
        "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" = 0  # Gebruikersbestanden
        "{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}" = 0  # Configuratiescherm
    }

    # Registry-pad voor bureaubladpictogrammen
    $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel"

    # Instellen van de zichtbaarheid van pictogrammen
    foreach ($guid in $desktopIcons.Keys) {
        Set-ItemProperty -Path $regPath -Name $guid -Value $desktopIcons[$guid] -Force
    }

    # Bureaublad vernieuwen
    rundll32.exe shell32.dll,Control_RunDLL desk.cpl,0
    Write-Output "Bureaubladpictogrammen bijgewerkt."
}

# Voer de functie uit
Show-DesktopIcons

function Set-NoshowDesktopAndTaskbar {
    # Verwijderen van VLC en Edge pictogrammen van het bureaublad
    $desktopPath = [Environment]::GetFolderPath("Desktop")
    $vlcShortcut = Join-Path -Path $desktopPath -ChildPath "VLC media player.lnk"
    $edgeShortcut = Join-Path -Path $desktopPath -ChildPath "Microsoft Edge.lnk"

    if (Test-Path $vlcShortcut) {
        Remove-Item -Path $vlcShortcut -Force
        Write-Output "VLC shortcut removed from desktop."
    }

    if (Test-Path $edgeShortcut) {
        Remove-Item -Path $edgeShortcut -Force
        Write-Output "Edge shortcut removed from desktop."
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


# Functie om de PSWindowsUpdate-module te installeren
function Install-PSWindowsUpdateModule {
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
Install-PSWindowsUpdateModule

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



#chocolatley auto update op pc zetten
New-Item -ItemType Directory -Path "C:\ProgramData\Scripts" -Force
Copy-Item -Path "Update-ChocolateyPack.ps1" -Destination "C:\ProgramData\Scripts" -Force
#taak planner toevoegen om 1 keer per week uit te voeren
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File 'C:\ProgramData\Scripts\Update-ChocolateyPack.ps1'"
$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 7:00AM
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

Register-ScheduledTask -Action $action -Trigger $trigger -Settings $settings -TaskName "UpdateChocolateyPackages" -Description "Update alle chocolatley packages 1 maal per week" -Force




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


# Functie om de computer opnieuw op te starten
function Restart-Computer {
    try {
        Restart-Computer -Force
    } catch {
        Write-Output "Error restarting computer: $_"
    }
}
Restart-Computer
