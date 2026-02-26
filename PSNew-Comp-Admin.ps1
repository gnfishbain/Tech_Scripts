<#
Script Description:
This PowerShell script automates several system configuration and setup tasks for Windows systems, including:

- Configuring firewall rules to allow required services.
- Setting the system time zone to Israel Standard Time (IST).
- Enabling Num Lock on startup.
- Configuring system restore with a 4% disk allocation.
- Enabling TeamViewer notifications in the system tray and fix admin right and password.
- Setting default application associations.
- Installing required software: Native and Harmony VPN.
- Adding the logon user to the Remote Desktop Users group.
- Removing desktop and C:\Apps folder shortcut warnings.
- Removing New Outlook and Taskbar Widgets.
- Ensuring proper installation of .NET 8 and VPN (for laptops).

This script is intended for system administrators managing Windows configurations in the Technion environment.

Author: Gal Nahum Fishbain
Date: 26.06.2025 (Last updated)
#>


# Set window size and position
$Host.UI.RawUI.WindowSize = New-Object System.Management.Automation.Host.Size(90, 30) # Width x Height
$Host.UI.RawUI.BufferSize = New-Object System.Management.Automation.Host.Size(90, 300) # Width x BufferHeight
$Host.UI.RawUI.WindowPosition = New-Object System.Management.Automation.Host.Coordinates(10, 10) # Left x Top

$Host.UI.RawUI.BackgroundColor = 'Black'
$Host.UI.RawUI.ForegroundColor = 'Green'
    Clear-Host

# Variables
$TempDir = "C:\temp"
$TimeNow = Get-Date -Format "ddMMyyyy_HHmm"
$LogFile = "$TempDir\NewCompAdmin_$TimeNow.txt"
$ScriptsDir = "\\share.technion.ac.il\pcsupport$\INS\Scripts"

# Create Temp Directory
if (!(Test-Path -Path $TempDir)) {
    New-Item -ItemType Directory -Path $TempDir
}

# Logging
Start-Transcript -Path $LogFile


# Enable Roles in Windows FireWall
Write-Host "=================================================" -ForegroundColor Cyan
Write-Host " Enabling Network Discovery and File Sharing...  " -ForegroundColor White
Write-Host "=================================================" -ForegroundColor Cyan

# Get-NetFirewallRule | Where-Object { $_.Group -eq "Network Discovery" -or $_.Group -eq "File and Printer Sharing" } | Set-NetFirewallRule -Enabled True
netsh advfirewall firewall set rule group="Network Discovery" new enable=Yes
netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=Yes
netsh advfirewall firewall set rule group="Remote Desktop" new enable=Yes
netsh advfirewall firewall set rule group="Windows Remote Management" new enable=yes
netsh advfirewall firewall add rule name="Allow TeamViewer" dir=in action=allow protocol=TCP localport=5938
netsh advfirewall firewall add rule name="Allow TeamViewer UDP" dir=in action=allow protocol=UDP localport=5938


# Set Time Zone
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " Setting Time to Israel Standard Time...  " -ForegroundColor White
Write-Host "========================================" -ForegroundColor Cyan

tzutil /s "Israel Standard Time"
Set-WinSystemLocale -SystemLocale he-IL


Write-Host "`nSystem locale has been updated to Hebrew (Israel)."
Write-Host "A manual restart is required for the changes to take effect."  -ForegroundColor Red

Get-WinSystemLocale


# Function to check the state of Num Lock
Write-Host "=========================" -ForegroundColor Cyan
Write-Host " Set NumLock at startup  " -ForegroundColor White
Write-Host "=========================" -ForegroundColor Cyan
function Get-NumLockState {
    $numLockState = [System.Windows.Forms.Control]::IsKeyLocked([System.Windows.Forms.Keys]::NumLock)
    return $numLockState
}

# Load the necessary assembly for checking the NumLock state
Add-Type -AssemblyName System.Windows.Forms

# Check the NumLock state
$state = Get-NumLockState

# Display the state of Num Lock
if ($state) {
    Write-Output "Num Lock is ON"
} else {
    Write-Output "Turning ON Num Lock"


# Create a VBScript to toggle Num Lock
$VBS = @"
Set WshShell = CreateObject("WScript.Shell")
WshShell.SendKeys("{NUMLOCK}")
"@

# Save the script to a temporary file
$TempFile = "$env:temp\ToggleNumLock.vbs"
Set-Content -Path $TempFile -Value $VBS

# Run the VBScript to toggle Num Lock
cscript.exe //nologo $TempFile

# Clean up the temporary file
Remove-Item -Path $TempFile -Force }

# Enable Num Lock at Startup
Write-Output "."
Write-Output "Enabling Num Lock at startup..." 
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Keyboard Layout" -Name "InitialKeyboardIndicators" -Value 2147483650

# Enable System Protection on C: drive
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " Enabling System Protection on C: drive " -ForegroundColor White
Write-Host "========================================" -ForegroundColor Cyan

Enable-ComputerRestore -Drive "C:\"

# Set maximum disk space usage to 4% (4% of total size in MB)
$TotalSizeGB = (Get-Volume -DriveLetter C).Size / 1GB
$MaxSizeGB = $TotalSizeGB * 0.04
vssadmin resize shadowstorage /on=C: /for=C: /maxsize=${MaxSizeGB}GB

Write-Output "System Protection enabled on C: drive with 4% allocated for recovery."  -ForegroundColor Blue

# Enable local Administrator
net user administrator /active:yes

Write-Host "======================================" -ForegroundColor Cyan
Write-Host "  Enabling Local administartor acount " -ForegroundColor White
Write-Host "======================================" -ForegroundColor Cyan


# TeamViewer: Always Show Icon in Notification Tray
Write-Host "===================================================" -ForegroundColor Cyan
Write-Host " Applying TeamViewer Notification Tray Icon Fix... " -ForegroundColor White
Write-Host "===================================================" -ForegroundColor Cyan

    # Specify the path to search
    $searchPath = "Control Panel\NotifyIconSettings"

    # Specify the value to search in binary data
    $searchValue = "TeamViewer"

    # Specify the key and value to add or update
    $newKey = "IsPromoted"
    $newValue = 1

    # Get all user profiles under HKEY_USERS
    $userProfiles = Get-ChildItem -Path "Registry::HKEY_USERS" -ErrorAction SilentlyContinue

    # Loop through each user profile
    foreach ($userProfile in $userProfiles) {
        $userProfilePath = "Registry::HKEY_USERS\$($userProfile.PSChildName)"
        $registryPath = Join-Path -Path $userProfilePath -ChildPath $searchPath

        # Check if the registry path exists
        if (Test-Path -Path $registryPath -ErrorAction SilentlyContinue) {
            # Get folders with numbers under NotifyIconSettings
            $numberedFolders = Get-ChildItem -Path $registryPath -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^\d+$' }

            # Loop through numbered folders
            foreach ($numberedFolder in $numberedFolders) {
                $folderPath = Join-Path -Path $registryPath -ChildPath $numberedFolder.PSChildName -ErrorAction SilentlyContinue

                # Get the value of ExecutablePath
                $executablePath = Get-ItemPropertyValue -LiteralPath $folderPath -Name "ExecutablePath" -ErrorAction SilentlyContinue

                # Check if the value contains TeamViewer
                if ($executablePath -like "*$searchValue*") {
                    # Check if the IsPromoted key exists
                    if (Test-Path -Path "$folderPath\$newKey") {
                        # Update the value if the key exists
                        Set-ItemProperty -Path $folderPath -Name $newKey -Value $newValue
                        Write-Host "Key updated for user profile: $($userProfile.PSChildName), Folder: $($numberedFolder.PSChildName)"
                    } else {
                        # Add the new key if it doesn't exist
                        New-ItemProperty -Path $folderPath -Name $newKey -Value $newValue -PropertyType DWORD -Force
                        Write-Host "Key added for user profile: $($userProfile.PSChildName), Folder: $($numberedFolder.PSChildName)"
                    }
                }
            }
        }
    }


    Write-Output "."    
    Write-Host "All Finish"

# Enter your action script hereNew-Item -Path "HKLM:\SOFTWARE\TeamViewer" -Force | Out-Null
# Define the registry path
$RegistryPath = "HKLM:\SOFTWARE\TeamViewer"

# Check if the registry path exists
if (-not (Test-Path -Path $RegistryPath)) {
    # Create the registry key if it doesn't exist
    New-Item -Path $RegistryPath -Force | Out-Null
}

# Add or update the properties
New-ItemProperty -Path $RegistryPath -Name "Security_Adminrights" -Value 1 -PropertyType DWORD -Force | Out-Null
New-ItemProperty -Path $RegistryPath -Name "Security_Disableshutdown" -Value 1 -PropertyType DWORD -Force | Out-Null

Write-Output "TeamViewer Registry keys and properties have been set successfully."

#Add Computer to Manage Computers in TeamViewer
#$tvPath = "C:\Program Files\TeamViewer\TeamViewer.exe"
#$assignmentId = "0001CoABChCFbRcgH0wR8KneOOtbNimQEigIACAAAgAJAKTvPmILqwjzErgI9GDg1-z-LEbXeBCX0OYDF3xOMz9JGkCmIyYAXM_7DQ4QS5nhXjWDMalxOMVoe2O-62jpqj7oORpTqmBoW7BUyw6pi8pvS_VmFPzHj4Foa7Pq0Nr5f8vCIAEQ4cO2wQk="
# stop-process -name "Teamv*" -force
# Start-Process -FilePath $tvPath -ArgumentList "unassign", "--id", $assignmentId -Wait -NoNewWindow

#Start-Process -FilePath $tvPath -ArgumentList "assignment", "--id", $assignmentId -Wait -NoNewWindow
# Start-Process -FilePath $tvPath 

# Define TeamViewer registry path (64-bit or 32-bit system)
$regPath = "HKLM:\SOFTWARE\TeamViewer"

# Define the Security_PasswordStrength value (1 = 6 characters)
$passwordStrength = 1

# Stop the TeamViewer service
Write-Output "Stopping TeamViewer service..."
Stop-Service -Name "TeamViewer" -Force -ErrorAction SilentlyContinue

# Set the registry value
Set-ItemProperty -Path $regPath -Name "Security_PasswordStrength" -Value $passwordStrength -Type DWord
Set-ItemProperty -Path $regPath -Name "RandomPasswordEnabled" -Value $passwordStrength -Type DWord
Write-Output "Registry updated successfully."

# Start the TeamViewer service
Write-Output "Starting TeamViewer service..."
Start-Service -Name "TeamViewer" -ErrorAction SilentlyContinue

Write-Output "TeamViewer random password strength set to 8 characters. Verify in TeamViewer GUI."

# Update Default App Associations
Write-Host "==================================" -ForegroundColor Cyan
Write-Host " Update Teamvier managmnet device " -ForegroundColor White
Write-Host "==================================" -ForegroundColor Cyan

Write-Output "System Protection enabled on C: drive with 4% allocated for recovery."



# Update Default App Associations
Write-Host "=================================" -ForegroundColor Cyan
Write-Host " Update Default App Associations " -ForegroundColor White
Write-Host "=================================" -ForegroundColor Cyan

Write-Output "."
Write-Output "Importing Default App Associations..." 

#Create the XML files
# Define the destination path
$destinationPath = "C:\temp"

# Create the directory if it does not exist
if (-not (Test-Path -Path $destinationPath)) {
    New-Item -ItemType Directory -Path $destinationPath | Out-Null
}

# Define the content for defaultassociations.xml
$defaultContent = @'
<?xml version="1.0" encoding="UTF-8"?>
<DefaultAssociations>
  <Association Identifier=".3g2" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Media Player" />
  <Association Identifier=".3gp" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Media Player" />
  <Association Identifier=".3gp2" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Media Player" />
  <Association Identifier=".3gpp" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Media Player" />
  <Association Identifier=".aac" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Media Player" />
  <Association Identifier=".ac3" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Media Player" />
  <Association Identifier=".adt" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Media Player" />
  <Association Identifier=".adts" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Media Player" />
  <Association Identifier=".amr" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Media Player" />
  <Association Identifier=".arw" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".asf" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Media Player" />
  <Association Identifier=".avi" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Media Player" />
  <Association Identifier=".bmp" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".cab" ProgId="CABFolder" ApplicationName="Windows Explorer" />
  <Association Identifier=".cr2" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".crw" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".dib" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".divx" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Media Player" />
  <Association Identifier=".dng" ProgId="AppXvvwq6wxamf7qhxd0vn6wm1wwehyxrdd6" ApplicationName="Photos" />
  <Association Identifier=".ec3" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Media Player" />
  <Association Identifier=".emf" ProgId="AppXcesbfs704v2mjbts9dkr42s9vmrhxbkj" ApplicationName="Paint" />
  <Association Identifier=".erf" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".flac" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Media Player" />
  <Association Identifier=".gif" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".heic" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".htm" ProgId="ChromeHTML" ApplicationName="Google Chrome" />
  <Association Identifier=".html" ProgId="ChromeHTML" ApplicationName="Google Chrome" />
  <Association Identifier=".ico" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".inf" ProgId="AppXzwr976v2e060wada4gabrk1x69h2dbwy" ApplicationName="Notepad" />
  <Association Identifier=".ini" ProgId="AppXhk4des8gf2xat3wtyzc5q06ny78jhkqx" ApplicationName="Notepad" />
  <Association Identifier=".jfif" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".jpe" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".jpeg" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".jpg" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".jxr" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".kdc" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".log" ProgId="AppX4ztfk9wxr86nxmzzq47px0nh0e58b8fw" ApplicationName="Notepad" />
  <Association Identifier=".m1v" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Media Player" />
  <Association Identifier=".m2t" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Media Player" />
  <Association Identifier=".m2ts" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Media Player" />
  <Association Identifier=".m2v" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Media Player" />
  <Association Identifier=".m3u" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Media Player" />
  <Association Identifier=".m4a" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Media Player" />
  <Association Identifier=".m4r" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Media Player" />
  <Association Identifier=".m4v" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Media Player" />
  <Association Identifier=".mht" ProgId="MSEdgeMHT" ApplicationName="Microsoft Edge" />
  <Association Identifier=".mhtml" ProgId="MSEdgeMHT" ApplicationName="Microsoft Edge" />
  <Association Identifier=".mka" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Media Player" />
  <Association Identifier=".mkv" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Media Player" />
  <Association Identifier=".mod" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Media Player" />
  <Association Identifier=".mov" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Media Player" />
  <Association Identifier=".MP2" ProgId="WMP11.AssocFile.MP3" ApplicationName="Windows Media Player Legacy" />
  <Association Identifier=".mp2v" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Media Player" />
  <Association Identifier=".mp3" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Media Player" />
  <Association Identifier=".mp4" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Media Player" />
  <Association Identifier=".mp4v" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Media Player" />
  <Association Identifier=".mpa" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Media Player" />
  <Association Identifier=".MPE" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Media Player" />
  <Association Identifier=".mpeg" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Media Player" />
  <Association Identifier=".mpg" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Media Player" />
  <Association Identifier=".mpv2" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Media Player" />
  <Association Identifier=".mrw" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".msg" ProgId="Outlook.File.msg.15" ApplicationName="Outlook" />
  <Association Identifier=".mts" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Media Player" />
  <Association Identifier=".nef" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".nrw" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".oga" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Media Player" />
  <Association Identifier=".ogg" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Media Player" />
  <Association Identifier=".ogm" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Media Player" />
  <Association Identifier=".ogv" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Media Player" />
  <Association Identifier=".ogx" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Media Player" />
  <Association Identifier=".opus" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Media Player" />
  <Association Identifier=".orf" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".pdf" ProgId="Acrobat.Document.DC" ApplicationName="Adobe Acrobat" />
  <Association Identifier=".pef" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".png" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".ps1" ProgId="AppXxf01pj590w7z9mxmyv3nx0a9ewj3e51g" ApplicationName="Notepad" />
  <Association Identifier=".psd1" ProgId="AppXc9vj55m1n3559gcjff0scsqeket80zp7" ApplicationName="Notepad" />
  <Association Identifier=".psm1" ProgId="AppX1b0e9ytcwx0wcmvkdey0h6af04t1ta3z" ApplicationName="Notepad" />
  <Association Identifier=".raf" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".raw" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".rle" ProgId="AppXcesbfs704v2mjbts9dkr42s9vmrhxbkj" ApplicationName="Paint" />
  <Association Identifier=".rw2" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".rwl" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".scp" ProgId="AppX4ztfk9wxr86nxmzzq47px0nh0e58b8fw" ApplicationName="Notepad" />
  <Association Identifier=".sr2" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".srw" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".svg" ProgId="ChromeHTML" ApplicationName="Google Chrome" />
  <Association Identifier=".tif" ProgId="PhotoViewer.FileAssoc.Tiff" ApplicationName="Windows Photo Viewer" />
  <Association Identifier=".tiff" ProgId="PhotoViewer.FileAssoc.Tiff" ApplicationName="Windows Photo Viewer" />
  <Association Identifier=".tod" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Media Player" />
  <Association Identifier=".TS" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Media Player" />
  <Association Identifier=".TTS" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Media Player" />
  <Association Identifier=".txt" ProgId="AppX4ztfk9wxr86nxmzzq47px0nh0e58b8fw" ApplicationName="Notepad" />
  <Association Identifier=".url" ProgId="InternetShortcut" ApplicationName="Internet Browser" />
  <Association Identifier=".vcf" ProgId="AppXpb1vntage8kvnwpyg40aqz34j851h4p1" ApplicationName="People" />
  <Association Identifier=".wav" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Media Player" />
  <Association Identifier=".wdp" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".webm" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Media Player" />
  <Association Identifier=".wm" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Media Player" />
  <Association Identifier=".wma" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Media Player" />
  <Association Identifier=".wmf" ProgId="AppXcesbfs704v2mjbts9dkr42s9vmrhxbkj" ApplicationName="Paint" />
  <Association Identifier=".wmv" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Media Player" />
  <Association Identifier=".WPL" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Media Player" />
  <Association Identifier=".wtx" ProgId="AppX4ztfk9wxr86nxmzzq47px0nh0e58b8fw" ApplicationName="Notepad" />
  <Association Identifier=".xht" ProgId="ChromeHTML" ApplicationName="Google Chrome" />
  <Association Identifier=".xhtml" ProgId="ChromeHTML" ApplicationName="Google Chrome" />
  <Association Identifier=".xvid" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Media Player" />
  <Association Identifier=".zip" ProgId="CompressedFolder" ApplicationName="Windows Explorer" />
  <Association Identifier=".zpl" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Media Player" />
  <Association Identifier="bingmaps" ProgId="AppXp9gkwccvk6fa6yyfq3tmsk8ws2nprk1p" ApplicationName="Maps" />
  <Association Identifier="ftp" ProgId="MSEdgeHTM" ApplicationName="Microsoft Edge" />
  <Association Identifier="http" ProgId="ChromeHTML" ApplicationName="Google Chrome" />
  <Association Identifier="https" ProgId="ChromeHTML" ApplicationName="Google Chrome" />
  <Association Identifier="mailto" ProgId="Outlook.URL.mailto.15" ApplicationName="Outlook" />
  <Association Identifier="microsoft-edge" ProgId="MSEdgeHTM" ApplicationName="Microsoft Edge" />
  <Association Identifier="microsoft-edge-holographic" ProgId="MSEdgeHTM" ApplicationName="Microsoft Edge" />
  <Association Identifier="ms-screenclip" ProgId="AppXfeq5vwnakrw6cy02kzhq8ekhhsremh62" ApplicationName="Snipping Tool" />
  <Association Identifier="ms-xbl-3d8b930f" ProgId="MSEdgeHTM" ApplicationName="Microsoft Edge" />
  <Association Identifier="mswindowsmusic" ProgId="AppXtggqqtcfspt6ks3fjzyfppwc05yxwtwy" ApplicationName="Media Player" />
  <Association Identifier="read" ProgId="MSEdgeHTM" ApplicationName="Microsoft Edge" />
</DefaultAssociations>
'@

# Define the content for Newdefaultassociations.xml
$newDefaultContent = @'
<?xml version="1.0" encoding="UTF-8"?>
<DefaultAssociations>
  <Association Identifier=".3fr" ProgId="AppX9rkaq77s0jzh1tyccadx9ghba15r6t3h" ApplicationName="Photos" />
  <Association Identifier=".ari" ProgId="AppX9rkaq77s0jzh1tyccadx9ghba15r6t3h" ApplicationName="Photos" />
  <Association Identifier=".arw" ProgId="AppX9rkaq77s0jzh1tyccadx9ghba15r6t3h" ApplicationName="Photos" />
  <Association Identifier=".avci" ProgId="AppX9rkaq77s0jzh1tyccadx9ghba15r6t3h" ApplicationName="Photos" />
  <Association Identifier=".avif" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".bay" ProgId="AppX9rkaq77s0jzh1tyccadx9ghba15r6t3h" ApplicationName="Photos" />
  <Association Identifier=".bmp" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".cab" ProgId="CABFolder" ApplicationName="Windows Explorer" />
  <Association Identifier=".cap" ProgId="AppX9rkaq77s0jzh1tyccadx9ghba15r6t3h" ApplicationName="Photos" />
  <Association Identifier=".cr2" ProgId="AppX9rkaq77s0jzh1tyccadx9ghba15r6t3h" ApplicationName="Photos" />
  <Association Identifier=".cr3" ProgId="AppX9rkaq77s0jzh1tyccadx9ghba15r6t3h" ApplicationName="Photos" />
  <Association Identifier=".crw" ProgId="AppX9rkaq77s0jzh1tyccadx9ghba15r6t3h" ApplicationName="Photos" />
  <Association Identifier=".dcr" ProgId="AppX9rkaq77s0jzh1tyccadx9ghba15r6t3h" ApplicationName="Photos" />
  <Association Identifier=".dcs" ProgId="AppX9rkaq77s0jzh1tyccadx9ghba15r6t3h" ApplicationName="Photos" />
  <Association Identifier=".dib" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".dng" ProgId="AppXvvwq6wxamf7qhxd0vn6wm1wwehyxrdd6" ApplicationName="Photos" />
  <Association Identifier=".drf" ProgId="AppX9rkaq77s0jzh1tyccadx9ghba15r6t3h" ApplicationName="Photos" />
  <Association Identifier=".eip" ProgId="AppX9rkaq77s0jzh1tyccadx9ghba15r6t3h" ApplicationName="Photos" />
  <Association Identifier=".emf" ProgId="AppXcesbfs704v2mjbts9dkr42s9vmrhxbkj" ApplicationName="Paint" />
  <Association Identifier=".erf" ProgId="AppX9rkaq77s0jzh1tyccadx9ghba15r6t3h" ApplicationName="Photos" />
  <Association Identifier=".fff" ProgId="AppX9rkaq77s0jzh1tyccadx9ghba15r6t3h" ApplicationName="Photos" />
  <Association Identifier=".gif" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".heic" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".heif" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".hif" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".htm" ProgId="ChromeHTML" ApplicationName="Google Chrome" />
  <Association Identifier=".html" ProgId="ChromeHTML" ApplicationName="Google Chrome" />
  <Association Identifier=".ico" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".ics" ProgId="AppX18q1gk8kdws5gt2g5c62cxc6qydq7tsw" ApplicationName="Outlook" />
  <Association Identifier=".iiq" ProgId="AppX9rkaq77s0jzh1tyccadx9ghba15r6t3h" ApplicationName="Photos" />
  <Association Identifier=".inf" ProgId="AppXzwr976v2e060wada4gabrk1x69h2dbwy" ApplicationName="Notepad" />
  <Association Identifier=".ini" ProgId="AppXhk4des8gf2xat3wtyzc5q06ny78jhkqx" ApplicationName="Notepad" />
  <Association Identifier=".jfif" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".jpe" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".jpeg" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".jpg" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".jxr" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".k25" ProgId="AppX9rkaq77s0jzh1tyccadx9ghba15r6t3h" ApplicationName="Photos" />
  <Association Identifier=".kdc" ProgId="AppX9rkaq77s0jzh1tyccadx9ghba15r6t3h" ApplicationName="Photos" />
  <Association Identifier=".log" ProgId="AppX4ztfk9wxr86nxmzzq47px0nh0e58b8fw" ApplicationName="Notepad" />
  <Association Identifier=".mef" ProgId="AppX9rkaq77s0jzh1tyccadx9ghba15r6t3h" ApplicationName="Photos" />
  <Association Identifier=".mht" ProgId="MSEdgeMHT" ApplicationName="Microsoft Edge" />
  <Association Identifier=".mhtml" ProgId="MSEdgeMHT" ApplicationName="Microsoft Edge" />
  <Association Identifier=".mos" ProgId="AppX9rkaq77s0jzh1tyccadx9ghba15r6t3h" ApplicationName="Photos" />
  <Association Identifier=".MP2" ProgId="WMP11.AssocFile.MP3" ApplicationName="Windows Media Player Legacy" />
  <Association Identifier=".mrw" ProgId="AppX9rkaq77s0jzh1tyccadx9ghba15r6t3h" ApplicationName="Photos" />
  <Association Identifier=".nef" ProgId="AppX9rkaq77s0jzh1tyccadx9ghba15r6t3h" ApplicationName="Photos" />
  <Association Identifier=".nrw" ProgId="AppX9rkaq77s0jzh1tyccadx9ghba15r6t3h" ApplicationName="Photos" />
  <Association Identifier=".orf" ProgId="AppX9rkaq77s0jzh1tyccadx9ghba15r6t3h" ApplicationName="Photos" />
  <Association Identifier=".ori" ProgId="AppX9rkaq77s0jzh1tyccadx9ghba15r6t3h" ApplicationName="Photos" />
  <Association Identifier=".pdf" ProgId="Acrobat.Document.DC" ApplicationName="Adobe Acrobat" />
  <Association Identifier=".pef" ProgId="AppX9rkaq77s0jzh1tyccadx9ghba15r6t3h" ApplicationName="Photos" />
  <Association Identifier=".png" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".ps1" ProgId="Applications\notepad++.exe" ApplicationName="Notepad++" />
  <Association Identifier=".psd1" ProgId="AppXc9vj55m1n3559gcjff0scsqeket80zp7" ApplicationName="Notepad" />
  <Association Identifier=".psm1" ProgId="AppX1b0e9ytcwx0wcmvkdey0h6af04t1ta3z" ApplicationName="Notepad" />
  <Association Identifier=".raf" ProgId="AppX9rkaq77s0jzh1tyccadx9ghba15r6t3h" ApplicationName="Photos" />
  <Association Identifier=".raw" ProgId="AppX9rkaq77s0jzh1tyccadx9ghba15r6t3h" ApplicationName="Photos" />
  <Association Identifier=".rle" ProgId="AppXcesbfs704v2mjbts9dkr42s9vmrhxbkj" ApplicationName="Paint" />
  <Association Identifier=".rw2" ProgId="AppX9rkaq77s0jzh1tyccadx9ghba15r6t3h" ApplicationName="Photos" />
  <Association Identifier=".rwl" ProgId="AppX9rkaq77s0jzh1tyccadx9ghba15r6t3h" ApplicationName="Photos" />
  <Association Identifier=".scp" ProgId="AppX4ztfk9wxr86nxmzzq47px0nh0e58b8fw" ApplicationName="Notepad" />
  <Association Identifier=".shtml" ProgId="ChromeHTML" ApplicationName="Google Chrome" />
  <Association Identifier=".sr2" ProgId="AppX9rkaq77s0jzh1tyccadx9ghba15r6t3h" ApplicationName="Photos" />
  <Association Identifier=".srf" ProgId="AppX9rkaq77s0jzh1tyccadx9ghba15r6t3h" ApplicationName="Photos" />
  <Association Identifier=".srw" ProgId="AppX9rkaq77s0jzh1tyccadx9ghba15r6t3h" ApplicationName="Photos" />
  <Association Identifier=".svg" ProgId="MSEdgeHTM" ApplicationName="Microsoft Edge" />
  <Association Identifier=".thumb" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".tif" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".tiff" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".txt" ProgId="AppX4ztfk9wxr86nxmzzq47px0nh0e58b8fw" ApplicationName="Notepad" />
  <Association Identifier=".url" ProgId="InternetShortcut" ApplicationName="Internet Browser" />
  <Association Identifier=".wdp" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".webp" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".wmf" ProgId="AppXcesbfs704v2mjbts9dkr42s9vmrhxbkj" ApplicationName="Paint" />
  <Association Identifier=".wtx" ProgId="AppX4ztfk9wxr86nxmzzq47px0nh0e58b8fw" ApplicationName="Notepad" />
  <Association Identifier=".xht" ProgId="MSEdgeHTM" ApplicationName="Microsoft Edge" />
  <Association Identifier=".xhtml" ProgId="ChromeHTML" ApplicationName="Google Chrome" />
  <Association Identifier=".xml" ProgId="MSEdgeHTM" ApplicationName="Microsoft Edge" />
  <Association Identifier=".zip" ProgId="CompressedFolder" ApplicationName="Windows Explorer" />
  <Association Identifier="ftp" ProgId="MSEdgeHTM" ApplicationName="Microsoft Edge" />
  <Association Identifier="http" ProgId="ChromeHTML" ApplicationName="Google Chrome" />
  <Association Identifier="https" ProgId="ChromeHTML" ApplicationName="Google Chrome" />
  <Association Identifier="mailto" ProgId="AppXbx2ce4vcxjdhff3d1ms66qqzk12zn827" ApplicationName="Outlook" />
  <Association Identifier="microsoft-edge" ProgId="MSEdgeHTM" ApplicationName="Microsoft Edge" />
  <Association Identifier="microsoft-edge-holographic" ProgId="MSEdgeHTM" ApplicationName="Microsoft Edge" />
  <Association Identifier="ms-outlook" ProgId="AppX1scw7cgxcz9hmq03sd8qajzg3s9t7901" ApplicationName="Outlook" />
  <Association Identifier="ms-screenclip" ProgId="AppXfeq5vwnakrw6cy02kzhq8ekhhsremh62" ApplicationName="Snipping Tool" />
  <Association Identifier="ms-xbl-3d8b930f" ProgId="MSEdgeHTM" ApplicationName="Microsoft Edge" />
  <Association Identifier="read" ProgId="MSEdgeHTM" ApplicationName="Microsoft Edge" />
</DefaultAssociations>
'@

# Save the files
$defaultContent | Out-File -FilePath (Join-Path $destinationPath "defaultassociations.xml") -Encoding utf8
$newDefaultContent | Out-File -FilePath (Join-Path $destinationPath "Newdefaultassociations.xml") -Encoding utf8

Write-Host "Files have been successfully created in $destinationPath" -ForegroundColor Green

$ScriptDir = "\\share.technion.ac.il\pcsupport$\ins\Scripts"
$TempDir = "C:\temp"
$PrimaryXML = Join-Path $TempDir "defaultassociations.xml"
$SecondaryXML = Join-Path $TempDir "Newdefaultassociations.xml"

New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DefaultAssociationsConfiguration" -Value "$TempDir\defaultassociations.xml" -PropertyType String -Force
dism.exe /Online /Import-DefaultAppAssociations:$TempDir\defaultassociations.xml

$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"

    New-Item -Path $regPath -Force | Out-Null

    New-ItemProperty -Path $regPath `
        -Name "DefaultAssociationsConfiguration" `
        -Value $TempXML `
        -PropertyType String -Force | Out-Null




# Enable local administartor account 
Enable-LocalUser -Name "Administrator" 


# Taskbar: Add "Show Desktop" Button
Write-Host "==================================" -ForegroundColor Cyan
Write-Host " Adding Show Desktop to Taskbarns " -ForegroundColor White
Write-Host "==================================" -ForegroundColor Cyan

Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarSd" -Value 1 -Force

# Taskbar: Remove Widgets
Write-Host "===============================" -ForegroundColor Cyan
Write-Host " Removing Widgets from Taskbar " -ForegroundColor White
Write-Host "===============================" -ForegroundColor Cyan

# Ensure the parent key exists
$parentKeyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Dsh"
if (-not (Test-Path $parentKeyPath)) {
    New-Item -Path $parentKeyPath -Force
}

# Create the property
New-ItemProperty -Path $parentKeyPath -Name "AllowNewsAndInterests" -Value 0 -PropertyType DWORD -Force


# Fix Shortcut Warning from Desktop and c:\apps folder for all users
Write-Host "============================" -ForegroundColor Cyan
Write-Host " Fixing Shortcut Warning... " -ForegroundColor White
Write-Host "============================" -ForegroundColor Cyan
Write-Output "."
Write-Output "Fixing Shortcut Warning..." 
    # Loop through each user folder in C:\Users
    Get-ChildItem -Directory -Path "C:\Users" | ForEach-Object {
        $desktopPaths = @(
            "$($_.FullName)\OneDrive - Technion\desktop",
            "$($_.FullName)\desktop",
            "c:\apps\"
            
        )
        
        foreach ($desktopPath in $desktopPaths) {
            # Check if the user folder exists
            if (Test-Path -Path $desktopPath) {
                # Change permissions for all .lnk files in the user's Desktop folder
                Unblock-File -Path "$desktopPath\*.lnk"

                Write-Host "Permissions changed for .lnk files in $desktopPath"
            } else {
                Write-Warning "User folder '$desktopPath' not found."
            }
        }
    }


    # Define the target folders
    $folders = "C:\Users\Public\Desktop", "C:\Users\Public\Desktop\Useful Links"

    # Iterate through each folder
    foreach ($folder in $folders) {
        # Check if the folder exists
        if (Test-Path $folder) {
            # Change permissions for all .lnk files in the folder
            unblock-file -path "$folder\*.lnk" 
            Write-Host "Permissions changed for .lnk files in $folder"
        } else {
            Write-Warning "Folder '$folder' not found."
        }
    }

# Add the logon User to Remote Desktop Users Group
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host " adding the logon User to Remote Desktop Users Group " -ForegroundColor White
Write-Host "=====================================================" -ForegroundColor Cyan

    
    # Get the "Remote Desktop Users" group
    $Group = Get-LocalGroup -Name "Remote Desktop Users"

    # Get the output of the logon user name
    $quserOutput = quser

    # Parse the output to get the logged on username
    # Match lines with a valid username and ignore header lines or any other non-relevant lines
    $loggedOnUser = $quserOutput | Select-String -Pattern "^\s*(\S+)\s+(\S+)\s+(\S+)" | ForEach-Object { $_.Matches[0].Groups[1].Value }

    # Remove any lines that are empty or contain "USERNAME"
    $LogOnUser = $loggedOnUser | Where-Object { $_ -and $_ -notmatch "USERNAME" } | ForEach-Object { $_.TrimStart('>') }
	
	    # Check if the user is already a member of the group
    $IsUserInGroup = Get-LocalGroupMember -Group $Group | Where-Object { $_.Name -eq "staff\$LogOnUser" }

    if ($IsUserInGroup) {
        Write-Host "User $LogOnUser is already a member of the 'Remote Desktop Users' group."
    } else {
        try {
            Add-LocalGroupMember -Group $Group -Member $LogOnUser@technion.ac.il -ErrorAction Stop
            Write-Host "User $LogOnUser@technion.ac.il added to 'Remote Desktop Users' group successfully." -ForegroundColor white -BackgroundColor blue
        } catch {
            Write-Host "Failed to add user $LogOnUser@technion.ac.il to 'Remote Desktop Users' group." -ForegroundColor white -BackgroundColor Red
        }
    }

    # Display the current users in the group
    Write-Host "this are the users that enable to remote this computer"
    Get-LocalGroupMember -Group "Remote Desktop Users" | Select-Object Name


# Check if the computer is a laptop and install Harmony VPN
Write-Host "===========================================================" -ForegroundColor Magenta
Write-Host " Check if the computer is a laptop to install Harmony VPN " -ForegroundColor White
Write-Host "===========================================================" -ForegroundColor Magenta
write-host ""

# Get information about the system enclosure
$enclosure = Get-WmiObject -Class Win32_SystemEnclosure

# Check the chassis type to define if it is a laptop or Desktop.
$laptopChassisTypes = @(8, 9, 10, 11, 12, 14, 18, 21, 31, 32)



# Remove Harmony SASE from Startup
Write-host "====================================================" -ForegroundColor Cyan
Write-host " Check for manufacturer Type and install Update App " -ForegroundColor White
Write-host "====================================================" -ForegroundColor Cyan

# Check if the computer is a laptop and install Harmony VPN
Write-Host "===========================================================" -ForegroundColor Magenta
Write-Host " Check if the computer is a laptop to install Harmony VPN " -ForegroundColor White
Write-Host "===========================================================" -ForegroundColor Magenta
Write-Host ""

# Get information about the system enclosure
$enclosure = Get-WmiObject -Class Win32_SystemEnclosure

# Define laptop chassis types
$laptopChassisTypes = @(8, 9, 10, 11, 12, 14, 18, 21, 31, 32)

# Check if the system is a laptop
if ($enclosure.ChassisTypes -match ($laptopChassisTypes -join '|')) {

    Write-Host "===================================================" -ForegroundColor Cyan
    Write-Host " Applying Harmony VPN Notification Tray Icon Fix... " -ForegroundColor White
    Write-Host "===================================================" -ForegroundColor Cyan

    $searchPath = "Control Panel\NotifyIconSettings"
    $searchValue = "Perimeter81.exe"
    $newKey = "IsPromoted"
    $newValue = 1
# If Computer is a laptop 
    $userProfiles = Get-ChildItem -Path "Registry::HKEY_USERS" -ErrorAction SilentlyContinue

    foreach ($userProfile in $userProfiles) {
        $userProfilePath = "Registry::HKEY_USERS\$($userProfile.PSChildName)"
        $registryPath = Join-Path -Path $userProfilePath -ChildPath $searchPath

        if (Test-Path -Path $registryPath -ErrorAction SilentlyContinue) {
            $numberedFolders = Get-ChildItem -Path $registryPath -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^\d+$' }

            foreach ($numberedFolder in $numberedFolders) {
                $folderPath = Join-Path -Path $registryPath -ChildPath $numberedFolder.PSChildName -ErrorAction SilentlyContinue
                $executablePath = Get-ItemPropertyValue -LiteralPath $folderPath -Name "ExecutablePath" -ErrorAction SilentlyContinue

                if ($executablePath -like "*$searchValue*") {
                    if (Test-Path -Path "$folderPath\$newKey") {
                        Set-ItemProperty -Path $folderPath -Name $newKey -Value $newValue
                        Write-Host "Key updated for user profile: $($userProfile.PSChildName), Folder: $($numberedFolder.PSChildName)"
                    } else {
                        New-ItemProperty -Path $folderPath -Name $newKey -Value $newValue -PropertyType DWORD -Force
                        Write-Host "Key added for user profile: $($userProfile.PSChildName), Folder: $($numberedFolder.PSChildName)"
                    }
                }
            }
        }
    }

    Write-Output "."    
    Write-Host "All Finish"
	stop-process -name explorer -force
} else {
    Write-Host "This computer is not identified as a laptop." -ForegroundColor Yellow
	stop-process -name explorer -force
}

# Clean up old files
Remove-Item -Path "c:\temp\Microsoft.UI.*.appx" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "c:\temp\Microsoft.VCLibs.*.appx" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "c:\temp\Microsoft.DesktopAppInstaller_*.msixbundle" -Force -ErrorAction SilentlyContinue

# remove Widgets
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft" -Name "Dsh" -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Dsh" -Name "AllowNewsAndInterests" -Value 0 -PropertyType DWord -Force

# Install Winget

    
    # Clean up old files
Remove-Item -Path "C:\temp\Microsoft.UI.*.appx" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\temp\Microsoft.VCLibs.*.appx" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\temp\Microsoft.DesktopAppInstaller_*.msixbundle" -Force -ErrorAction SilentlyContinue

# Check if winget is already installed
$wingetPath = (Get-Command winget -ErrorAction SilentlyContinue).Source
if ($wingetPath) {
    Write-Host "Winget is already installed at $wingetPath" -ForegroundColor Green
} else {
    # Copy new files from network share
    $sourcePath = "\\share.technion.ac.il\pcsupport$\INS\Scripts\WinGetFiles\*"
    if (Test-Path $sourcePath) {
        Copy-Item -Path $sourcePath -Destination "C:\temp\" -Force -Recurse
        Write-Host "Copied Winget files from network share." -ForegroundColor Green
    } else {
        Write-Host "Network share unavailable. Downloading Winget from the internet..." -ForegroundColor Yellow
        # Download latest Winget and dependencies
        Invoke-WebRequest -Uri "https://github.com/microsoft/winget-cli/releases/latest/download/Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle" -OutFile "C:\temp\Microsoft.DesktopAppInstaller.msixbundle"
        Invoke-WebRequest -Uri "https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx" -OutFile "C:\temp\Microsoft.VCLibs.x64.14.00.Desktop.appx"
        Invoke-WebRequest -Uri "https://github.com/microsoft/microsoft-ui-xaml/releases/download/v2.8.6/Microsoft.UI.Xaml.2.8.x64.appx" -OutFile "C:\temp\Microsoft.UI.Xaml.2.8.x64.appx"
    }

    # Install dependencies
    try {
        Add-AppxPackage -Path "C:\temp\Microsoft.VCLibs.*.appx" -ErrorAction Stop
        Add-AppxPackage -Path "C:\temp\Microsoft.UI.*.appx" -ErrorAction Stop
        Add-AppxPackage -Path "C:\temp\Microsoft.DesktopAppInstaller*.msixbundle" -ErrorAction Stop
	    $msix = Join-Path -Path $env:TEMP -ChildPath 'source.msix'
		Invoke-WebRequest https://cdn.winget.microsoft.com/cache/source.msix -OutFile $msix -UseBasicParsing  
		Add-AppXPackage -Path $msix  
		Write-Host "Source file has been installed" -ForegroundColor Green
    
    # Update winget source
    winget source update
    Clear-Host
    Write-Host "Updated winget source"
        Write-Host "Winget and dependencies installed successfully." -ForegroundColor Green
    } catch {
        Write-Host "Failed to install Winget: $_" -ForegroundColor Red
        
    }

    # Refresh PATH
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
}

# Verify Winget is available
$wingetPath = (Get-Command winget -ErrorAction SilentlyContinue).Source
if ($wingetPath) {
    Write-Host "Winget is now available at $wingetPath" -ForegroundColor Green
    # Update winget source
    winget source update
} else {
    Write-Host "Winget installation failed or not found in PATH. Please restart the script or install manually." -ForegroundColor Red
    
}

Write-Host "Winget installation complete." -ForegroundColor Cyan
    $msix = Join-Path -Path $env:TEMP -ChildPath 'source.msix'
    Invoke-WebRequest https://cdn.winget.microsoft.com/cache/source.msix -OutFile $msix -UseBasicParsing  
    Add-AppXPackage -Path $msix  
    Write-Host "Source file has been installed"
    
    # Update winget source
    winget source update
    Clear-Host
    Write-Host "Updated winget source"    
    # Update winget source
    winget source update
    Clear-Host
    Write-Host ""
    Write-host "=======================================" -ForegroundColor Cyan
    Write-host " Updated sources to install update app " -ForegroundColor White
    Write-host "=======================================" -ForegroundColor Cyan

# Winget upgrade
# exclude Harmony SASE for updated
winget upgrade --accept-package-agreements --accept-source-agreements --force > $null 2>&1
winget pin add --id Perimeter81.HarmonySASE --blocking --accept-package-agreements --accept-source-agreements


Write-Host "Checks the computer manufacturer and installs the appropriate software"
# Get computer system information
$computerSystem = Get-WmiObject -Class Win32_ComputerSystem
# Check the manufacturer
$manufacturer = $computerSystem.Manufacturer
# Convert the manufacturer name to lowercase for easier comparison
$manufacturer = $manufacturer.ToLower()
if ($manufacturer -like "*dell*") {
    #xcopy "\\share.technion.ac.il\pcsupport$\INS\Amit_Tools\apps\Dell-Command-Update-Windows-Universal-Application*.EXE" "c:\temp\*"

	#winget command to install Dell Command Update Universal
    #$exeFile = Get-ChildItem -Path "C:\temp\Dell-Command-Update-Windows-Universal-Application*.EXE" | Select-Object -First 1
	winget install --id Dell.CommandUpdate.Universal --silent --accept-package-agreements --accept-source-agreements --scope machine

    # Check if a file was found
    if ($exeFile) {
        Start-Process -FilePath $exeFile.FullName -ArgumentList "/s" -Wait
    } else {
        Write-Error "No matching Dell Command Update .EXE file found in the specified path."
    }
} else {

}


if ($manufacturer -like "*lenovo*") {
    Write-Host "This Is a Lenovo Computer, Installing Lenovo Commercial Vantage"
	# Define variables
$Url = "https://download.lenovo.com/pccbbs/thinkvantage_en/metroapps/Vantage/LenovoCommercialVantage_20.2511.24.0.20251217075118.zip"
$ZipPath = "C:\Temp\LenovoCommercialVantage.zip"
$ExtractPath = "C:\Temp\LenovoCoVantage"
$InstallerPath = Join-Path $ExtractPath "VantageInstaller.exe"

# Ensure Temp directory exists
if (!(Test-Path "C:\Temp")) {
    New-Item -Path "C:\" -Name "Temp" -ItemType Directory -Force | Out-Null
}

# Download file
Write-Host "Downloading Lenovo Commercial Vantage - this will take a few minutes..."
Invoke-WebRequest -Uri $Url -OutFile $ZipPath -UseBasicParsing

if (!(Test-Path $ZipPath)) {
    Write-Error "Download failed. File not found."
    exit 1
}

# Remove existing extraction folder if exists
if (Test-Path $ExtractPath) {
    Write-Host "Cleaning previous extraction folder..."
    Remove-Item -Path $ExtractPath -Recurse -Force
}

# Extract ZIP
Write-Host "Extracting package..."
Expand-Archive -Path $ZipPath -DestinationPath $ExtractPath -Force

if (!(Test-Path $InstallerPath)) {
    Write-Error "Installer not found after extraction."
    exit 1
}

# Run installer
Write-Host "Running Lenovo Commercial Vantage installer..."
Start-Process -FilePath $InstallerPath -ArgumentList "Install -Vantage" -Wait -NoNewWindow

Write-Host "Installation process completed."

}
     
    # Clean downloaded files
     Remove-Item -Path "C:\temp\Microsoft.DesktopAppInstaller_*.msixbundle" -Force -ErrorAction SilentlyContinue
     Remove-Item -Path "C:\temp\Microsoft.VCLibs.*.appx" -Force -ErrorAction SilentlyContinue
     Remove-Item -Path "C:\temp\Microsoft.UI.*.appx" -Force -ErrorAction SilentlyContinue
     Write-Host "Cleaned all downloaded files"


# Prompt user if continue with Winget update
Write-Host "Do you want to update installed programs using Winget? (Y/N)" -ForegroundColor Blue
$response = (Read-Host).Trim().ToLower()

if ($response -in @('y','yes')) {
    Write-Output "."
    Write-Output "Running Winget Update..."

  
    # Winget upgrade all packages
	# Exclude Harmony SASE from winget update
	winget pin add --id Perimeter81.HarmonySASE
	
    Write-Host "Starting Winget Upgrade for all packages..."
    winget upgrade --all -h -u --force

    Write-Host "============================" -ForegroundColor Cyan
    Write-Host " Finished Winget Upgrade... " -ForegroundColor White
    Write-Host "============================" -ForegroundColor Cyan
    Write-Host ""
   
    
} else {
    Write-Output "Skipping Winget update."
	}

# Remove CIS Profile
Write-host "Remove CIS Profile"
$profile = Get-WmiObject Win32_UserProfile | Where-Object { $_.LocalPath -match "C:\\Users\\cis" }
$profile.Delete()
Write-host "CIS Profile deleted"


# End Logging
Write-Host "============================" -ForegroundColor White -BackgroundColor Cyan
Write-Host " Script execution complete! " -ForegroundColor Black -BackgroundColor Cyan
Write-Host "============================" -ForegroundColor White -BackgroundColor Cyan
Write-Host ""
Write-host "you can check the log file at: "$TempDir\NewCompAdmin_$TimeNow.txt""  -ForegroundColor yellow
Write-Host ""
Write-Host "Press Enter to Close the window" -ForegroundColor Blue
Read-Host ""
Stop-Transcript

# Open Windows update
Start-Process "ms-settings:windowsupdate"

start-Process explorer.exe \\share.technion.ac.il\pcsupport$\INS\Scripts\

exit
