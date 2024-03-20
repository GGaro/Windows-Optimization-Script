Add-Type -AssemblyName System.Windows.Forms

$form = New-Object System.Windows.Forms.Form
$form.Text = "Windows Optimization Script"
$form.Size = New-Object System.Drawing.Size(800, 600)
$form.StartPosition = "CenterScreen"

function Create-OptimizationButton {
    param (
        [string]$ButtonText,
        [int]$X,
        [int]$Y,
        [scriptblock]$OnClick
    )

    $button = New-Object System.Windows.Forms.Button
    $button.Text = $ButtonText
    $button.Location = New-Object System.Drawing.Point($X, $Y)

    $buttonWidth = [System.Windows.Forms.TextRenderer]::MeasureText($button.Text, $button.Font).Width
    $button.Width = $buttonWidth + 20  
    $button.Add_Click($OnClick)

    return $button
}

function Set-RegistryValue {
    param (
        [string]$Path,
        [string]$Name,
        [object]$Value,
        [string]$Type = "DWORD"
    )

    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -Force
    }

    switch ($Type) {
        "DWORD" { New-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWORD -Force }
        "String" { New-ItemProperty -Path $Path -Name $Name -Value $Value -Type String -Force }
        "Binary" { New-ItemProperty -Path $Path -Name $Name -Value $Value -Type Binary -Force }
        default { Write-Host "Unsupported registry value type: $Type" }
    }
}

function Take-Ownership {
    param (
        [string]$FilePath
    )

    $acl = Get-Acl $FilePath
    $owner = [System.Security.Principal.NTAccount]"BUILTIN\Administrators"
    $acl.SetOwner($owner)
    Set-Acl -Path $FilePath -AclObject $acl
}


$SplitThresholdAction = {
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control"
    $valueName = "SvcHostSplitThresholdInKB"
    $totalRAMKB = (Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1KB
    $newValueData = [math]::ceiling($totalRAMKB + 100000)
    New-ItemProperty -Path $registryPath -Name $valueName -Value $newValueData -PropertyType DWord -Force
    Write-Host "Split Threshold for Svchost set to '$newValueData' KB'."
}

$RepairAction = {
    Write-Host "Running Repair commands..."
    Start-Process -FilePath "cmd.exe" -ArgumentList "/c @ECHO OFF && DISM /Online /Cleanup-Image /CheckHealth && DISM /Online /Cleanup-Image /ScanHealth && DISM /Online /Cleanup-Image /RestoreHealth && Sfc /scannow && timeout /t -1" -Verb RunAs
}

$RestorePointAction = {
    Write-Host "Creating a system restore point..."
    Checkpoint-Computer -Description "Optimization Restore Point" -RestorePointType "MODIFY_SETTINGS"
    Write-Host "System restore point created."
}

$DisableBackgroundAppsAction = {
    Write-Host "Disabling background apps..."
    Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -Name "GlobalUserDisabled" -Value 1
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -Name "AllowPrelaunch" -Value 0 -Type DWORD
    Write-Host "Background apps disabled."
}

$DisableDefenderAction = {
    Write-Host "Disabling Windows Defender..."
    Set-MpPreference -DisableRealtimeMonitoring $true
    Set-MpPreference -DisableScanningNetworkFiles $true
    $defenderRegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
    $defenderRegistryValues = @{
        "DisableAntiSpyware" = 1
        "DisableRealtimeMonitoring" = 1
        "DisableAntiVirus" = 1
        "DisableSpecialRunningModes" = 1
        "DisableRoutinelyTakingAction" = 1
        "ServiceKeepAlive" = 0
    }
    $defenderRegistryValues.GetEnumerator() | ForEach-Object {
        Set-RegistryValue -Path $defenderRegistryPath -Name $_.Key -Value $_.Value -Type DWORD
    }

    $realTimeProtectionRegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
    $realTimeProtectionValues = @{
        "DisableBehaviorMonitoring" = 1
        "DisableOnAccessProtection" = 1
        "DisableScanOnRealtimeEnable" = 1
        "DisableRealtimeMonitoring" = 1
    }
    $realTimeProtectionValues.GetEnumerator() | ForEach-Object {
        Set-RegistryValue -Path $realTimeProtectionRegistryPath -Name $_.Key -Value $_.Value -Type DWORD
    }

    $signatureUpdatesRegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates"
    Set-RegistryValue -Path $signatureUpdatesRegistryPath -Name "ForceUpdateFromMU" -Value 0 -Type DWORD


    $spynetRegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet"
    Set-RegistryValue -Path $spynetRegistryPath -Name "DisableBlockAtFirstSeen" -Value 1 -Type DWORD


    Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "Windows Defender" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" -Name "Windows Defender" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsDefender" -ErrorAction SilentlyContinue

    Write-Host "Windows Defender disabled."
}

$ShowVerbMessAction = {
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "VerboseStatus" -Value 1 -Type DWORD
    Write-Host "Verbose Messages Enabled."
}

$ClearVMAction = {
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "ClearPageFileAtShutdown" -Value 1 -Type DWORD
    Write-Host "Clear Virtual Memory Page File at Shutdown Enabled."
}

$DisableHibernateAction = {
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name "HibernateEnabled" -Value 0 -Type DWORD
    Write-Host "Hibernate Disabled."
}

$GamingBoostAction = {

    $gameBarRegistryPath = "HKCU:\Software\Microsoft\GameBar"
    $gameBarRegistryValues = @{
        "AllowAutoGameMode" = 1
        "AutoGameModeEnabled" = 1
    }
    $gameBarRegistryValues.GetEnumerator() | ForEach-Object {
        Set-RegistryValue -Path $gameBarRegistryPath -Name $_.Key -Value $_.Value -Type DWORD
    }

    Set-RegistryValue -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" -Name "AppCaptureEnabled" -Value 0 -Type DWORD

    Set-RegistryValue -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Value 0 -Type DWORD

    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowgameDVR" -Value 0 -Type DWORD

    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name "HwSchMode" -Value 1 -Type DWORD

    Set-RegistryValue -Path "HKCU:\Software\Microsoft\DirectX\GraphicsSettings" -Name "SwapEffectUpgradeCache" -Value 1 -Type DWORD

    Set-RegistryValue -Path "HKCU:\Software\Microsoft\DirectX\UserGpuPreferences" -Name "DirectXUserGlobalSettings" -Value "SwapEffectUpgradeEnable=1;" -Type String

    Write-Host "Gaming Boosted."
}

$PrivacyAction = {
    Set-RegistryValue -Path "HKCU:\Software\Policies\Microsoft\Windows\EdgeUI" -Name "DisableMFUTracking" -Value 1 -Type DWORD
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisableUAR" -Value 1 -Type DWORD
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0
    Set-RegistryValue -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "AllowCortana" -Value 0
    Set-RegistryValue -Path "HKCU:\SOFTWARE\Microsoft\Input\TIPC" -Name "EnableDesktopModeTransform" -Value 0
    Set-RegistryValue -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Value 0
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "Value" -Value 0

    Write-Host "Disabling Data Logging Services..."

    $servicesToDisable = @(
        "DiagTrack",
        "dmwappushservice",
        "diagnosticshub.standardcollector.service",
        "WMPNetworkSvc",
        "WSearch"
    )

    $servicesToDisable | ForEach-Object {
        Stop-Service -Name $_ -Force
        Set-Service -Name $_ -StartupType Disabled
    }

    $autoLoggerPath = "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\AutoLogger-Diagtrack-Listener"
    $autoLoggerReg = Get-ItemProperty -Path $autoLoggerPath
    Set-RegistryValue -Path $autoLoggerPath -Name Enabled -Value 0
    Set-RegistryValue -Path $autoLoggerPath -Name Start -Value 0

    Write-Host "Removing Microsoft Compatibility Appraiser..."

    Take-Ownership -FilePath "$env:windir\System32\CompatTelRunner.exe"

    $filePath = "$env:windir\System32\CompatTelRunner.exe"
    icacls $filePath /grant "$env:username:F"

    Remove-Item "$env:windir\System32\CompatTelRunner.exe" -Force

    Write-Host "Microsoft Compatibility Appraiser removed."

    Write-Host "Modifying the Windows registry..."

    $registryCommands = @{
    'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\ClientTelemetry' = @(
        'IsCensusDisabled=1',
        'DontRetryOnError=1',
        'TaskEnableRun=1'
    )
    'HKLM\SOFTWARE\Microsoft\DataCollection' = 'AllowTelemetry=0'
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection' = 'AllowTelemetry=0'
    'HKCU\SOFTWARE\Policies\Microsoft\Windows\DataCollection' = 'AllowTelemetry=0'
    'HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\SQMLogger' = 'Start=0'
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat' = 'AITEnable=0'
    'HKCU\SOFTWARE\Policies\Microsoft\Assistance\Client\1.0' = 'NoExplicitFeedback=1'
    }   




    $registryCommands.GetEnumerator() | ForEach-Object {
    $key = $_.Key
    $values = $_.Value

    foreach ($value in $values) {
        $regPath = $key -replace 'REG_DWORD$', ''
        $regType = if ($key -match 'REG_DWORD$') { 'REG_DWORD' } else { 'REG_SZ' }

        Write-Host "Adding registry entry: $regPath /v $value /t $regType /d 0 /f"
        reg add "$regPath" /v "$value" /t $regType /d 0 /f
    }
   
    Write-Host "Windows registry modified."

    Write-Host "Windows privacy improved."
    }
}

$EnableLongPathsAction = {
    Write-Host "Enabling Win32 long paths..."

    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name "LongPathsEnabled" -Value 1

    Write-Host "Win32 long paths enabled."
}

$OptimizeNetworkSettingsAction = {
    Write-Host "Optimizing network settings..."

    netsh int tcp set global autotuninglevel=normal

    netsh interface 6to4 set state disabled
    netsh int isatap set state disable
    netsh int tcp set global timestamps=disabled
    netsh int tcp set heuristics disabled
    netsh int tcp set global chimney=disabled
    netsh int tcp set global ecncapability=disabled
    netsh int tcp set global rsc=disabled
    netsh int tcp set global nonsackrttresiliency=disabled
    netsh int tcp set security mpp=disabled
    netsh int tcp set security profiles=disabled
    netsh int ip set global icmpredirects=disabled
    netsh int tcp set security mpp=disabled profiles=disabled
    netsh int ip set global multicastforwarding=disabled
    netsh int tcp set supplemental internet congestionprovider=ctcp
    netsh interface teredo set state disabled
    netsh winsock reset
    netsh int isatap set state disable
    netsh int ip set global taskoffload=disabled
    netsh int ip set global neighborcachelimit=4096
    netsh int tcp set global dca=enabled
    netsh int tcp set global netdma=enabled

    Get-NetAdapter | ForEach-Object {
        Disable-NetAdapterLso -Name $_.Name
        Disable-NetAdapterPowerManagement -Name $_.Name -ErrorAction SilentlyContinue
        Disable-NetAdapterLso -Name $_.Name -ErrorAction SilentlyContinue
    }

    $regCommands = @(
        'reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableICMPRedirect" /t REG_DWORD /d "1" /f',
        'reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnablePMTUDiscovery" /t REG_DWORD /d "1" /f',
        'reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "Tcp1323Opts" /t REG_DWORD /d "0" /f',
        'reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxDupAcks" /t REG_DWORD /d "2" /f',
        'reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpTimedWaitDelay" /t REG_DWORD /d "32" /f',
        'reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "GlobalMaxTcpWindowSize" /t REG_DWORD /d "8760" /f',
        'reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpWindowSize" /t REG_DWORD /d "8760" /f',
        'reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxConnectionsPerServer" /t REG_DWORD /d "0" /f',
        'reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxUserPort" /t REG_DWORD /d "65534" /f',
        'reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "SackOpts" /t REG_DWORD /d "0" /f',
        'reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DefaultTTL" /t REG_DWORD /d "64" /f',
        'reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_SZ /d "ffffffff" /f'
    )

    $regCommands | ForEach-Object {
        Invoke-Expression $_
    }

    Write-Host "Network settings optimized."
}

$UninstallEdgeAction = {
    Write-Host "Uninstalling Microsoft Edge and preventing updates..."

    $edgePath = "$env:ProgramFiles(x86)\Microsoft\Edge"

    $version = Get-ChildItem -Path "$edgePath\Application" | Where-Object { $_.PSIsContainer } | Select-Object -ExpandProperty Name

    $edgeWebViewSetup = Join-Path -Path $edgePath -ChildPath "EdgeWebView\Application\$version\Installer\setup.exe"
    $edgeSetup = Join-Path -Path $edgePath -ChildPath "Edge\Application\$version\Installer\setup.exe"
    $edgeCoreSetup = Join-Path -Path $edgePath -ChildPath "EdgeCore\$version\Installer\setup.exe"

    if (Test-Path $edgeWebViewSetup) {
        Start-Process -FilePath $edgeWebViewSetup -ArgumentList "--uninstall", "--force-uninstall", "--msedgewebview", "--system-level", "--verbose-logging" -Wait
    }

    if (Test-Path $edgeSetup) {
        Start-Process -FilePath $edgeSetup -ArgumentList "--uninstall", "--force-uninstall", "--msedge", "--system-level", "--verbose-logging" -Wait
    }

    if (Test-Path $edgeCoreSetup) {
        Start-Process -FilePath $edgeCoreSetup -ArgumentList "--uninstall", "--force-uninstall", "--msedge", "--system-level", "--verbose-logging" -Wait
    }

    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft" -Name "DoNotUpdateToEdgeWithChromium" -Value 1 -PropertyType DWORD -Force | Out-Null

    Get-AppxPackage -Name Microsoft.MicrosoftEdge | Remove-AppxPackage -ErrorAction SilentlyContinue

    Remove-Item -Path $edgePath -Force -Recurse -ErrorAction SilentlyContinue

    Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\Edge\User Data" -Force -Recurse -ErrorAction SilentlyContinue

    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "DefaultPDFHandlerEnabled" -Value 0 -Force

    Write-Host "Microsoft Edge uninstalled and updates prevented." 
}

$CleanTempAction = {
    Write-Host "Cleaning temporary files..."

    Remove-Item -Path "$env:SYSTEMDRIVE\windows\temp\*" -Force -Recurse -ErrorAction SilentlyContinue

    Remove-Item -Path "$env:SYSTEMDRIVE\windows\temp" -Force -Recurse -ErrorAction SilentlyContinue

    New-Item -ItemType Directory -Path "c:\windows\temp" -Force

    Remove-Item -Path "$env:SYSTEMDRIVE\WINDOWS\Prefetch\*" -Force -Recurse -ErrorAction SilentlyContinue

    Remove-Item -Path "$env:temp\*" -Force -Recurse -ErrorAction SilentlyContinue

    Remove-Item -Path "$env:temp" -Force -Recurse -ErrorAction SilentlyContinue

    New-Item -ItemType Directory -Path "$env:temp" -Force

    Remove-Item -Path "$env:SYSTEMDRIVE\Temp\*" -Force -Recurse -ErrorAction SilentlyContinue

    Remove-Item -Path "$env:WINDIR\Prefetch\*" -Force -Recurse -ErrorAction SilentlyContinue

    Remove-Item -Path "$env:SYSTEMDRIVE\*.log" -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "$env:SYSTEMDRIVE\*.bak" -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "$env:SYSTEMDRIVE\*.gid" -Force -ErrorAction SilentlyContinue

    Write-Host "Temporary files cleaned."      
}

$UninstallOneDriveAction = {
    Write-Host "Uninstalling OneDrive..."

    Start-Process -FilePath "$env:SYSTEMROOT\SYSWOW64\ONEDRIVESETUP.EXE" -ArgumentList "/UNINSTALL" -Wait

    Remove-Item -Path "C:\OneDriveTemp" -Force -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path "$env:USERPROFILE\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path "$env:PROGRAMDATA\Microsoft OneDrive" -Force -Recurse -ErrorAction SilentlyContinue

    Set-RegistryValue -Path "HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}\ShellFolder" -Name "Attributes" -Value 0 -Type DWORD
    Set-RegistryValue -Path "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}\ShellFolder" -Name "Attributes" -Value 0 -Type DWORD

    Write-Host "OneDrive has been removed."
    
    Stop-Process -Name explorer -Force
    Start-Process explorer
}

$RemoveXboxAction = {
    Write-Host "Removing Xbox..."

    Get-AppxPackage -Name Microsoft.XboxApp | Remove-AppxPackage -ErrorAction SilentlyContinue

    Get-AppxPackage -Name Microsoft.XboxGamingOverlay | Remove-AppxPackage -ErrorAction SilentlyContinue

    Get-AppxPackage -Name Microsoft.XboxIdentityProvider | Remove-AppxPackage -ErrorAction SilentlyContinue

    Write-Host "Xbox removed."  
}

$DisableEdgePDFAction = {
    Write-Host "Disabling Microsoft Edge PDF handling..."

    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "DefaultPDFHandlerEnabled" -Value 0 -Force | Out-Null

    Write-Host "Microsoft Edge PDF handling disabled."   
}

$OptimizeWindowsAction = {
    Write-Host "Disabling Windows Feedback Experience program"
    $Advertising = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo"
    If (Test-Path $Advertising) {
        Set-RegistryValue $Advertising Enabled -Value 0 
    }

    Write-Host "Stopping Cortana from being used as part of your Windows Search Function"
    $Search = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
    If (Test-Path $Search) {
        Set-RegistryValue $Search AllowCortana -Value 0 
    }

    Write-Host "Disabling Bing Search in Start Menu"
    $WebSearch = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
    Set-RegistryValue "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" BingSearchEnabled -Value 0 
    If (!(Test-Path $WebSearch)) {
        New-Item $WebSearch
    }
    Set-RegistryValue $WebSearch DisableWebSearch -Value 1 

    Write-Host "Stopping the Windows Feedback Experience program"
    $Period = "HKCU:\Software\Microsoft\Siuf\Rules"
    If (!(Test-Path $Period)) { 
        New-Item $Period
    }
    Set-RegistryValue $Period PeriodInNanoSeconds -Value 0 

    Write-Host "Adding Registry key to prevent bloatware apps from returning"
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
    $registryOEM = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
    If (!(Test-Path $registryPath)) { 
        New-Item $registryPath
    }
    Set-RegistryValue $registryPath DisableWindowsConsumerFeatures -Value 1 

    If (!(Test-Path $registryOEM)) {
        New-Item $registryOEM
    }
    Set-RegistryValue $registryOEM ContentDeliveryAllowed -Value 0 
    Set-RegistryValue $registryOEM OemPreInstalledAppsEnabled -Value 0 
    Set-RegistryValue $registryOEM PreInstalledAppsEnabled -Value 0 
    Set-RegistryValue $registryOEM PreInstalledAppsEverEnabled -Value 0 
    Set-RegistryValue $registryOEM SilentInstalledAppsEnabled -Value 0 
    Set-RegistryValue $registryOEM SystemPaneSuggestionsEnabled -Value 0          

    Write-Host "Setting Mixed Reality Portal value to 0 so that you can uninstall it in Settings"
    $Holo = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Holographic"    
    If (Test-Path $Holo) {
        Set-RegistryValue $Holo FirstRunSucceeded -Value 0 
    }

    Write-Host "Disabling Wi-Fi Sense"
    $WifiSense1 = "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting"
    $WifiSense2 = "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots"
    $WifiSense3 = "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config"
    If (!(Test-Path $WifiSense1)) {
        New-Item $WifiSense1
    }
    Set-RegistryValue $WifiSense1 Value -Value 0 
    If (!(Test-Path $WifiSense2)) {
        New-Item $WifiSense2
    }
    Set-RegistryValue $WifiSense2 Value -Value 0 
    Set-RegistryValue $WifiSense3 AutoConnectAllowedOEM -Value 0 

    Write-Host "Disabling live tiles"
    $Live = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"    
    If (!(Test-Path $Live)) {      
        New-Item $Live
    }
    Set-RegistryValue $Live NoTileApplicationNotification -Value 1 

    Write-Host "Turning off Data Collection"
    $DataCollection1 = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"
    $DataCollection2 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
    $DataCollection3 = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection"    
    If (Test-Path $DataCollection1) {
        Set-RegistryValue $DataCollection1 AllowTelemetry -Value 0 
    }
    If (Test-Path $DataCollection2) {
        Set-RegistryValue $DataCollection2 AllowTelemetry -Value 0 
    }
    If (Test-Path $DataCollection3) {
        Set-RegistryValue $DataCollection3 AllowTelemetry -Value 0 
    }

    Write-Host "Disabling Location Tracking"
    $SensorState = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}"
    $LocationConfig = "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration"
    If (!(Test-Path $SensorState)) {
        New-Item $SensorState
    }
    Set-RegistryValue $SensorState SensorPermissionState -Value 0 
    If (!(Test-Path $LocationConfig)) {
        New-Item $LocationConfig
    }
    Set-RegistryValue $LocationConfig Status -Value 0 

    Write-Host "Disabling People icon on Taskbar"
    $People = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People"    
    If (!(Test-Path $People)) {
        New-Item $People
    }
    Set-RegistryValue $People PeopleBand -Value 0 

    Write-Host "Disabling scheduled tasks"
    Get-ScheduledTask XblGameSaveTaskLogon | Disable-ScheduledTask
    Get-ScheduledTask XblGameSaveTask | Disable-ScheduledTask
    Get-ScheduledTask Consolidator | Disable-ScheduledTask
    Get-ScheduledTask UsbCeip | Disable-ScheduledTask
    Get-ScheduledTask DmClient | Disable-ScheduledTask
    Get-ScheduledTask DmClientOnScenarioDownload | Disable-ScheduledTask

    Write-Host "Stopping and disabling WAP Push Service"
    Stop-Service "dmwappushservice"
    Set-Service "dmwappushservice" -StartupType Disabled

    Write-Host "Stopping and disabling Diagnostics Tracking Service"
    Stop-Service "DiagTrack"
    Set-Service "DiagTrack" -StartupType Disabled

    Write-Host "Windows tracking disabled."   
}

$DisableSuperfetchAction = {
    Write-Host "Disabling Superfetch service"
    Stop-Service -Name "SysMain" -Force
    Set-Service -Name "SysMain" -StartupType Disabled
}




$RepairButton = Create-OptimizationButton -ButtonText "Repair (No Restore Point Required)" -X 20 -Y 20 -OnClick $RepairAction
$RestorePointButton = Create-OptimizationButton -ButtonText "Create Restore Point (IMPORTANT!!!!)" -X ($RepairButton.Left + $RepairButton.Width + 20) -Y 20 -OnClick $RestorePointAction

$OptimizeWindowsButton = Create-OptimizationButton -ButtonText "Generic Windows Optimization" -X 20 -Y 60 -OnClick $OptimizeWindowsAction
$DisableSuperfetchButton = Create-OptimizationButton -ButtonText "Disable Superfetch" -X ($OptimizeWindowsButton.Left + $OptimizeWindowsButton.Width + 20) -Y 60 -OnClick $disableSuperfetchAction

$SplitThresholdButton = Create-OptimizationButton -ButtonText "Change Split Threshold Above Ram" -X 20 -Y 100 -OnClick $SplitThresholdAction
$DisableBackgroundAppsButton = Create-OptimizationButton -ButtonText "Disable Background Apps" -X ($SplitThresholdButton.Left + $SplitThresholdButton.Width + 20) -Y 100 -OnClick $DisableBackgroundAppsAction

$DisableDefenderButton = Create-OptimizationButton -ButtonText "Disable Windows Defender" -X 20 -Y 140 -OnClick $DisableDefenderAction
$ShowVerbMessButton = Create-OptimizationButton -ButtonText "Show Verbose Messages" -X ($DisableDefenderButton.Left + $DisableDefenderButton.Width + 20) -Y 140 -OnClick $ShowVerbMessAction

$ClearVMButton = Create-OptimizationButton -ButtonText "Clear Virtual Memory Page File at Shutdown" -X 20 -Y 180 -OnClick $ClearVMAction
$DisableHibernateButton = Create-OptimizationButton -ButtonText "Disable Hibernation" -X ($ClearVMButton.Left + $ClearVMButton.Width + 20) -Y 180 -OnClick $DisableHibernateAction

$GamingBoostButton = Create-OptimizationButton -ButtonText "Gaming Boosts" -X 20 -Y 220 -OnClick $GamingBoostAction
$PrivacyButton = Create-OptimizationButton -ButtonText "Improve Privacy (Massive Change)" -X ($GamingBoostButton.Left + $GamingBoostButton.Width + 20) -Y 220 -OnClick $PrivacyAction

$EnableLongPathsButton = Create-OptimizationButton -ButtonText "Enable Long Paths" -X 20 -Y 260 -OnClick $EnableLongPathsAction
$OptimizeNetworkSettingsButton = Create-OptimizationButton -ButtonText "Optimize Network Settings" -X ($EnableLongPathsButton.Left + $EnableLongPathsButton.Width + 20) -Y 260 -OnClick $OptimizeNetworkSettingsAction

$CleanTempButton = Create-OptimizationButton -ButtonText "Clean Temporary Files" -X 20 -Y 300 -OnClick $CleanTempAction
$UninstallOneDriveButton = Create-OptimizationButton -ButtonText "Uninstall OneDrive" -X ($CleanTempButton.Left + $CleanTempButton.Width + 20) -Y 300 -OnClick $UninstallOneDriveAction

$RemoveXboxButton = Create-OptimizationButton -ButtonText "Remove Xbox" -X 20 -Y 340 -OnClick $RemoveXboxAction
$RemoveEdgeButton = Create-OptimizationButton -ButtonText "Remove Microsoft Edge" -X ($RemoveXboxButton.Left + $RemoveXboxButton.Width + 20) -Y 340 -OnClick $UninstallEdgeAction

$DisableEdgePDFButton = Create-OptimizationButton -ButtonText "Disable Edge PDF Handling" -X 20 -Y 380 -OnClick $DisableEdgePDFAction


$form.Controls.Add($RepairButton)
$form.Controls.Add($RestorePointButton)
$form.Controls.Add($OptimizeWindowsButton)
$form.Controls.Add($DisableSuperfetchButton)
$form.Controls.Add($SplitThresholdButton)
$form.Controls.Add($DisableBackgroundAppsButton)
$form.Controls.Add($DisableDefenderButton)
$form.Controls.Add($ShowVerbMessButton)
$form.Controls.Add($ClearVMButton)
$form.Controls.Add($DisableHibernateButton)
$form.Controls.Add($GamingBoostButton)
$form.Controls.Add($PrivacyButton)
$form.Controls.Add($EnableLongPathsButton)
$form.Controls.Add($OptimizeNetworkSettingsButton)
$form.Controls.Add($CleanTempButton)
$form.Controls.Add($UninstallOneDriveButton)
$form.Controls.Add($RemoveXboxButton)
$form.Controls.Add($RemoveEdgeButton)
$form.Controls.Add($DisableEdgePDFButton)

$form.ShowDialog()
