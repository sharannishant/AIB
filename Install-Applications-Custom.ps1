# Software install Script
#
# Applications to install:
#


#region Set logging 
$logFile = "C:\TCS\" + (get-date -format 'yyyyMMdd') + '_softwareinstall.log'
function Write-Log {
    Param($message)
    Write-Output "$(get-date -format 'yyyyMMdd HH:mm:ss') $message" | Out-File -Encoding utf8 $logFile -Append
}
#endregion


#region Trend Micro
try {
    Start-Process -filepath msiexec.exe -ErrorAction Stop -ArgumentList '/i', 'C:\TCS\Agent-Core-Windows-20.0.1.233.x64.msi', '/quiet' -Wait
    
    if (Test-Path "C:\Program Files\Trend Micro\Deep Security Agent\dsa.exe") 
    {
        Write-Log "Trend Micro has been installed"
    }
    else {
        write-log "Error locating the Trend Micro executable"
    }
}
catch {
    $ErrorMessage = $_.Exception.message
    write-log "Error installing Trend Micro: $ErrorMessage"
}
#endregion

#region CrowdStrike

try {
    Start-Process -filepath 'C:\TCS\WindowsSensor.exe' -ArgumentList "/install /quiet /norestart CID=58CE029866E14481A529D5E495AEB242-76  NO_START=1" -Wait
    
    if (Test-Path "C:\Program Files\CrowdStrike\CSFalconService.exe") 
    {
        Write-Log "CrowdStrike has been installed"
    }
    else {
        write-log "Error locating the CrowdStrike executable"
    }
}
catch {
    $ErrorMessage = $_.Exception.message
    write-log "Error installing CrowdStrike: $ErrorMessage"
}
#endregion

#region Qualys
try {
    Start-Process -filepath 'C:\TCS\QualysCloudAgent.exe' -ArgumentList "CustomerId={183554fa-0bc8-cb39-837d-10f521fe6a8b} ActivationId={8cae7032-f75e-4160-a50a-ebf12196aff9} WebServiceUri=https://qagpublic.qg1.apps.qualys.eu/CloudAgent/" -Wait
    Start-Process -filepath 'C:\Program Files\qualys\qualysagent\QualysProxy.exe' -Args "/a http://siaphadkcph001.apmoller.net/pac/central.pac"

    if (Test-Path "C:\ProgramData\Qualys") 
    {
        Write-Log "QualysCloudAgent has been installed"
    }
    else {
        write-log "Error locating the QualysCloudAgent executable"
    }
}
catch {
    $ErrorMessage = $_.Exception.message
    write-log "Error installing QualysCloudAgent: $ErrorMessage"
}

#endregion


#region Java

try {
    Start-Process -filepath 'C:\TCS\JRE8_up241_x64.exe' -ArgumentList "/s REBOOT=ReallySuppress" -Wait -PassThru |out-file "C:\TCS\JavaInstall.txt"
    Start-Process -filepath 'C:\TCS\JRE8_up241_x86.exe' -ArgumentList "/s REBOOT=ReallySuppress" -Wait -PassThru |out-file "C:\TCS\JavaInstall.txt"


    if (Test-Path "C:\Program Files\Java\jre1.8.0_291\bin\java.exe") 
    {
        Write-Log "Java 8 Update 241 64-Bit has been installed"
    }
    else {
        write-log "Error locating the Java 8 executable"
    }
    if (Test-Path "C:\Program Files (x86)\Java\jre1.8.0_291\bin\java.exe") 
    {
        Write-Log "Java 8 Update 241 32-Bit has been installed"
    }
    else {
        write-log "Error locating the Java 8 executable"
    }

}
catch {
    $ErrorMessage = $_.Exception.message
    write-log "Error installing Java: $ErrorMessage"
}
#endregion

#region 32 bit Java Update Disable
$Name1 = "NotifyDownload"
$Name2 = "EnableJavaUpdate"
$value = "0"
# Add Registry value
try {
    New-ItemProperty -ErrorAction Stop -Path "HKLM:\SOFTWARE\JavaSoft\Java Update\Policy" -Name $Name1 -Value $value -PropertyType DWORD -Force |out-file "C:\TCS\JavaReg.txt"
    New-ItemProperty -ErrorAction Stop -Path "HKLM:\SOFTWARE\JavaSoft\Java Update\Policy" -Name $Name2 -Value $value -PropertyType DWORD -Force |out-file "C:\TCS\JavaReg.txt"

    if ((Get-ItemProperty "HKLM:\SOFTWARE\JavaSoft\Java Update\Policy").PSObject.Properties.Name -contains $Name1) 
    {
        Write-log "Added Java NotifyDownload DWORD"
    }
    else 
    {
        write-log "Failed to Add Java NotifyDownload DWORD"
    }
    if ((Get-ItemProperty "HKLM:\SOFTWARE\JavaSoft\Java Update\Policy").PSObject.Properties.Name -contains $Name2) {
        Write-log "Added EnableJavaUpdate DWORD"
    }
    else {
        write-log "Failed to Add EnableJavaUpdate DWORD"
    }
}
catch {
    $ErrorMessage = $_.Exception.message
    write-log "Error adding Java Registries for 32-Bit Java: $ErrorMessage"
}
#endregion

#region 64 bit Java Update Disable
$Name1 = "NotifyDownload"
$Name2 = "EnableJavaUpdate"

$value = "0"
# Add Registry value
try {
    New-ItemProperty -ErrorAction Stop -Path "HKLM:\SOFTWARE\WOW6432Node\JavaSoft\Java Update\Policy" -Name $Name1 -Value $value -PropertyType DWORD -Force |out-file "C:\TCS\JavaReg.txt"
    New-ItemProperty -ErrorAction Stop -Path "HKLM:\SOFTWARE\WOW6432Node\JavaSoft\Java Update\Policy" -Name $Name2 -Value $value -PropertyType DWORD -Force |out-file "C:\TCS\JavaReg.txt"
    New-ItemProperty -ErrorAction Stop -Path "HKLM:\SOFTWARE\WOW6432Node\JavaSoft\Java Update\Policy\jucheck" -Name $Name1 -Value $value -PropertyType DWORD -Force |out-file "C:\TCS\JavaReg.txt"

    if ((Get-ItemProperty "HKLM:\SOFTWARE\WOW6432Node\JavaSoft\Java Update\Policy").PSObject.Properties.Name -contains $Name1) 
    {
        Write-log "Added Java NotifyDownload DWORD"
    }
    else 
    {
        write-log "Failed to Add Java NotifyDownload DWORD"
    }
    if ((Get-ItemProperty "HKLM:\SOFTWARE\WOW6432Node\JavaSoft\Java Update\Policy").PSObject.Properties.Name -contains $Name2) {
        Write-log "Added EnableJavaUpdate DWORD"
    }
    else {
        write-log "Failed to Add EnableJavaUpdate DWORD"
    }
    if ((Get-ItemProperty "HKLM:\SOFTWARE\WOW6432Node\JavaSoft\Java Update\Policy\jucheck").PSObject.Properties.Name -contains $Name1) 
    {
        Write-log "Added Java NotifyDownload DWORD"
    }
    else 
    {
        write-log "Failed to Add Java NotifyDownload DWORD"
    }
}
catch {
    $ErrorMessage = $_.Exception.message
    write-log "Error adding Java Registries for 64-Bit Java: $ErrorMessage"
}
#endregion


#region ZScaler Certificate
Import-Certificate -FilePath C:\TCS\ZscalerRootCertificate-2048-SHA256.crt -CertStoreLocation Cert:\LocalMachine\Root |out-file "C:\TCS\ZScaler.txt"
#endregion


#region Schedule Task for Trend
try 
{
	$taskaction = New-ScheduledTaskAction -Execute "C:\TCS\TrendActivator.bat"
	$taskTrigger = New-ScheduledTaskTrigger -AtStartup
	$taskName = "Trend Activator"
	$User= "NT AUTHORITY\SYSTEM"
	$description = "Activate Trend Micro at Startup"
	Register-ScheduledTask -TaskName $taskName -Action $taskaction -Trigger $taskTrigger -User $User -Description $description -RunLevel Highest -Force |out-file "C:\TCS\TaskSchedular.txt"
	$taskExists = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if ($taskExists) 
    {
        Write-Log "Trend Activator Schedule Task has been created"
    }
    else {
        write-log "Creation Failed for Trend Activator Schedule Task"
    }
}
catch {
    $ErrorMessage = $_.Exception.message
    write-log "Error in Creation for Trend Activator Schedule Task: $ErrorMessage"
}
#endregion

#region Applying LGPO
try {
    Start-Process -filepath 'C:\TCS\LGPO\LGPO.exe' -ArgumentList "/g C:\TCS\LGPO\Backup\{CB7407B8-C6C2-48E8-ACC9-7710AD73D131}\" -Wait
    
    if ((Get-ItemProperty "HKLM:\SOFTWARE\FSLogix\Profiles").PSObject.Properties.Name -contains "Enabled") 
    {
        Write-log "FSLogix configured by LGPO"
    }
    else 
    {
        write-log "FSLogix not configured by LGPO.Please verify"
    }
}
catch {
    $ErrorMessage = $_.Exception.message
    write-log "LGPO not executed: $ErrorMessage"
}
#endregion

#region Set logging 
$logFile = "C:\TCS\" + (get-date -format 'yyyyMMdd') + '_softwareinstall.log'
function Write-Log {
    Param($message)
    Write-Output "$(get-date -format 'yyyyMMdd HH:mm:ss') $message" | Out-File -Encoding utf8 $logFile -Append
}
#endregion

#region Setup RDP ShortPath
$Name1 = "fUseUdpPortRedirector"
$Name2 = "UdpPortNumber"
$value = "1"
# Add Registry value
try {
    $WinstationsKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations'
    New-ItemProperty -Path $WinstationsKey -Name $Name1 -Value $value -PropertyType DWORD -Force |out-file "C:\TCS\RDPShortPathReg.txt"
    New-ItemProperty -Path $WinstationsKey -Name $Name2 -Value $value -PropertyType DWORD -Force |out-file "C:\TCS\RDPShortPathReg.txt"
    New-NetFirewallRule -DisplayName 'Remote Desktop - Shortpath (UDP-In)'  -Action Allow -Description 'Inbound rule for the Remote Desktop service to allow RDP traffic. [UDP 3390]' -Group '@FirewallAPI.dll,-28752' -Name 'RemoteDesktop-UserMode-In-Shortpath-UDP'  -PolicyStore PersistentStore -Profile Domain, Private -Service TermService -Protocol udp -LocalPort 3390 -Program '%SystemRoot%\system32\svchost.exe' -Enabled:True
    if ((Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations").PSObject.Properties.Name -contains $Name1) 
    {
        Write-log "Added RDP ShortPath DWORD"
    }
    else 
    {
        write-log "Failed to Add RDP ShortPath DWORD"
    }
    if ((Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations").PSObject.Properties.Name -contains $Name2) {
        Write-log "Added RDP ShortPath DWORD"
    }
    else {
        write-log "Failed to Add RDP ShortPath DWORD"
    }
}
catch {
    $ErrorMessage = $_.Exception.message
    write-log "Error adding RDP ShortPath Registries: $ErrorMessage"
}
#endregion

#region Time Zone Redirection
$Name = "fEnableTimeZoneRedirection"
$value = "1"
# Add Registry value
try {
    New-ItemProperty -ErrorAction Stop -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name $name -Value $value -PropertyType DWORD -Force
    if ((Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services").PSObject.Properties.Name -contains $name) {
        Write-log "Added time zone redirection registry key"
    }
    else {
        write-log "Error locating the Time registry key"
    }
}
catch {
    $ErrorMessage = $_.Exception.message
    write-log "Error adding time registry KEY: $ErrorMessage"
}
#endregion


#region Sysprep Fix
# Fix for first login delays due to Windows Module Installer
try {
    ((Get-Content -path C:\DeprovisioningScript.ps1 -Raw) -replace 'Sysprep.exe /oobe /generalize /quiet /quit', 'Sysprep.exe /oobe /generalize /quit /mode:vm' ) | Set-Content -Path C:\DeprovisioningScript.ps1
    write-log "Sysprep Mode:VM fix applied"
}
catch {
    $ErrorMessage = $_.Exception.message
    write-log "Error updating script: $ErrorMessage"
}
#endregion

