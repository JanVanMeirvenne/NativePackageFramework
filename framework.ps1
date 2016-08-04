<#
.SYNOPSIS 
 
This script is an engine to deploy and manage native applications on a machine. It does this by utilizing an input 'application info' file which provides the steps needed to perform an installation, uninstall or detection of the application.

.DESCRIPTION 
 
The script can be started as followed:

framework.ps1 -action <Install|Uninstall|Detection[default])> (-force) -ApplicationInfo <Path To Application File[default=ApplicationInfo.txt in script root]>
 
 
The Application Input file needs to have the name and type 'ApplicationInfo.txt;

These sections must be defined, each one being opened with a [<section>] tag, and the value being entered on the next line:
[ApplicationName]
<the name of the application>
[ApplicationVersion]
<the version of the application>
[ApplicationDescription]
<a short description on the functionality of the packaged application>
[ApplicationAuthor]
<who packaged the application>
[ApplicationInstallSequence]
<the steps needed to install the application>
[ApplicationUninstallSequence]
<the steps needed to uninstall the application>
[ApplicationDetectionSequence]
<the steps needed to detect the installation of the application>
[ApplicationParameters]
<dynamic parameters that can be used in the sequencesm format Key->Value>

A Sequence consists of a Type, a Path and optionally, Parameters

Type
----

A type is an action that the script needs to perform as part of a sequence. The following types exist (divided per sequence Install, Uninstall and Detection)

    Install
    -------

    Note: unless the -force parameter is specified when executing the framework, the install action will not continue if the application is detected on the system


    MSIInstall: this action installs a given MSI file with /qn /norestart /l*v:<logroot> as default parameters (you do not need to specify these). Additional parameters can be placed in the parameters field
    Example: Type=MSIInstall,Path=(ApplicationRoot)\MyApp.msi,Parameters=DEFAULT_SERVER=MyAppServer.contoso.com
    Note: this action is elevated automatically

    File: this actions runs any given file in a new admin process, appended by the given parameters in the parameters-field.
    Example: Type=File,Path=reg.exe,Parameters=import (ApplicationRoot)\MyRegSettings.reg
    Example: Type=File,Path=powershell.exe,Parameters=-executionpolicy bypass -command "get-service -name MyService|restart-service"
    Example: Type=File,Path=(ApplicationRoot)\setup.exe,Parameters=/silent
    Note: this action is elevated automatically

    UserReg: this action can be used to make sure a certain registry key is created for existing and new users. It uses a custom function to cause registry additions at user logon
    Format: Type=UserReg,Path=hkcu:\<MyUserRegPath>,Parameters=Type=<(String|DWord|ExpandString|Binary|MultiString)>,Name=<RegValueName>,Value=<RegValue>
    Example: Type=UserReg,Path=hkcu:\MyUserRegPath\ChildNode,Parameters=Type=DWord,Name=UpdatesEnabled,Value=0
    Note: this action is NOT elevated automatically currently

    UnInstall
    ---------

    Note: unless the -force parameter is specified when executing the framework, the uninstall action will not continue if the application is not detected on the system

    MSIUninstall: this action uninstalls a MSI-installation using a given MSI file of product code. It uses the parameters /qn /norestart by default.
    Example: Type=MSIUninstall,Path=(ApplicationRoot)\MyApp.msi,Parameters=
    Example: Type=MSIUninstall,Path={AEC5BCA3-A2C5-46D7-9873-7698E6D3CAA4}

    File: this actions runs any given file in a new admin process, appended by the given parameters in the parameters-field.
    Example: Type=File,Path=reg.exe,Parameters=import (ApplicationRoot)\MyRegSettings.reg
    Example: Type=File,Path=powershell.exe,Parameters=-executionpolicy bypass -command "get-service -name MyService|restart-service"
    Example: Type=File,Path=(ApplicationRoot)\setup.exe,Parameters=/silent
    Note: this action is elevated automatically

    Detection
    ---------

    MSIDetection: this action returns true when the installation with a given msi file or product code has been found
    Example: Type=MSIDetection,Path=(ApplicationRoot)\MyApp.msi,Parameters=
    Example: Type=MSIDetection,Path={AEC5BCA3-A2C5-46D7-9873-7698E6D3CAA4}

    WMI: this action performs a WMI query and returns true if a result is returned
    Example: Type=WMI,Path=select * from win32_service where name = 'MyApplicationService',Parameters=

    Registry: this action checks if a certain key or value is present in the registry and returns true if this is the case
    Example: Type=Registry,Path=hklm:\software\MyAppKey
    Example: Type=Registry,Path=hklm:\software\MyAppKey,Parameters=ProductVersion:1.2.3

Full Example of an applicationinfo.txt file
-------------------------------------------

[ApplicationName]
MBAMClient
[ApplicationVersion]
25
[ApplicationDescription]
Installs the MBAM Client and Contoso settings (http://bitlocker.contoso.com/MBAMRecoveryAndHardwareService/CoreService.svc)
[ApplicationAuthor]
Jan Van Meirvenne
[ApplicationInstallSequence]
Type=MSIInstall,Path=(ApplicationRoot)\MbamClientSetup-2.5.1100.0.msi,Parameters=
Type=File,Path=reg.exe,Parameters=import (ApplicationRoot)\ZOLMBAMSettings.reg
Type=File,Path=powershell.exe,Parameters=-executionpolicy bypass -command "get-service MBAMAgent|restart-service"
[ApplicationUninstallSequence]
Type=MSIUninstall,Path={AEC5BCA3-A2C5-46D7-9873-7698E6D3CAA4}
[ApplicationDetectionSequence]
Type=MSIDetection,Path={AEC5BCA3-A2C5-46D7-9873-7698E6D3CAA4}
[ApplicationParameters]

Variables
---------

Variables specified in the [ApplicationParameters] can be used in the sequence step definitions using the format (VariableKey)
Example: Type=File,Path=setup.exe,Parameters=/server=(ApplicationServer)

There are some default variables available:
(ApplicationRoot): the root-folder of the package, where the framework.ps1 is present
(LogRoot): the folder where the log-files are generated

Logging
-------

All actions are logged in a central file in c:\temp\ZOLSWInstall
with a dynamically generated folder with format <ApplicationName>_<ApplicationVersion[dots are removed]
and a filename with name <ApplicationName>_<ApplicationVersion[dots are removed]_<TimeStamp[yyyyMMdd-hhmmss]>-<Mode[Install|Uninstall].log

If possible, setup log files are trapped and merged in the central log file.
For MSI's, this is done automatically

For other installers, you can use the (LogRoot) in combination with the reserved names 'temp.log', 'temp.txt' or 'exeout.txt'.
These files will be searched for in the log-folder and merged in the central log file automatically

Shortcuts
---------

In the root-folder of the package, a sub-folder 'desktop' can be defined and populated with .lnk and .url objects.
After an installation, the objects will be placed on the all-users desktop. An uninstall will use the same sub-folder to determine which icons to remove from the all-users desktop.

Reboot
------

A reboot can be regulated by setting Reboot->1 in the [ApplicationParameters] section. This will force the framework to return a 3010 return code, indicating a pending reboot.
This is useful for SCCM based deployments to initiate a machine reboot operation
 
.EXAMPLE 

Force an application installation

framework.ps1 -action install -force
 
.EXAMPLE 

Uninstall an application

framework.ps1 -action uninstall

.EXAMPLE 

Check if an application is installed

framework.ps1 -action detection

.EXAMPLE 

Install an application with a specific application-file

framework.ps1 -action install -ApplicationFile d:\swrepo\softwareX\OfficeWithoutOutlook.txt
 
.NOTES 
 
It is advised to run this framework from an elevated prompt. A prompt is displayed if this is not the case, but this might not be implemented for every function.

.LINK

ChangeLog
---------
04-08-2016: initial documented version
#>


param(
    [ValidateSet("Install","Uninstall","Detection")]
    [string]
    # The Action to Perform for the application. Can be Install, Uninstall or Detection.
    $Action = "Detection",
    [switch]
    # Always executes the requested operation without checking the application install state first
    $Force,
    [string]
    # The application input file to use
    $ApplicationFile = "$PSScriptRoot\ApplicationInfo.txt"
)



# setup default variables and parameters, the script should stop the moment an exception occurs
$ErrorActionPreference = "stop"
$global:LogLocation = "C:\temp\ZOLSWInstall\"
$global:ApplicationInfoFile = $ApplicationFile

New-Variable -Name LogFile -Force
$global:ApplicationInfo = $null
New-Variable -Name Mode -Force
#New-Variable -Name ApplicationRoot -Scope Global -force -Value $PSScriptRoot
$global:LogRoot = $null


 if($Action){
        $Mode = $Action
    } else {
        $Mode = 'none'
    }

function Start-ZOLApplicationFramework(){
    
    [System.Threading.Thread]::CurrentThread.CurrentUICulture = 'en-US'
    [System.Threading.Thread]::CurrentThread.CurrentCulture = 'en-US'
    Set-PSDebug -Strict

    $global:ApplicationInfo = Get-ZOLApplicationInfo

    if($Mode -match "[iI]nstall|[uU]ninstall"){
        if((test-path $global:LogLocation) -eq $false){
            $LogDirectory = New-Item -Path $global:LogLocation -ItemType Directory
            Invoke-WmiMethod -Path "Win32_Directory.Name='$($LogDirectory.FullName)'" -Name compress|out-null
        }

    
        $ApplicationLogPath = "$global:LogLocation\$($global:ApplicationInfo.ApplicationName)_$($global:ApplicationInfo.ApplicationVersion.Replace('.',''))\"
        
        if((test-path "$ApplicationLogPath") -eq $false){
            new-item -Path $ApplicationLogPath -ItemType Directory|out-null
            
        }
     #   if($global:ApplicationInfo.ApplicationLog -eq $null){
            $global:ApplicationInfo.ApplicationLog = "$ApplicationLogPath\$($global:ApplicationInfo.ApplicationName)_$($global:ApplicationInfo.ApplicationVersion.Replace('.',''))_$(get-date -format 'yyyyMMdd-hhmmss')-$Mode.log"
            
        $global:LogRoot = split-path $global:ApplicationInfo.ApplicationLog
        log -Message "Setting log directory to $global:LogRoot"
        #Set-ZOLApplicationParameters
     #   }
    }
    Set-ZOLApplicationParameters
    return $global:ApplicationInfo
}

function Set-ZOLApplicationParameters {
     foreach($Sequence in $global:ApplicationInfo.ApplicationInstallSequence){
            $Sequence.Path = $Sequence.Path.Replace('(ApplicationRoot)',$PSScriptRoot).Replace('(LogRoot)',$global:LogRoot)
             if($Sequence.Parameters -ne $null){
                $Sequence.Parameters = $Sequence.Parameters.Replace('(ApplicationRoot)',$PSScriptRoot).Replace('(LogRoot)',$global:LogRoot)
            }
        }
     foreach($Sequence in $global:ApplicationInfo.ApplicationUnInstallSequence){
            $Sequence.Path = $Sequence.Path.Replace('(ApplicationRoot)',$PSScriptRoot).Replace('(LogRoot)',$global:LogRoot)
             if($Sequence.Parameters -ne $null){
                $Sequence.Parameters = $Sequence.Parameters.Replace('(ApplicationRoot)',$PSScriptRoot).Replace('(LogRoot)',$global:LogRoot)
            }
        }
     foreach($Sequence in $global:ApplicationInfo.ApplicationDetectionSequence){
            $Sequence.Path = $Sequence.Path.Replace('(ApplicationRoot)',$PSScriptRoot).Replace('(LogRoot)',$global:LogRoot)
             if($Sequence.Parameters -ne $null){
                $Sequence.Parameters = $Sequence.Parameters.Replace('(ApplicationRoot)',$PSScriptRoot).Replace('(LogRoot)',$global:LogRoot)
            }
        }
    foreach($Key in $global:ApplicationInfo.ApplicationParameters.Keys){
        foreach($Sequence in $global:ApplicationInfo.ApplicationInstallSequence){
            $Sequence.Path = $Sequence.Path.Replace("($Key)",$global:ApplicationInfo.ApplicationParameters[$Key])
             if($Sequence.Parameters -ne $null){
                $Sequence.Parameters = $Sequence.Parameters.Replace("($Key)",$global:ApplicationInfo.ApplicationParameters[$Key])
            }
        }
         foreach($Sequence in $global:ApplicationInfo.ApplicationUnInstallSequence){
            $Sequence.Path = $Sequence.Path.Replace("($Key)",$global:ApplicationInfo.ApplicationParameters[$Key])
             if($Sequence.Parameters -ne $null){
                $Sequence.Parameters = $Sequence.Parameters.Replace("($Key)",$global:ApplicationInfo.ApplicationParameters[$Key])
            }
        }
         foreach($Sequence in $global:ApplicationInfo.ApplicationDetectionSequence){
            $Sequence.Path = $Sequence.Path.Replace("($Key)",$global:ApplicationInfo.ApplicationParameters[$Key])
            if($Sequence.Parameters -ne $null){
                $Sequence.Parameters = $Sequence.Parameters.Replace("($Key)",$global:ApplicationInfo.ApplicationParameters[$Key])
            }
        }
    }

}
function Start-ZOLApplicationOperation {
    param(
        $Action = $Mode
    )
    $Action = $Action
    Log -Message "An application operation for '$($global:ApplicationInfo.ApplicationName) - $($global:ApplicationInfo.ApplicationVersion)' with action '$Action' has started"

    if($Mode -match ("[uU]ninstall|[iI]nstall")){
        $RDSRolePresent = Get-WmiObject -query "select * from win32_serverfeature where id = 130" -ErrorAction SilentlyContinue

        if($RDSRolePresent){
            Log -Message "RDS Role detected, setting user session to 'install mode'"
            & change /user install
        }
    }
}

function Stop-ZOLApplicationOperation {
    Log -Message "An application operation for '$($global:ApplicationInfo.ApplicationName) - $($global:ApplicationInfo.ApplicationVersion)' with action '$Mode' has ended"
    if($Mode -match ("[uU]ninstall|[iI]nstall")){
        $RDSRolePresent = Get-WmiObject -query "select * from win32_serverfeature where id = 130" -ErrorAction SilentlyContinue
        if($RDSRolePresent){
            Log -Message "RDS Role detected, setting user session to 'execute mode'"
            & change /user execute
        }
    }
    Get-ChildItem $global:LogRoot|?{$_.FullName -ne $global:ApplicationInfo.ApplicationLog.Replace("\\","\")}|Remove-Item -Force
}

function Get-ZOLApplicationInfo(){
    function _StoreVariable(){
        if($Variable -ne $null -and $SupportedVariables -contains $Variable){
                $Value = $Temp
                $Object.$Variable = $Value
                $Temp = $null
            }
    }
    $Content = get-content -Path $global:ApplicationInfoFile
    $Object = ""|select ApplicationName,ApplicationDescription,ApplicationVersion,ApplicationAuthor,ApplicationParameters,ApplicationLog,ApplicationInstallSequence,ApplicationUninstallSequence,ApplicationDetectionSequence
    $Variable = $null
    $SupportedVariables = (($Object|gm -MemberType NoteProperty).Name)
    $Value = $null
    $ParameterCapture = $false
    $SequenceCapture = $false
    $Temp = $null
    foreach($Line in $Content){
        if($Line -match "\[(.+)\]"){
            _StoreVariable
            if($SupportedVariables -contains $Matches[1]){
                $Variable = $Matches[1]
                if($Matches[1] -eq 'ApplicationParameters'){
                    $ParameterCapture = $true
                    $Temp = @{}
                } elseif($Matches[1] -match 'Application(Install|Uninstall|Detection)Sequence'){
                    $ParameterCapture = $false
                    $SequenceCapture = $true
                    $Temp = @()
                
                } else {
                    $ParameterCapture = $false
                    $SequenceCapture = $false
                    $Temp = ""
                }
                

            }
        } else {
            if($ParameterCapture -eq $true){
                $Split = $Line -split "->"
                $Temp.Add($Split[0],$Split[1])
            } elseif($SequenceCapture -eq $true){
                if($Line -match "Type=(File|MSI(?:Install|Uninstall|Detection)|Script|Registry|WMI|UserReg),Path=([^,]+)(?:,Parameters=(.+))?"){
                    $Sequence = ""|select Type,Path,Parameters
                    $Sequence.Type = $Matches[1]
                    $Sequence.Path = $Matches[2]
                    
                   # $Matches
                    if($Matches[3] -ne $null){
                        
                        $Sequence.Parameters = $Matches[3]
                    }
                    $Temp += $Sequence
                 
                }
            
            } else {
                $Temp += $Line
            }
        }
    }
    
    _StoreVariable
   
    return $Object
}

function Log {
    param(
        $Message,
        $Level = 'Info'
    )

    $Timestamp = get-date -Format 'ddMMyyyThhmmss'
    $Line = "[$Timestamp] [$Level] $Message"
    if($Mode -match "[Uu]ninstall|[iI]nstall"){
        $Line|Out-File -FilePath $global:ApplicationInfo.ApplicationLog -Append
    }
    write-host $Line
}

function Set-ZOLMSIApplication {
    param(
        $MSI,
        $Arguments,
        $Action
    )
    $ModeArgument = $null
    if($MSI -match "^[{|\(]?[0-9A-F]{8}[-]?([0-9A-F]{4}[-]?){3}[0-9A-F]{12}[\)|}]?$"){
        $File = $MSI
    } else {
        $FileObject = get-item $MSI
        $File = $FileObject.FullName
        $Extension = $FileObject.Extension
    }
    switch($Action){
        "Install" {
            switch($Extension){
                ".msi" {$ModeArgument = "/i"}
                ".msp" {$ModeArgument = "/p"}
                default { throw "Unsupported MSI file" }
            }
        }
            
        "Uninstall" { $ModeArgument = "/x" }
      
        default { $ModeArgument = "/i" }
    }
    
    Log -Message "MSI operation with action '$Action' started with file $File and arguments '$Arguments'"
    Log -Message "MSI log start" -Level Info
    #Log -Message "Start-Process -FilePath 'msiexec.exe' -ArgumentList ""$ModeArgument $MSI /qn /norestart /l*v $($global:ApplicationInfo.ApplicationLog) $Arguments"""
    #write-warning "$ModeArgument $File /qn /norestart /l*v+ $($global:ApplicationInfo.ApplicationLog) $Arguments"
    $Return = Start-Process -PassThru -Wait -FilePath 'msiexec.exe' -ArgumentList "$ModeArgument ""$File"" /qn /norestart /l*v+ $($global:ApplicationInfo.ApplicationLog) $Arguments" -Verb runas

    Log -Message "MSI log end" -Level Info
    Log -Message "MSI operation ended with return code $($Return.ExitCode)"
    return $Return
}

function Set-ZOLEXEApplication{
    param(
        $File,
        $Arguments
    )
    $FullFile = ""
    Log -Message "EXE operation with started with file $File and arguments '$Arguments'"
   
    if(($FullFile = (get-item $File -ErrorAction SilentlyContinue).FullName) -eq $null){
        foreach($item in $env:Path.split(";")){if(test-path $item\$File){$FullFile = "$item\$File"}}
    }
    
    if($FullFile.Length -eq 0){
       
        throw "EXE not found"
        return 1
    }
    Log -Message "EXE log start" -Level Info
    try{
     
        $return = start-process -wait -PassThru -FilePath $FullFile -ArgumentList $Arguments -Verb runas
    }
    catch {
        Log "Error during EXE operation: $_"
        $return = ""|select ExitCode
        $return.ExitCode = 1
        return $return
    }
    if((Test-Path $global:LogRoot\temp.log) -or (Test-Path $global:LogRoot\temp.txt) -or (Test-Path $global:LogRoot\exeout.txt)){
        if(Test-Path $global:LogRoot\exeout.txt){
            Log -Message "EXE Output:`r`n$(get-content $global:LogRoot\exeout.txt)"
        }
        Rename-Item -Path $global:LogRoot\temp.txt -NewName temp.log -ErrorAction SilentlyContinue
        Log -Message "Found log file, merging it here:`r`n$(get-content $global:LogRoot\temp.log)"
        Remove-Item $global:LogRoot\temp.log -Force
    }
    Log -Message "EXE log end" -Level Info
    Log -Message "EXE operation ended with return code $($return.ExitCode)"
    return $return
}
function Get-ZOLMSIDatabase {
    param(
        $MSI
    )

    $File = get-item $MSI
    $MSIFullName = $File.FullName
    $PropertyHash = @{}
    $WindowsInstaller = New-Object -com WindowsInstaller.Installer
    $Database = $WindowsInstaller.GetType().InvokeMember(“OpenDatabase”, “InvokeMethod”, $Null, $WindowsInstaller, @($MSIFullName,0))
    $View = $Database.GetType().InvokeMember(“OpenView”, “InvokeMethod”, $Null, $Database, (“SELECT * FROM Property”))
    $View.GetType().InvokeMember(“Execute”, “InvokeMethod”, $Null, $View, $Null)

    $Record = $View.GetType().InvokeMember(“Fetch”, “InvokeMethod”, $Null, $View, $Null)

    while($Record -ne $Null)
    {
        $PropertyName = $Record.GetType().InvokeMember(“StringData”, “GetProperty”, $Null, $Record, 1)
      #  if (-not ($PropertyName -cmatch “[a-z]”))
      #  {
            $PropertyValue = $Record.GetType().InvokeMember(“StringData”, “GetProperty”, $Null, $Record, 2)
            $PropertyHash.Add($PropertyName,$PropertyValue);
           # Write-Host ($PropertyName + ” = ” + $PropertyValue)
      #  }
        $Record = $View.GetType().InvokeMember(“Fetch”, “InvokeMethod”, $Null, $View, $Null)
    }

    return $PropertyHash

}

function Get-ZOLMSIProductInfo {
    param($MSI)

    $Data = Get-ZOLMSIDatabase -MSI $MSI
    $Data = $Data[1]
    $Object = ""|select MSICode,MSIVersion,MSICPU,MSIName

    $Object.MSICode = $Data["ProductCode"]
    $Object.MSIVersion = $Data["ProductVersion"]
    $Object.MSICPU = $Data["ProductCPU"] 
    $Object.MSIName = $Data["ProductName"]

    return $Object
}

function Get-ZOLMSIInstalledProduct
{
    param(
        $Code = '*'
    )
    $installer = $null
    if(!($installer = (get-childitem HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall|where{$_.PSChildName -eq "$Code"}))){
        $installer = (get-childitem HKLM:\SOFTWARE\Wow6432node\Microsoft\Windows\CurrentVersion\Uninstall|where{$_.PSChildName -eq "$Code"})
    }
   # $return = Get-WmiObject -Query "select * from win32_product where identifyingnumber = '$Code'"
    if($installer){
        $return = ""|select MSICode,MSIVersion,MSICPU,MSIName
        $return.MSICode = $Code
        $return.MSIName = $installer[0].GetValue('DisplayName')
        $return.MSIVersion = $installer[0].GetValue('DisplayVersion')
    } else {$return = $null}
    return $return
}

function Get-ZOLMSIInstalledPatch
{
    param(
        $Code = '%'
    )

    $return = Get-WmiObject -Query "select * from win32_quickfixengineering where HotFixID like '$Code'"

    return $return
}













function Detection {
    if($global:ApplicationInfo.ApplicationDetectionSequence.count -eq 0){
        Log -Message "No detection sequence found"
        if($Action -eq 'Install'){
            return $false
        } else {
            return $true
        }
    }
    $Found = $true;
    $i = 1;
    $count = $global:ApplicationInfo.ApplicationDetectionSequence.Count
    foreach($Sequence in $global:ApplicationInfo.ApplicationDetectionSequence){
        Log -Message "Executing detection sequence $i of $count : $($Sequence|ConvertTo-Csv -NoTypeInformation)"
       
        if($Sequence.Type -match "MSIDetection"){
            $Code = ""
            $Info = $null
            
            if($Sequence.Path -match "^[{|\(]?[0-9A-F]{8}[-]?([0-9A-F]{4}[-]?){3}[0-9A-F]{12}[\)|}]?$"){
                $Code = $Sequence.Path
                if($Sequence.Parameters -match "Version=([^ ]+)"){
                    $Info = ""|select MSIVersion,MSICode
                    $Info.MSIVersion = $Matches[1]
                    $Info.MSICode = $Code
                }
            } else {
                $Info = Get-ZOLMSIProductInfo -MSI $Sequence.Path
                $Code = $Info.MSICode
            } 
            
            $Install = Get-ZOLMSIInstalledProduct -Code $Code 
            if($Install -and (($Info -eq $null) -or ($Install.MSIVersion -eq $Info.MSIVersion))){
                Log -Message "Product '$($Install.MSIName)' found"
                Log -Message "Sequence $i : OK"
                
            }
            else { Log -Message "Sequence $i : NOK";$Found = $false }
        }

        if($Sequence.Type -match "WMI"){
            $result = Get-WmiObject -Query $Sequence.Path
            if($result){
                Log -Message "Sequence $i : OK"
                
            }
            else { Log -Message "Sequence $i : NOK";$Found = $false }
        }
         if($Sequence.Type -match "Registry"){
            New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT -ErrorAction SilentlyContinue|out-null
            $key = (get-item -Path $Sequence.Path -ErrorAction SilentlyContinue)
            if(!$key){
                $key = (get-item -Path $Sequence.Path.Replace("HKLM:\SOFTWARE\","HKLM:\SOFTWARE\Wow6432Node\") -ErrorAction SilentlyContinue)
            }
            $value = $false
            $result = $false;
            if($Sequence.Parameters -match "(.+):(.+)"){
                try{
                    if($key.getvalue($Matches[1]) -eq $Matches[2]){
                        $value = $true
                    }
                }
                catch {
                    $value = $false
                }
            } else {if($key){$value = $true} else {$value -= $false}}
           
            if($value){
                Log -Message "Sequence $i : OK"
                
            }
            else { Log -Message "Sequence $i : NOK";$Found = $false }
        }

         if($Sequence.Type -match "File"){
            $result = Get-Item $Sequence.Path -ErrorAction SilentlyContinue
            if($result){
                Log -Message "Sequence $i : OK"
                
            }
            else { Log -Message "Sequence $i : NOK";$Found = $false }
        }

        $i++
    }

    return $Found

}
function Install {
    $Detect = Detection
    $exitcode = 0
    $returns = @()
    Log -Message "Detect: $Detect"
    if($Detect -eq $false -or $Force){
                Start-ZOLApplicationOperation
                $i = 1;
                $count = $global:ApplicationInfo.ApplicationInstallSequence.Count
                foreach($Sequence in $global:ApplicationInfo.ApplicationInstallSequence){
                    $Return = "";
                    Log -Message "Executing install sequence $i of $count : $($Sequence|ConvertTo-Csv -NoTypeInformation)"
                    if($Sequence.Type -match "MSI(.+)"){
                        $Return = Set-ZOLMSIApplication -MSI $Sequence.Path -Arguments $Sequence.Parameters -Action $Matches[1]
                        $Return = $Return.ExitCode
                        $returns += $Return
                    } elseif($Sequence.Type -match "File"){
                        #write-host "$Return = Set-ZOLEXEApplication -File $Sequence.Path -Arguments $Sequence.Parameters"
                        $Return = Set-ZOLEXEApplication -File $Sequence.Path -Arguments $Sequence.Parameters
                        $Return = $Return.ExitCode
                        $returns += $Return
                    } elseif($Sequence.Type -match "UserReg"){
                        $Return = 0
                        $ErrorActionPreference = "Continue"
                        try {
                        if($Sequence.Path -match "hkcu\:\\(.+)"){
                            $regpath = $Matches[1]
                            if($Sequence.Parameters -match "Type\:(String|DWord|ExpandString|Binary|MultiString),Name\:([^,]+),Value\:(.+)"){
                                $Type=$Matches[1]
                                $Name=$Matches[2]
                                $Value=$Matches[3]
                                Log -Message "Adding regkey for all users: Path=$regpath,Type=$Type,Name=$Name,Value=$Value"
                                Set-RegistryValueForAllUsers -RegistryInstance @{'Name' = "$Name"; 'Type' = "$Type"; 'Value' = "$Value"; 'Path' = $regpath}
                            } else { throw "Format Error 1"}
                        } else { throw "Format Error 2"}
                        $ErrorActionPreference = "Stop"

                        } catch { Log -Message $_; $Return = 1 } finally { $returns += $Return }
                        
                    }
                    Log -Message "Sequence $i ended with return code $($Return)"
                    $i++
                }
                log -Message "Publishing shortcuts"
                $shortcuts = get-childitem -Path ".\desktop" -Include @("*.lnk","*.url") -Recurse -ErrorAction SilentlyContinue
                        foreach($shortcut in $shortcuts){
                            $Return = Set-ZOLEXEApplication -File "powershell.exe" -Arguments "-command ""copy-item '$($shortcut.fullname)' 'C:\Users\Public\Desktop\' -force""" 
                            $Return = $Return.ExitCode
                            $returns += $Return
                        }
                if(($reboot = $global:ApplicationInfo.ApplicationParameters["Reboot"]) -ne $null){
                    if($reboot -eq 1){
                        log -Message "Reboot parameter set, returning 'reboot required' status"
                        $returns += 3010
                    }
                }
                foreach($item in $returns){
                    if($item -notmatch("0|1641")){
                        log -Message "Error $item occured during the installation of this application"
                        $exitcode = $item
                        break;
                    } elseif($item -match ("3010")){
                        log -Message "Pending reboot detected"
                        $exitcode = 3010
                    } else {$exitcode = 0}
                }
                log -Message "Final Exit Code: $exitcode"        
                Stop-ZOLApplicationOperation
                return $exitcode
            } else {log -Message "Application already installed" }


}

function Uninstall {
    $Detect = Detection
    $exitcode = 0
    $returns = @()
    if($Detect -ne $false -or $Force){
        Start-ZOLApplicationOperation
        $i = 1;
        $count = $global:ApplicationInfo.ApplicationUnInstallSequence.Count
        foreach($Sequence in $global:ApplicationInfo.ApplicationUnInstallSequence){
            Log -Message "Executing sequence $i of $count : $($Sequence|ConvertTo-Csv -NoTypeInformation)"
            if($Sequence.Type -match "MSI(.+)"){
                $Return = Set-ZOLMSIApplication -MSI $Sequence.Path -Arguments $Sequence.Parameters -Action $Matches[1]
                $Return = $Return.ExitCode
                $returns += $Return
            }
              elseif($Sequence.Type -match "File"){
                      
                        $Return = Set-ZOLEXEApplication -File $Sequence.Path -Arguments $Sequence.Parameters
                        $Return = $Return.ExitCode
                        $returns += $Return
            } 
            Log -Message "Sequence $i ended with return code $($Return)"
            $i++
        }
        log -Message "Removing shortcuts"
                $shortcuts = get-childitem -Path ".\desktop" -Include @("*.lnk","*.url") -Recurse -ErrorAction SilentlyContinue
                        foreach($shortcut in $shortcuts){
                            $Return = Set-ZOLEXEApplication -File "powershell.exe" -Arguments "-command ""remove-item 'C:\Users\Public\Desktop\$($shortcut.name)' -force""" 
                            $Return = $Return.ExitCode
                            $returns += $Return
                        }
         if(($reboot = $global:ApplicationInfo.ApplicationParameters["Reboot"]) -ne $null){
                    if($reboot -eq 1){
                        log -Message "Reboot parameter set, returning 'reboot required' status"
                        $returns += 3010
                    }
                }
                foreach($item in $returns){
                    if($item -notmatch("0|1641")){
                        log -Message "Error $item occured during the installation of this application"
                        $exitcode = $item
                        break;
                    } elseif($item -match ("3010")){
                        log -Message "Pending reboot detected"
                        $exitcode = 3010
                    } else {$exitcode = 0}
                }
                log -Message "Final Exit Code: $exitcode"  
        Stop-ZOLApplicationOperation
    } else {log -Message "Application not installed" }



}

function Set-RegistryValueForAllUsers {
    <#
	.SYNOPSIS
		This function uses Active Setup to create a "seeder" key which creates or modifies a user-based registry value
		for all users on a computer. If the key path doesn't exist to the value, it will automatically create the key and add the value.
	.EXAMPLE
		PS> Set-RegistryValueForAllUsers -RegistryInstance @{'Name' = 'Setting'; 'Type' = 'String'; 'Value' = 'someval'; 'Path' = 'SOFTWARE\Microsoft\Windows\Something'}
	
		This example would modify the string registry value 'Type' in the path 'SOFTWARE\Microsoft\Windows\Something' to 'someval'
		for every user registry hive.
	.PARAMETER RegistryInstance
	 	A hash table containing key names of 'Name' designating the registry value name, 'Type' to designate the type
		of registry value which can be 'String,Binary,Dword,ExpandString or MultiString', 'Value' which is the value itself of the
		registry value and 'Path' designating the parent registry key the registry value is in.
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory=$true)]
		[hashtable[]]$RegistryInstance
	)
	try {
		New-PSDrive -Name HKU -PSProvider Registry -Root Registry::HKEY_USERS | Out-Null
		
		## Change the registry values for the currently logged on user. Each logged on user SID is under HKEY_USERS
		$LoggedOnSids = (Get-ChildItem HKU: | where { $_.Name -match 'S-\d-\d+-(\d+-){1,14}\d+$' }).PSChildName
		Write-Verbose "Found $($LoggedOnSids.Count) logged on user SIDs"
		foreach ($sid in $LoggedOnSids) {
			Write-Verbose -Message "Loading the user registry hive for the logged on SID $sid"
			foreach ($instance in $RegistryInstance) {
				## Create the key path if it doesn't exist
				New-Item -Path "HKU:\$sid\$($instance.Path | Split-Path -Parent)" -Name ($instance.Path | Split-Path -Leaf) -Force | Out-Null
				## Create (or modify) the value specified in the param
				Set-ItemProperty -Path "HKU:\$sid\$($instance.Path)" -Name $instance.Name -Value $instance.Value -Type $instance.Type -Force
			}
		}
		
		## Create the Active Setup registry key so that the reg add cmd will get ran for each user
		## logging into the machine.
		## http://www.itninja.com/blog/view/an-active-setup-primer
		Write-Verbose "Setting Active Setup registry value to apply to all other users"
		foreach ($instance in $RegistryInstance) {
			## Generate a unique value (usually a GUID) to use for Active Setup
			$Guid = [guid]::NewGuid().Guid
			$ActiveSetupRegParentPath = 'HKLM:\Software\Microsoft\Active Setup\Installed Components'
			## Create the GUID registry key under the Active Setup key
			New-Item -Path $ActiveSetupRegParentPath -Name $Guid -Force | Out-Null
			$ActiveSetupRegPath = "HKLM:\Software\Microsoft\Active Setup\Installed Components\$Guid"
			Write-Verbose "Using registry path '$ActiveSetupRegPath'"
			
			## Convert the registry value type to one that reg.exe can understand.  This will be the
			## type of value that's created for the value we want to set for all users
			switch ($instance.Type) {
				'String' {
					$RegValueType = 'REG_SZ'
				}
				'Dword' {
					$RegValueType = 'REG_DWORD'
				}
				'Binary' {
					$RegValueType = 'REG_BINARY'
				}
				'ExpandString' {
					$RegValueType = 'REG_EXPAND_SZ'
				}
				'MultiString' {
					$RegValueType = 'REG_MULTI_SZ'
				}
				default {
					throw "Registry type '$($instance.Type)' not recognized"
				}
			}
			
			## Build the registry value to use for Active Setup which is the command to create the registry value in all user hives
			$ActiveSetupValue = "reg add `"{0}`" /v {1} /t {2} /d {3} /f" -f "HKCU\$($instance.Path)", $instance.Name, $RegValueType, $instance.Value
			Write-Verbose -Message "Active setup value is '$ActiveSetupValue'"
			## Create the necessary Active Setup registry values
			Set-ItemProperty -Path $ActiveSetupRegPath -Name '(Default)' -Value 'Active Setup Test' -Force
			Set-ItemProperty -Path $ActiveSetupRegPath -Name 'Version' -Value '1' -Force
			Set-ItemProperty -Path $ActiveSetupRegPath -Name 'StubPath' -Value $ActiveSetupValue -Force
		}
	} catch {
		Write-Warning -Message $_.Exception.Message
	}
}
function Get-Admin(){
    # Get the ID and security principal of the current user account
     $myWindowsID=[System.Security.Principal.WindowsIdentity]::GetCurrent()
     $myWindowsPrincipal=new-object System.Security.Principal.WindowsPrincipal($myWindowsID)
  
     # Get the security principal for the Administrator role
     $adminRole=[System.Security.Principal.WindowsBuiltInRole]::Administrator
  
     # Check to see if we are currently running "as Administrator"
     if ($myWindowsPrincipal.IsInRole($adminRole))
        {
        # We are running "as Administrator" - so change the title and background color to indicate this
        #$Host.UI.RawUI.WindowTitle = $myInvocation.MyCommand.Definition + "(Elevated)"
        #$Host.UI.RawUI.BackgroundColor = "DarkBlue"
        #clear-host
        }
     else
        {
        # We are not running "as Administrator" - so relaunch as administrator
    
        # Create a new process object that starts PowerShell
        $newProcess = new-object System.Diagnostics.ProcessStartInfo "PowerShell";
    
        # Specify the current script path and name as a parameter
        $newProcess.Arguments = "-file $myInvocation.MyCommand.Definition"
    
        # Indicate that the process should be elevated
        $newProcess.Verb = "runas";
    
        # Start the new process
        [System.Diagnostics.Process]::Start($newProcess);
    
        # Exit from the current, unelevated, process
        exit
        }
}


#Get-Admin
Start-ZOLApplicationFramework
switch($Action){
    "Install"{
        Install
    }
    "Uninstall" {
       Uninstall
    }
    "Detection"{
        return Detection
    }

    "Generate-SCCM" {
    }
}
            