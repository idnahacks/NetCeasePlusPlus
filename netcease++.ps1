function Get-SessRegkey {
    <#
    .DESCRIPTION
        Gets the current settings from the local registry and returns them as a Security Descriptor Object
    #>
    $key = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity"
    $name = "SrvsvcSessionInfo"
    $regKey = Get-Item -Path $key 
    $srvSvcSessionInfo = $regKey.GetValue($name, $null)
    $script:csd = New-Object -TypeName System.Security.AccessControl.CommonSecurityDescriptor -ArgumentList $true,$false, $srvSvcSessionInfo,0
}

function Get-SessRawvalue {
    <#
    .DESCRIPTION
        Function to read in data copied from the GPO value and returns it as a Security Descriptor Object
    #>
    param (
        [Parameter(Mandatory, HelpMessage = "Enter the raw string from the GPO GUI")]
        [string]
        $rawdata
    )
    $splitdata = $rawdata -split '(..)' -ne ''
    $decarray = @()
    foreach ($value in $splitdata) {
    $decvalue = [convert]::ToInt32($value, 16);
    $decarray += $decvalue

    }
    $srvSvcSessionInfo = [byte[]]$decarray
    $script:csd = New-Object -TypeName System.Security.AccessControl.CommonSecurityDescriptor -ArgumentList $true,$false, $srvSvcSessionInfo,0
}

function Get-SessionEnumPermissions {
    <#
    .DESCRIPTION
        Displays the current permissions, either from a raw hex string taken from the GPO Management GUI or from the local registry.
    #>
    param (
        [Parameter(HelpMessage = "Enter the raw string from the GPO GUI")]
        [string]
        $rawdata,
        [Parameter(HelpMessage = "Gets the settings from the local registry")]
        [switch]
        $fromreg
    )
    if ($rawdata) {
        
        Get-SessRawvalue -rawdata $rawdata
    }
    else {
        Get-SessRegkey
    }
    $csd | select -ExpandProperty DiscretionaryAcl | ForEach-Object { $_ | Add-Member -MemberType ScriptProperty -Name TranslatedSID -Value ({$this.SecurityIdentifier.Translate([System.Security.Principal.NTAccount]).Value}) -PassThru}
}

function Set-DefaultNetCeasePermissions {
    <#
    .DESCRIPTION
        Sets the default hardened Session Enumeration permissions as set in the original NetCease script and either outputs the hex string to set by GPO, or sets directly in the local registry.
    #>
    param (
        [Parameter(HelpMessage = "Sets the new permissions in the local registry (requires Powershell to be running as Administrator)")]
        [switch]
        $toreg
    )
    Get-SessRawvalue -rawdata 010004801400000020000000000000002c00000001010000000000051200000001010000000000051200000002008c000600000000001400ff011f0001010000000000050300000000001400ff011f0001010000000000050400000000001400ff011f000101000000000005060000000000180013000f00010200000000000520000000200200000000180013000f00010200000000000520000000230200000000180013000f0001020000000000052000000025020000
    $SRVSVC_SESSION_USER_INFO_GET = 0x00000001
    $data = New-Object -TypeName System.Byte[] -ArgumentList $csd.BinaryLength
    $csd.GetBinaryForm($data,0)
    if ($toreg) {
        $key = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity"
        $name = "SrvsvcSessionInfo"
        Set-ItemProperty -Path $key -Name $name -Value $data
    }
    else {
        $hexarray = @()
        foreach ($d in $data) {
        $h = '{0:x2}' -f $d
        $hexarray += $h
        }
        $hexstring = $hexarray -join ''
        $hexstring
    }
}

function Add-SessionEnumUser {
    <#
    .DESCRIPTION
        Add a user or group to the Allowed Session Enumeration Permissions and either outputs the hex string to set by GPO, or sets directly in the local registry.
    #>
    param (
        [Parameter(Mandatory, HelpMessage = "The user or group to add, in the format domain\user or domain\group")]
        [string]
        $user,
        [Parameter(HelpMessage = "Sets the new permissions in the local registry (requires Powershell to be running as Administrator)")]
        [switch]
        $toreg,
        [Parameter(HelpMessage = "Reads the settings from the local registry")]
        [switch]
        $fromreg,
        [Parameter(HelpMessage = "Enter the raw string from the GPO GUI")]
        [string]
        $rawdata
    )
        if ($fromreg) {
            Get-SessRegkey -ErrorAction STOP
        }
        else {
            try {
                Get-SessRawvalue -rawdata $rawdata -ErrorAction STOP
                }
            catch [System.Management.Automation.ParameterBindingException]{
                Write-Error "Either rawdata or fromreg must be selected as the input" -ErrorAction STOP
            }
            catch {
                Write-Error $PSItem.Exception.Message -ErrorAction STOP
            }
        }
    

    $SRVSVC_SESSION_USER_INFO_GET = 0x00000001
    $ntuser = New-Object System.Security.Principal.NTAccount($user)
    $sid = $ntuser.Translate([System.Security.Principal.SecurityIdentifier])
    $csd.DiscretionaryAcl.AddAccess([System.Security.AccessControl.AccessControlType]::Allow, $sid, $SRVSVC_SESSION_USER_INFO_GET,0,0)
    $data = New-Object -TypeName System.Byte[] -ArgumentList $csd.BinaryLength
    $csd.GetBinaryForm($data,0)
    if ($toreg) {
        $key = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity"
        $name = "SrvsvcSessionInfo"
        Set-ItemProperty -Path $key -Name $name -Value $data
    }
    else {
        $hexarray = @()
        foreach ($d in $data) {
        $h = '{0:x2}' -f $d
        $hexarray += $h
        }
        $hexstring = $hexarray -join ''
        $hexstring
    }
}

function Remove-SessionEnumUser {
    <#
    .DESCRIPTION
        Removes a user or group to the Allowed Session Enumeration Permissions
    #>
    param (
        [Parameter(Mandatory, HelpMessage = "The user or group to remove, in the format domain\user or domain\group")]
        [string]
        $user,
        [Parameter(HelpMessage = "Sets the new permissions in the local registry (requires Powershell to be running as Administrator)")]
        [switch]
        $toreg,
        [Parameter(HelpMessage = "Reads the settings from the local registry")]
        [switch]
        $fromreg,
        [Parameter(HelpMessage = "Enter the raw string from the GPO GUI")]
        [string]
        $rawdata
    )
    if ($fromreg) {
        Get-SessRegkey -ErrorAction STOP
    }
    else {
        try {
            Get-SessRawvalue -rawdata $rawdata -ErrorAction STOP
            }
        catch [System.Management.Automation.ParameterBindingException]{
            Write-Error "Either rawdata or fromreg must be selected as the input" -ErrorAction STOP
        }
        catch {
            Write-Error $PSItem.Exception.Message -ErrorAction STOP
        }
    }
    $SRVSVC_SESSION_USER_INFO_GET = 0x00000001
    $ntuser = New-Object System.Security.Principal.NTAccount($user)
    $sid = $ntuser.Translate([System.Security.Principal.SecurityIdentifier])
    $csd.DiscretionaryAcl.RemoveAccess([System.Security.AccessControl.AccessControlType]::Allow, $sid, $SRVSVC_SESSION_USER_INFO_GET,0,0)
    $data = New-Object -TypeName System.Byte[] -ArgumentList $csd.BinaryLength
    $csd.GetBinaryForm($data,0)
    if ($toreg) {
        $key = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity"
        $name = "SrvsvcSessionInfo"
        Set-ItemProperty -Path $key -Name $name -Value $data
    }
    else {
        $hexarray = @()
        foreach ($d in $data) {
        $h = '{0:x2}' -f $d
        $hexarray += $h
        }
        $hexstring = $hexarray -join ''
        $hexstring
    }
}

function Get-RemoteSAMPermissions {
    param (
        [Parameter(HelpMessage = "Reads the settings from the local registry")]
        [switch]
        $fromreg,
        [Parameter(HelpMessage = "Enter the raw string from the GPO GUI")]
        [string]
        $rawdata
    )
    if ($fromreg) {
        Get-SamRegKey
        Write-Host "`n`nYour local RemoteSAM permissions in the local registry are:`n"
        ConvertFrom-SddlString -sddl $restrictremotesam | select -ExpandProperty DiscretionaryAcl
        Write-Host "`n`nThis translates to an SDDL of:`n"
        $restrictremotesam
    }
    else {
        try{
            ConvertFrom-SddlString -sddl $rawdata | select -ExpandProperty DiscretionaryAcl
        }
        catch [System.Management.Automation.ParameterBindingException]{
            Write-Error "Either rawdata or fromreg must be selected as the input" -ErrorAction STOP
        }
        catch {
            Write-Error $PSItem.Exception.Message -ErrorAction STOP
        }
    }
}

function Get-SamRegKey {
    $key = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    $name = "RestrictRemoteSAM"
    $regKey = Get-Item -Path $key
    $script:restrictremotesam = $regKey.GetValue($name, $null)
}

function Add-RemoteSAMUser {
    <#
    .DESCRIPTION
        Add a user or group to the Remote SAM Enumeration Permissions and either outputs the SDDL string to set by GPO, or sets directly in the local registry.
    #>
    param (
        [Parameter(Mandatory, HelpMessage = "The user or group to add, in the format domain\user or domain\group")]
        [string]
        $user,
        [Parameter(HelpMessage = "Sets the new permissions in the local registry (requires Powershell to be running as Administrator)")]
        [switch]
        $toreg,
        [Parameter(HelpMessage = "Reads the settings from the local registry")]
        [switch]
        $fromreg,
        [Parameter(HelpMessage = "Enter the raw SDDL string from the GPO GUI")]
        [string]
        $rawdata
    )
    $remoteAccess = 0x00020000
    $ntuser = New-Object System.Security.Principal.NTAccount($user)
    $sid = $ntuser.Translate([System.Security.Principal.SecurityIdentifier])
    if ($fromreg) {
        Get-SamRegKey
        $rsd = New-Object -TypeName System.Security.AccessControl.RawSecurityDescriptor -ArgumentList $restrictremotesam
    }
    else {
        $rsd = New-Object -TypeName System.Security.AccessControl.RawSecurityDescriptor -ArgumentList $rawdata
    }
        foreach ($ace in $rsd.DiscretionaryAcl)
        {
            if (($ace.SecurityIdentifier.CompareTo($sid.value) -eq 0) -and $ace.AceType -eq [System.Security.AccessControl.AceType]::AccessAllowed)
            {
                Write-Host "`n$($user) already has permissions.`n"
                return
            }
        }
    $commonAce = New-Object -TypeName System.Security.AccessControl.CommonAce -ArgumentList 0, 0, $remoteAccess, $sid,$false, $null
    $rsd.DiscretionaryAcl.InsertAce(0, $commonAce)
    $newsddl = $rsd.GetSddlForm([System.Security.AccessControl.AccessControlSections]::All)
    if ($toreg) {
        $key = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        $name = "RestrictRemoteSAM"
        Set-ItemProperty -Path $key -Name $name -Value $newsddl
    }
    else {
        Write-Host "`n`nYour new SDDL to be deployed by GPO is`n$($newsddl)`n`n"
        Write-Host "This translates to the following ACL:`n"
        ConvertFrom-SddlString -sddl $newsddl | select -ExpandProperty DiscretionaryAcl
    }
}

function Remove-RemoteSAMUser {
    <#
    .DESCRIPTION
        Removes a user or group from the Remote SAM Enumeration Permissions and either outputs the SDDL string to set by GPO, or sets directly in the local registry.
    #>
    param (
        [Parameter(Mandatory, HelpMessage = "The user or group to remove, in the format domain\user or domain\group")]
        [string]
        $user,
        [Parameter(HelpMessage = "Sets the new permissions in the local registry (requires Powershell to be running as Administrator)")]
        [switch]
        $toreg,
        [Parameter(HelpMessage = "Reads the settings from the local registry")]
        [switch]
        $fromreg,
        [Parameter(HelpMessage = "Enter the raw SDDL string from the GPO GUI")]
        [string]
        $rawdata
    )
    $remoteAccess = 0x00020000
    $ntuser = New-Object System.Security.Principal.NTAccount($user)
    $sid = $ntuser.Translate([System.Security.Principal.SecurityIdentifier])
    if ($fromreg) {
        Get-SamRegKey
        $rsd = New-Object -TypeName System.Security.AccessControl.RawSecurityDescriptor -ArgumentList $restrictremotesam
    }
    else {
        $rsd = New-Object -TypeName System.Security.AccessControl.RawSecurityDescriptor -ArgumentList $rawdata
    }
    if (($sid.Value -in $rsd.DiscretionaryAcl.SecurityIdentifier.value) -eq $true) {
        $aclindex = [array]::indexof($rsd.DiscretionaryAcl.securityidentifier.value,$sid.Value)
        $rsd.DiscretionaryAcl.RemoveAce($aclindex)
        $newsddl = $rsd.GetSddlForm([System.Security.AccessControl.AccessControlSections]::All)
        if ($toreg) {
            $key = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
            $name = "RestrictRemoteSAM"
            Set-ItemProperty -Path $key -Name $name -Value $newsddl
        }
        else {
            Write-Host "`n`nYour new SDDL to be deployed by GPO is`n$($newsddl)`n`n"
            Write-Host "This translates to the following ACL:`n"
            ConvertFrom-SddlString -sddl $newsddl | select -ExpandProperty DiscretionaryAcl
        }
    }
    else {
        Write-Host "`n$($user) does not have RemoteSAM permissions.`n"
    }
}