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
    if ($fromreg) {
        Get-SessRegkey
    }
    else {
        Get-SessRawvalue -rawdata $rawdata
    }
    $csd | select -ExpandProperty DiscretionaryAcl | ForEach-Object { $_ | Add-Member -MemberType ScriptProperty -Name TranslatedSID -Value ({$this.SecurityIdentifier.Translate([System.Security.Principal.NTAccount]).Value}) -PassThru}
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
        Get-SessRegkey
    }
    else {
        Get-SessRawvalue -rawdata $rawdata
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
        ConvertFrom-SddlString -sddl $restrictremotesam | select -ExpandProperty DiscretionaryAcl
    }
    else {
        ConvertFrom-SddlString -sddl $rawdata | select -ExpandProperty DiscretionaryAcl
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
        Write-Host "`n`nYour new SDDL is `n$($newsddl)`n`n"
        Write-Host "This translates to the following ACL:`n"
        ConvertFrom-SddlString -sddl $newsddl | select -ExpandProperty DiscretionaryAcl
    }
}