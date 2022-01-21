function Get-SessRegkey {
    $key = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity"
    $name = "SrvsvcSessionInfo"
    $regKey = Get-Item -Path $key 
    $srvSvcSessionInfo = $regKey.GetValue($name, $null)
    $script:csd = New-Object -TypeName System.Security.AccessControl.CommonSecurityDescriptor -ArgumentList $true,$false, $srvSvcSessionInfo,0
}

function Get-SessRawvalue {

    param (
        [Parameter(Mandatory, HelpMessage = "Enter the raw string from the GPO GUI")]
        [string]
        $gpostring
    )
    $splitdata = $gpostring -split '(..)' -ne ''
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
    .SYNOPSIS
    Gets the Session Enumeration permissions from the local registry or from a user provided hex string.
    .DESCRIPTION
    Function to read in user provided hex string copied from the GPO value, or from the local registry and returns it as a Security Descriptor Object.
    .PARAMETER fromreg
    Specifies that the settings from the local registry should be displayed. This is the default behaviour and so this parameter is not required to be stated.
    .PARAMETER gpostring
    Used to enter a hex string taken from the GPO setting relating to Session Enumeration permissions. The function will translate this into a Security Descriptor Object.

    .EXAMPLE
    PS> Get-SessionEnumPermissions -fromreg | Format-Table
    TranslatedSID                         BinaryLength  AceQualifier IsCallback OpaqueLength AccessMask SecurityIdentifier                                    AceType AceFlags IsInherited
    -------------                         ------------  ------------ ---------- ------------ ---------- ------------------                                    ------- -------- -----------
    NT AUTHORITY\BATCH                              20 AccessAllowed      False            0    2032127 S-1-5-3                                         AccessAllowed     None       False
    NT AUTHORITY\INTERACTIVE                        20 AccessAllowed      False            0    2032127 S-1-5-4                                         AccessAllowed     None       False
    NT AUTHORITY\SERVICE                            20 AccessAllowed      False            0    2032127 S-1-5-6                                         AccessAllowed     None       False
    BUILTIN\Administrators                          24 AccessAllowed      False            0     983059 S-1-5-32-544                                    AccessAllowed     None       False
    BUILTIN\Power Users                             24 AccessAllowed      False            0     983059 S-1-5-32-547                                    AccessAllowed     None       False
    BUILTIN\Server Operators                        24 AccessAllowed      False            0     983059 S-1-5-32-549                                    AccessAllowed     None       False
    
    .EXAMPLE
    Take the hex string set in the Group Policy Object that is currently applied (if applicable) and see the settings that this translates to

    PS> Get-SessionEnumPermissions -gpostring "010004801400000020000000000000002c00000001010000000000051200000001010000000000051200000002008c000600000000001400ff011f0001010000000000050300000000001400ff011f0001010000000000050400000000001400ff011f000101000000000005060000000000180013000f00010200000000000520000000200200000000180013000f00010200000000000520000000230200000000180013000f0001020000000000052000000025020000" | Format-Table
    
    TranslatedSID                         BinaryLength  AceQualifier IsCallback OpaqueLength AccessMask SecurityIdentifier                                    AceType AceFlags IsInherited
    -------------                         ------------  ------------ ---------- ------------ ---------- ------------------                                    ------- -------- -----------
    NT AUTHORITY\BATCH                              20 AccessAllowed      False            0    2032127 S-1-5-3                                         AccessAllowed     None       False
    NT AUTHORITY\INTERACTIVE                        20 AccessAllowed      False            0    2032127 S-1-5-4                                         AccessAllowed     None       False
    NT AUTHORITY\SERVICE                            20 AccessAllowed      False            0    2032127 S-1-5-6                                         AccessAllowed     None       False
    BUILTIN\Administrators                          24 AccessAllowed      False            0     983059 S-1-5-32-544                                    AccessAllowed     None       False
    BUILTIN\Power Users                             24 AccessAllowed      False            0     983059 S-1-5-32-547                                    AccessAllowed     None       False
    BUILTIN\Server Operators                        24 AccessAllowed      False            0     983059 S-1-5-32-549                                    AccessAllowed     None       False

    .LINK
    https://github.com/idnahacks/NetCeasePlusPlus
    #>
    param (
        [Parameter(HelpMessage = "Enter the raw string from the GPO GUI")]
        [string]
        $gpostring,
        [Parameter(HelpMessage = "Gets the settings from the local registry")]
        [switch]
        $fromreg
    )
    if ($gpostring) {
        
        Get-SessRawvalue -gpostring $gpostring
    }
    else {
        Get-SessRegkey
    }
    $csd | select -ExpandProperty DiscretionaryAcl | ForEach-Object { $_ | Add-Member -MemberType ScriptProperty -Name TranslatedSID -Value ({$this.SecurityIdentifier.Translate([System.Security.Principal.NTAccount]).Value}) -PassThru}
}

function Set-DefaultNetCeasePermissions {
    <#
    .SYNOPSIS
    Sets the hardened Session Enumeration permissions as described in the original NetCease script.
    .DESCRIPTION
    Sets the hardened Session Enumeration permissions as described in the original NetCease script.
    By default this is output as a hex string to be deployed by GPO, or with the -toreg parameter is set in the local registry.
    The lanmanserver service needs to be restarted in order for the new settings to take effect.
    .PARAMETER toreg
    Set the hardened Session Enumeration permissions in the local registry. Requires Powershell to be running as an Administrator.
    .EXAMPLE
    PS> Set-DefaultNetCeasePermissions
    010004801400000020000000000000002c00000001010000000000051200000001010000000000051200000002008c000600000000001400ff011f0001010000000000050300000000001400ff011f0001010000000000050400000000001400ff011f000101000000000005060000000000180013000f00010200000000000520000000200200000000180013000f00010200000000000520000000230200000000180013000f0001020000000000052000000025020000
    .EXAMPLE
    PS> Set-DefaultNetCeasePermissions -toreg
    .LINK
    https://github.com/idnahacks/NetCeasePlusPlus
    #>

    param (
        [Parameter(HelpMessage = "Sets the new permissions in the local registry (requires Powershell to be running as Administrator)")]
        [switch]
        $toreg
    )
    Get-SessRawvalue -gpostring 010004801400000020000000000000002c00000001010000000000051200000001010000000000051200000002008c000600000000001400ff011f0001010000000000050300000000001400ff011f0001010000000000050400000000001400ff011f000101000000000005060000000000180013000f00010200000000000520000000200200000000180013000f00010200000000000520000000230200000000180013000f0001020000000000052000000025020000
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
    .SYNOPSIS
    Adds a user or group to the Session Enumeration permissions provided either by hex string or from the local registry.
    .DESCRIPTION
    Add a user or group to the Allowed Session Enumeration Permissionsprovided either by hex string or from the local registry.
    Outputs the hex string to set by GPO, or sets directly in the local registry.
    The lanmanserver service needs to be restarted in order for the new settings to take effect.
    .PARAMETER user
    The user or group to be added in the format domain\user or domain\group. By default the local domain will be chosen if not entered.
    .PARAMETER toreg
    Adds the user or group to the Session Enumeration permissions set in the local registry. Requires Powershell to be running as an Administrator.
    .PARAMETER fromreg
    Tells the module to read the Session Enumeration permissions from the local registry and add the new user or group to them.
    .PARAMETER gpostring
    Tells the module to use the user provided hex string taken from the GPO gui and add the new user or group to it.
    .EXAMPLE
    Looks at the local registry settings and adds the user contoso.com\user1 to them.
    PS> Add-SessionEnumUser -user "contoso.com\user1" -fromreg -toreg
    .EXAMPLE
    Looks at the local registry settings and adds the user contoso.com\user1 to them displaying the new hex string to be deployed.
    PS> Add-SessionEnumUser -user "contoso.com\user1" -fromreg
    .EXAMPLE
    Takes a hex string from the GPO GUI and adds the group contoso.com\group1 to it displaying the new hex string to be deployed.
    PS> Add-SessionEnumUser -user "contoso.com\group1" -gpostring "010004801400000020000000000000002c00000001010000000000051200000001010000000000051200000002008c000600000000001400ff011f0001010000000000050300000000001400ff011f0001010000000000050400000000001400ff011f000101000000000005060000000000180013000f00010200000000000520000000200200000000180013000f00010200000000000520000000230200000000180013000f0001020000000000052000000025020000"
    .LINK
    https://github.com/idnahacks/NetCeasePlusPlus
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
        $gpostring
    )
        if ($fromreg) {
            Get-SessRegkey -ErrorAction STOP
        }
        else {
            try {
                Get-SessRawvalue -gpostring $gpostring -ErrorAction STOP
                }
            catch [System.Management.Automation.ParameterBindingException]{
                Write-Error "Either gpostring or fromreg must be selected as the input" -ErrorAction STOP
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
    .SYNOPSIS
    Removes a user or group from the Session Enumeration permissions provided either by hex string or from the local registry.
    .DESCRIPTION
    Removes a user or group from the Allowed Session Enumeration Permissionsprovided either by hex string or from the local registry.
    Outputs the new hex string to set by GPO, or sets directly in the local registry.
    The lanmanserver service needs to be restarted in order for the new settings to take effect.
    .PARAMETER user
    The user or group to be removed in the format domain\user or domain\group. By default the local domain will be chosen if not entered.
    .PARAMETER toreg
    Removes the user or group from the Session Enumeration permissions set in the local registry. Requires Powershell to be running as an Administrator.
    .PARAMETER fromreg
    Tells the module to read the Session Enumeration permissions from the local registry and remove the new user or group from them.
    .PARAMETER gpostring
    Tells the module to use the user provided hex string taken from the GPO gui and removes the new user or group from it.
    .EXAMPLE
    Looks at the local registry settings and removes the user contoso.com\user1 from them.
    PS> Remove-SessionEnumUser -user "contoso.com\user1" -fromreg -toreg
    .EXAMPLE
    Looks at the local registry settings and removes the user contoso.com\user1 from them displaying the new hex string to be deployed.
    PS> Remove-SessionEnumUser -user "contoso.com\user1" -fromreg
    .EXAMPLE
    Takes a hex string from the GPO GUI and removes the group contoso.com\group1 from it displaying the new hex string to be deployed.
    PS> Remove-SessionEnumUser -user "contoso.com\group1" -gpostring "010004801400000020000000000000002c00000001010000000000051200000001010000000000051200000002008c000600000000001400ff011f0001010000000000050300000000001400ff011f0001010000000000050400000000001400ff011f000101000000000005060000000000180013000f00010200000000000520000000200200000000180013000f00010200000000000520000000230200000000180013000f0001020000000000052000000025020000"
    .LINK
    https://github.com/idnahacks/NetCeasePlusPlus
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
        $gpostring
    )
    if ($fromreg) {
        Get-SessRegkey -ErrorAction STOP
    }
    else {
        try {
            Get-SessRawvalue -gpostring $gpostring -ErrorAction STOP
            }
        catch [System.Management.Automation.ParameterBindingException]{
            Write-Error "Either gpostring or fromreg must be selected as the input" -ErrorAction STOP
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
    <#
    .SYNOPSIS
    Gets the Remote SAM permissions from the local registry or from a user provided SDDL string.
    .DESCRIPTION
    Function to read in user provided SDDL string copied from the GPO value relating to Remote SAM enumeration permissions, or from the local registry and returns it as an ACL.
    .PARAMETER fromreg
    Specifies that the settings from the local registry should be displayed. This is the default behaviour and so this parameter is not required to be stated.
    .PARAMETER gpostring
    Used to enter an SDDL string taken from the GPO setting relating to Remote SAM enumeration permissions. The function will translate this into an ACL.
    .EXAMPLE
    Gets the Remote SAM permissions from the local registry.
    PS> Get-RemoteSAMPermissions
    .EXAMPLE
    Gets the Remote SAM permissions from the local registry.
    PS> Get-RemoteSAMPermissions -fromreg
    .EXAMPLE
    Gets the Remote SAM permissions from a provided SDDL string.
    Get-RemoteSAMPermissions -gpostring "O:BAG:BAD:(A;;RC;;;BA)"
    .LINK
    https://github.com/idnahacks/NetCeasePlusPlus
    #>
    param (
        [Parameter(HelpMessage = "Reads the settings from the local registry")]
        [switch]
        $fromreg,
        [Parameter(HelpMessage = "Enter the raw string from the GPO GUI")]
        [string]
        $gpostring
    )
    if ($gpostring) {
        ConvertFrom-SddlString -sddl $gpostring | select -ExpandProperty DiscretionaryAcl
    }
    else {
        Get-SamRegKey
        Write-Host "`n`nYour local RemoteSAM permissions in the local registry are:`n"
        ConvertFrom-SddlString -sddl $restrictremotesam | select -ExpandProperty DiscretionaryAcl
        Write-Host "`n`nThis translates to an SDDL of:`n"
        $restrictremotesam
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
    .SYNOPSIS
    Adds a user or group to the Remote SAM Enumeration permissions provided either by an SDDL string or from the local registry.
    .DESCRIPTION
    Add a user or group to the Remote SAM Enumeration Permissions and either outputs the SDDL string to set by GPO, or sets directly in the local registry.
    .PARAMETER user
    The user or group to be added in the format domain\user or domain\group. By default the local domain will be chosen if not entered.
    .PARAMETER toreg
    Adds the user or group to the Remote SAM Enumeration permissions set in the local registry.
    Requires Powershell to be running as an Administrator.
    .PARAMETER fromreg
    Tells the module to read the Remote SAM Enumeration permissions from the local registry and add the new user or group to them.
    .PARAMETER gpostring
    Tells the module to use the user provided SDDL string taken from the GPO gui and add the new user or group to it.
    .EXAMPLE
    Looks at the local Remote SAM Enumeration registry settings and adds the user contoso.com\user1 to them.
    PS> Add-RemoteSAMUser -user "contoso.com\user1" -fromreg -toreg
    .EXAMPLE
    Looks at the local Remote SAM Enumeration registry settings and adds the user contoso.com\user1 to them displaying the new SDDL string to be deployed.
    PS> Add-RemoteSAMUser -user "contoso.com\user1" -fromreg
    .EXAMPLE
    Takes an SDDL string provided and adds the group contoso.com\group1 to it displaying the new SDDL string to be deployed.
    PS> Add-RemoteSAMUser -user "constoso.com\group1" -gpostring "O:BAG:BAD:(A;;RC;;;BA)"
    .LINK
    https://github.com/idnahacks/NetCeasePlusPlus
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
        $gpostring
    )
    $remoteAccess = 0x00020000
    $ntuser = New-Object System.Security.Principal.NTAccount($user)
    $sid = $ntuser.Translate([System.Security.Principal.SecurityIdentifier])
    if ($gpostring) {
        $rsd = New-Object -TypeName System.Security.AccessControl.RawSecurityDescriptor -ArgumentList $gpostring
    }
    else {
        Get-SamRegKey
        $rsd = New-Object -TypeName System.Security.AccessControl.RawSecurityDescriptor -ArgumentList $restrictremotesam
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
    .SYNOPSIS
    Removes a user or group from the Remote SAM Enumeration permissions provided either by an SDDL string or from the local registry.
    .DESCRIPTION
    Removes a user or group from the Remote SAM Enumeration Permissions and either outputs the SDDL string to set by GPO, or sets directly in the local registry.
    .PARAMETER user
    The user or group to be removed in the format domain\user or domain\group. By default the local domain will be chosen if not entered.
    .PARAMETER toreg
    Removes the user or group from the Remote SAM Enumeration permissions set in the local registry.
    Requires Powershell to be running as an Administrator.
    .PARAMETER fromreg
    Tells the module to read the Remote SAM Enumeration permissions from the local registry and removes the new user or group from them.
    .PARAMETER gpostring
    Tells the module to use the user provided SDDL string taken from the GPO gui and removes the new user or group from it.
    .EXAMPLE
    Looks at the local Remote SAM Enumeration registry settings and removes the user contoso.com\user1 from them.
    PS> Remove-RemoteSAMUser -user "contoso.com\user1" -fromreg -toreg
    .EXAMPLE
    Looks at the local Remote SAM Enumeration registry settings and removes the user contoso.com\user1 from them displaying the new SDDL string to be deployed.
    PS> Remove-RemoteSAMUser -user "contoso.com\user1" -fromreg
    .EXAMPLE
    Takes an SDDL string provided and removes the group contoso.com\group1 from it displaying the new SDDL string to be deployed.
    PS> Remove-RemoteSAMUser -user "constoso.com\group1" -gpostring <SDDLstring>
    .LINK
    https://github.com/idnahacks/NetCeasePlusPlus
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
        $gpostring
    )
    $remoteAccess = 0x00020000
    $ntuser = New-Object System.Security.Principal.NTAccount($user)
    $sid = $ntuser.Translate([System.Security.Principal.SecurityIdentifier])
    if ($gpostring) {
        $rsd = New-Object -TypeName System.Security.AccessControl.RawSecurityDescriptor -ArgumentList $gpostring
    }
    else {
        Get-SamRegKey
        $rsd = New-Object -TypeName System.Security.AccessControl.RawSecurityDescriptor -ArgumentList $restrictremotesam
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

Export-ModuleMember -Function Get-SessionEnumPermissions, Set-DefaultNetCeasePermissions, Add-SessionEnumUser, Remove-SessionEnumUser, Get-RemoteSAMPermissions, Add-RemoteSAMUser, Remove-RemoteSAMUser