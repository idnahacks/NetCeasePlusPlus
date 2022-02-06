# NetCease++
## Introduction
A Powershell module that stands on the shoulders of the original [NetCease](https://github.com/p0w3rsh3ll/NetCease) and SAMRi10 work and rolls them up into one, with some added functionality.

For a great overview on these two originating scripts and their intentions check out this [Stealthbits blogpost](https://stealthbits.com/blog/making-internal-reconnaissance-harder-using-netcease-and-samri1o/).

------
[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/B0B7AAAK2)  
> I'm lucky enough to do this for a living. Any donations will be passed on to my local foodbank, animal sanctuary and animal rescue centres.  
------

## Session Enumeration Permissions
### Viewing Session Enumeration Permissions
To view the settings applied to your local machine use:
```Powershell
Get-SessionEnumPermissions | Format-Table
```
If you are working with an existing Group Policy Object and want to translate the hex value that is set use the following, swapping the hex string to the one set at Computer Configuration/Preferences/Windows Settings/Registry/SrvSvcSessionInfo/General:
```Powershell
    Get-SessionEnumPermissions -gpostring "010004801400000020000000000000002c00000001010000000000051200000001010000000000051200000002008c000600000000001400ff011f0001010000000000050300000000001400ff011f0001010000000000050400000000001400ff011f000101000000000005060000000000180013000f00010200000000000520000000200200000000180013000f00010200000000000520000000230200000000180013000f0001020000000000052000000025020000" | Format-Table
```
### Adding and removing users or groups
To add or remove a user or group to or from the Session Enumeration permissions set in the local registry use the following. This will display a new hex string that can be set in a GPO setting at Computer Configuration/Preferences/Windows Settings/Registry/SrvSvcSessionInfo/General:
```Powershell
Add-SessionEnumUser -user "domain.com\user1" -fromreg
```
```Powershell
Remove-SessionEnumUser -user "domain.com\group1" -fromreg
```
To perform the same action but instead of displaying the new hex string set the new permission in the local registry use the -toreg parameter.  
Powershell will need to be running with elevated privileges to set registry values.
```Powershell
Add-SessionEnumUser -user "domain.com\user1" -fromreg -toreg
```
The above cmdlets can also take input as a hexstring instead of the local registry. This can be used if you have already deployed permissions by GPO but want to add users to the value displayed at Computer Configuration/Preferences/Windows Settings/Registry/SrvSvcSessionInfo/General.  
The output will be the new hex string.
```Powershell
Add-SessionEnumUser -user "domain.com\group2" -gpostring "010004801400000020000000000000002c00000001010000000000051200000001010000000000051200000002008c000600000000001400ff011f0001010000000000050300000000001400ff011f0001010000000000050400000000001400ff011f000101000000000005060000000000180013000f00010200000000000520000000200200000000180013000f00010200000000000520000000230200000000180013000f0001020000000000052000000025020000"
```

## Remote SAM Enumeration Permissions
### Viewing Remote SAM Enumeration Permissions
To view the settings applied to your local machine you can use the following command. This displays the local settings as an ACL and also an SDDL string:
```Powershell
Get-RemoteSamPermissions
```
If you are working with an existing Group Policy Object and want to translate the SDDL string that is set use the following command, swapping the SDDL string to the one set at "Computer Configuration/Policies/Windows Settings/Security Settings/Local Policies/Security Options/Other/Network access: Restrict clients allowed to make remote calls to SAM":
```Powershell
Get-RemoteSamPermissions -gpostring "O:BAG:BAD:(A;;RC;;;BA)"
```
### Adding and removing users or groups
To add or remove a user or group to or from the Remote SAM Enumeration permissions set in the local registry use the following. This will display a new SDDL string that can be set in a GPO setting at "Computer Configuration/Policies/Windows Settings/Security Settings/Local Policies/Security Options/Other/Network access: Restrict clients allowed to make remote calls to SAM":
```Powershell
Add-RemoteSAMUser -user "domain.com\user1" -fromreg
```
```Powershell
Remove-RemoteSAMUser -user "domain.com\group2" -fromreg
```
To perform the same action but instead of displaying the new SDDL string set the new permission in the local registry use the -toreg parameter.  
Powershell will need to be running with elevated privileges to set registry values.
```Powershell
Add-RemoteSAMUser -user "domain.com\user1" -fromreg -toreg
```
The above cmdlets can also take input as an SDDL string instead of the local registry. This can be used if you have already deployed permissions by GPO but want to add users to the value displayed at "Computer Configuration/Policies/Windows Settings/Security Settings/Local Policies/Security Options/Other/Network access: Restrict clients allowed to make remote calls to SAM"
The output will be the new SDDL string.
```Powershell
Add-RemoteSAMUser -user "domain.com\user2" -gpostring "O:BAG:BAD:(A;;RC;;;BA)"
```
