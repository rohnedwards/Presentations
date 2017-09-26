
[ROE.PowerShellAccessControl.Helper]::GetAdaptedSecurityDescriptor((get-acl C:\Windows))                                                                                                                                   
[ROE.PowerShellAccessControl.Helper]::GetAdaptedSecurityDescriptor((get-acl HKLM:\SOFTWARE))                                                                                                                               

$User = Get-ADUser edwardsr -Properties ntsecuritydescriptor
$ADSD1 = Get-Acl ("AD:\$($User.DistinguishedName)")
$ADSD2 = $User.ntsecuritydescriptor
[ROE.PowerShellAccessControl.Helper]::GetAdaptedSecurityDescriptor($ADSD1)
[ROE.PowerShellAccessControl.Helper]::GetAdaptedSecurityDescriptor($ADSD2)

[ROE.PowerShellAccessControl.Helper]::GetAdaptedSecurityDescriptor((Get-Item C:\win7_ship_2013090501.iso).GetAccessControl())

[ROE.PowerShellAccessControl.Helper]::GetPathInfo((Get-Item C:\Windows))
[ROE.PowerShellAccessControl.Helper]::GetAdaptedSecurityDescriptor((Get-Item C:\Windows))

[ROE.PowerShellAccessControl.Helper]::GetPathInfo((Get-Item HKLM:\SOFTWARE))