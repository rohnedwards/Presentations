

# Direct copy a security descriptor (no audit)
Get-AccessControlEntry HKLM:\SOFTWARE\NAVO\test2
Set-SecurityDescriptor -SDObject HKLM:\SOFTWARE -InputObject HKLM:\SOFTWARE\NAVO\test2
Get-AccessControlEntry HKLM:\SOFTWARE\NAVO\test2

# Same as before, but with Audit
Get-AccessControlEntry HKLM:\SOFTWARE\NAVO\test2 -SDOption (New-PacCommandOption -SecurityDescriptorSections AllAccessAndAudit)
Set-SecurityDescriptor -SDObject HKLM:\SOFTWARE -InputObject HKLM:\SOFTWARE\NAVO\test2 -SDOption (New-PacCommandOption -SecurityDescriptorSections AllAccessAndAudit)


# Previous two tests, but with no access:
$Option = New-PacCommandOption -BypassAclCheck -SecurityDescriptorSections AllAccessAndAudit
$OriginalNoAccessSD = Get-SecurityDescriptor HKLM:\SOFTWARE\NAVO\test -SDOption $Option

Set-SecurityDescriptor -SDObject HKLM:\SOFTWARE -InputObject HKLM:\SOFTWARE\NAVO\test -SDOption $Option
<#

NOTE: THIS CREATED PSEUDO-INHERITED ACES AT THE NEW LOCATION!!!! (I think that was when -Sections still existed as an option on Set-SD, and the final SetSecurityInfo() call was being called w/o Protected or Unprotected DACL switches)

#>

Get-AccessControlEntry HKLM:\SOFTWARE\NAVO\test -SDOption $Option

# Set it back:
$OriginalNoAccessSD | Set-SecurityDescriptor -SDOption (New-PacCommandOption -SecurityDescriptorSections AllAccessAndAudit)