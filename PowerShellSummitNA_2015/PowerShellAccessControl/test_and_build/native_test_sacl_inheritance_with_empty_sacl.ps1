$path = "D:\temp\perm_test\overwritesacl"

# Break it by clearing SACL and disabling inheritance:
Get-Acl $path | Set-Acl

# Get ACL w/ SACL
$acl = Get-Acl $path -Audit

# If SACL is empty, add a rule to it...
$dummyAce = $null  # Need to know later if this was used
if ($acl.Audit.Count -eq 0) {
    $dummyAce = New-Object System.Security.AccessControl.FileSystemAuditRule("Everyone","TakeOwnerShip","Success")
    $acl.AddAuditRule($dummyAce)
}
$acl.SetAuditRuleProtection($false, $false)
$acl | Set-Acl

# Cleanup if $dummyAce was used earlier
if ($dummyAce) {
    $acl = Get-Acl $path -Audit
    $acl.RemoveAuditRuleSpecific($dummyAce)
    $acl | Set-Acl
}



<#
Same thing, but with PAC module
#>
Get-Acl $path | Set-Acl  # Start from scratch
Get-AccessControlEntry $path -PacSDOption (New-PacCommandOption -Audit) # Confirm it's empty

# This is all that's needed (NOTE: Need to play around w/ requiring New-PacCommandOption when -SystemAcl is set)
# Another note: why is this setting all sections? Modifies sections should only be set, and only SACL should have been modified; OK, -SecurityDescriptorSections overrides the modified sections; should this behavior be kept??
Enable-AclInheritance -SystemAcl $path -PacSDOption (New-PacCommandOption -SecurityDescriptorSections Audit) 

Get-AccessControlEntry $path -PacSDOption (New-PacCommandOption -Audit) # Confirm it's empty



<#
What happens when SACL inheritance is enabled and you want to disable it?
#>
Get-Acl $path | Set-Acl
Enable-AclInheritance -SystemAcl $path -PacSDOption (New-PacCommandOption -SecurityDescriptorSections Audit) -Force

$acl = Get-Acl $path -Audit
$acl.AreAuditRulesProtected
$acl.SetAuditRuleProtection($true, $true)
$acl | Set-Acl

<#  Scratch area

$sd = Get-SecurityDescriptor $path -PacSDOption (New-PacCommandOption -Audit)
$sd

Get-AccessControlEntry $path -PacSDOption (New-PacCommandOption -Audit) # Confirm it's empty



$sddl = $acl.Sddl
if (-not $acl.GetSecurityDescriptorSddlForm("Audit")) {
    $sddl += "S:"
}
$acl.SetSecurityDescriptorSddlForm($sddl)
$acl.SetAuditRuleProtection($false, $false)
$acl.SetAuditRuleProtection($true, $true)
$acl.SetAuditRuleProtection($false, $false)
$acl | Set-Acl



# Reflection
$_sd = $acl.gettype().invokemember("_securityDescriptor", "Nonpublic, GetField, Instance", $null, $acl, $null)
$acl.gettype().invokemember("WriteLock", "Nonpublic, InvokeMethod, Instance", $null, $acl, $null)
$acl.gettype().invokemember("GetAccessControlSectionsFromChanges", "Nonpublic, InvokeMethod, Instance", $null, $acl, $null)
$acl.gettype().invokemember("WriteUnlock", "Nonpublic, InvokeMethod, Instance", $null, $acl, $null)


$_sd.GetType().InvokeMember("IsSystemAclPresent", "Nonpublic, GetProperty, Instance", $null, $_sd, $null)

#>
