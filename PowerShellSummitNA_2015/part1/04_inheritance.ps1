
$TestFolderPath = "$RootFolderPath\InheritSD"

<##############################################
# Managing inheritance with Native PowerShell
###############################################>

$Acl = Get-Acl $TestFolderPath -Audit

# Inheritance information is stored in the 'AreAccessRulesProtected' and 'AreAuditRulesProtected' 
# properties of the security descriptor
$Acl | Select-Object @{N="Path"; E={Convert-Path $_.Path}}, Are*Protected | fl

# Since the access rules are not protected, that means that inheritance is currently enabled. If
# they were protected, then inheritance would be disabled.

# To change the inheritance status, use the 'SetAccessRuleProtection' and/or 'SetAuditRuleProtection'
# methods. Both methods take two parameters:
#     1. isProtected - A boolean value; $true enables protection (disables inheritance) and $false 
#                      disables protection (enables inheritance)
#     2. preserveInheritance - A boolean value; it is only checked when isProtected is $true. If this
#                              is $true, then any inherited entries are copied as explicit entries. If
#                              it is $false, the inherited entries will be removed
$Acl | Get-Member -MemberType Method -Name Set*Protection

# This will disable DACL inheritance, and copy any inherited entries as explicit entries):
$Acl.SetAccessRuleProtection($true, $true)

# If you look at the DACL, you'll see that there are still inherited ACEs:
$Acl.Access | ft
$Acl | Get-AccessControlEntry

# Get-AccessControlEntry correctly displays that DACL Inheritance is disabled, but it still shows some
# inherited ACEs. To have the SD's ACLs property reflect the change to inheritance, you'll need to save
# the SD and then get a new copy:
(Get-Item $Acl.Path).SetAccessControl($Acl)
$Acl = Get-Acl $TestFolderPath -Audit
$Acl.AreAccessRulesProtected

# This looks better:
$Acl.Access | ft
$Acl | Get-AccessControlEntry



<##############################################
# Managing inheritance with PAC Module
###############################################>

# First, you probably already noticed that Get-AccessControlEntry showed the Inheritance status.
# Second, SD objects returned from Get-SecurityDescriptor can be modified the same way as the SDs from
# Get-Acl (with the Set*RuleProtection() methods). The real PAC way to do it, though, is through the
# Enabled-AclInheritance and/or Disable-AclInheritance functions:


# Let's re-enable the DACL inheritance from earlier (there are two switches that deal with which ACL to
# work with: -DiscretionaryAcl or -SystemAcl. When neither is specified, the default is to only work on
# the DACL):
$Acl | Enable-AclInheritance -Force -Apply

# Now look at the SD (straight from the object, not the in-memory SD) and notice the DACL Inheritance is
# enabled again (notice the duplicate ACEs now; each inherited ACE has a non-inherited copy):
$TestFolderPath | Get-AccessControlEntry

# Let's do a DACL and a SACL (notice that I'm using Get-SecurityDescriptor. When working with the DACL
# only, it's not necessary, but since I want to work with the SACL, I have to use Get-SD and pass the
# -Audit switch; since I want the changes to be applied without having to call Set-SecurityDescriptor,
# I have pass the -Apply switch. The -Apply switch wouldn't be necessary if I was passing a DirectoryInfo
# object or a string path, but because I'm calling Get-SD first, it is necessary unless we're just trying
# to change an in memory security descriptor):
$TestFolderPath2 = "$RootFolderPath\SomeExtraAces"
$TestFolderPath2 | Get-AccessControlEntry -Audit
Get-SecurityDescriptor $TestFolderPath2 -Audit | 
    Disable-AclInheritance -DiscretionaryAcl -SystemAcl -Apply -PreserveExistingAces -Force

# Without using the -Force or -PreserveExistingAces switches, the function prompts for the existing ACE
# behavior. If you don't want the prompt, you can pass -PreserveExistingAces to copy any inherited ACEs
# as explicit ACEs, or -PreserveExistingAces:$false to remove the inherited ACEs without copying them

# Confirm that ACL inheritance is disabled:
$TestFolderPath2 | Get-AccessControlEntry -Audit

# Let's undo the action and remove any explicit entries that match the inherited entries. This will need
# to be a two step process since the SD has to be applied and obtained again before it will reflect the
# inherited ACEs. This time, lets just fix the DACL:
$TestFolderPath2 | Enable-AclInheritance
$TestFolderPath2 | Get-AccessControlEntry -Audit

# Now, remove any duplicate inherited entries (this only works properly with DACLs for now; to fix SACLs,
# see the example below)
$TestFolderPath2 | Get-AccessControlEntry -AceType AccessAllowed, AccessDenied -Inherited | Remove-AccessControlEntry -Specific
$TestFolderPath2 | Get-AccessControlEntry -Audit

#region Remove duplicate inherited entries for SACL
# First, enable SACL inheritance:
Get-SecurityDescriptor $TestFolderPath2 -Audit | Enable-AclInheritance -SystemAcl -Force -Apply

# Now, this is very similar to removing duplicates for DACL, but it can't be piped as cleanly, so we have
# to use a ForEach-Object:
Get-SecurityDescriptor $TestFolderPath2 -Audit | ForEach-Object {
    $SD = $_
    $SD | Get-AccessControlEntry -AceType SystemAudit -Inherited | Remove-AccessControlEntry -Specific -SDObject $SD
    $SD
} | Set-SecurityDescriptor
#endregion

# This should work for AD objects, registry keys, folders, and WMI namespaces
gwmi __systemsecurity | Disable-AclInheritance -PreserveExistingAces -WhatIf
gi HKCU:\Software\Sysinternals | Disable-AclInheritance -PreserveExistingAces -WhatIf