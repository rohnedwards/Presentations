# To add or remove access/audit rules with native PowerShell, an ACE object is required. The ACE object
# is passed to the .NET SD modification methods, and rules are added/replaced/merged/removed/purged, etc,
# depending on the methods used.

# NOTE: In these examples, $Acl is a variable used to hold a security descriptor obtained by calling
#       Get-Acl (a built-in PS cmdlet), and $SD is a variable used to hold a security descriptor obtained
#       by calling Get-SecurityDescriptor (a function in the PowerShell Access Control module)
#
#       Also, there are no New-Object calls to create ACEs in these examples. See the 02_adding_access.ps1 
#       script for examples of those. All ACE creations in this script use either New-AccessControlEntry 
#       or the similar ACE creation parameters of the Remove-AccessControlEntry function.

<###############################################
  Removing access with native PS cmdlets/.NET
###############################################>
# Create an ACE object that contains the type, principal, and access we want to remove
$Ace = New-AccessControlEntry -Principal Everyone -FolderRights Write -AppliesTo Object

# We'll use the $Acl and $SD variables defined in the previous script:
$Acl, $SD | Get-AccessControlEntry -NotInherited

#region ACE addition methods discussion
$Acl | Get-Member -MemberType Method | ? Name -match "Remove|Purge"
<#
There are four methods that deal with removing allow/deny/audit rules:
  1. RemoveAccessRule/RemoveAuditRule (Takes a single ACE as input)
        This will remove the permissions specified in the ACE from the ACL (and it does nothing if there
        is no matching permission in the ACL). For example, if 'Everyone' has 'Read and Write' privileges
        allowed on O CC CO, passing an ACE that specifies 'Allow' 'Write' on the object only, then the 
        resulting ACL will grant 'Allow' access to 'Read and Write' for child containers and child objects, 
        but only 'Read' access to the object (only the access in the ACE that was passed is removed) 
  2. RemoveAccessRuleSpecific/RemoveAuditRuleSpecific (Takes a single ACE as 
     input)
        This will remove the permissions specified in the ACE from the ACL, but only if a matching ACE is 
        found (the ACE must patch principal, access mask, AppliesTo, AceType, etc). 
  3. RemoveAccessRuleAll/RemoveAuditRuleAll (Takes a single ACE as input)
        This will remove any ACEs that match the Principal and AceType of the provided ACE.
  3. PurgeAccessRules/PurgeAuditRules (Takes an IdentityReference, which is
     either a SecurityIdentifier .NET object, or an NTAccount .NET object)
        This will remove any ACEs that match the provided IdentityReference (Principal).
#>
#endregion

# Remove 'Write' access:
$Acl | Get-AccessControlEntry -Principal Everyone -NotInherited
$Acl.RemoveAccessRule($Ace)

# Notice that there are now 2 ACES: one that grants 'Read' access to O CC CO, and another that grants 'Write' 
# access just to CC CO (we told it to take 'Write' access away from O, which it did
$Acl | Get-AccessControlEntry -Principal Everyone -NotInherited

#region How to save SD changes
# The $Acl security descriptor only exists in memory right now. To save it, we'd call one 
# of the following commands
$Acl | Set-Acl  # This will only work if you are the owner of the file
   # or #
(Get-Item $Acl.Path).SetAccessControl($Acl) # This will set the DACL
#endregion

#region Compare RemoveRule/RemoveRuleSpecific/RemoveRuleAll/PurgeRules methods
# Create some more ACEs:
$FullControlFilesAce = New-AccessControlEntry -Principal Everyone -FileRights FullControl
$FullControlAce = New-AccessControlEntry -Principal Everyone -FolderRights FullControl
$ModifyAce = New-AccessControlEntry -Principal Everyone -FolderRights Modify

# Add an ACE that grants full control and one that denies delete (using PAC module for this):
$Acl | Add-AccessControlEntry -AceObject $FullControlAce -PassThru |
       Add-AccessControlEntry -Principal Everyone -FolderRights Delete -AceType AccessDenied -PassThru |
       Get-AccessControlEntry -Principal Everyone -NotInherited

# Call RemoveAccessRuleSpecific, which will only remove access/audit info if it finds a perfectly matching ACE
$Acl.RemoveAccessRuleSpecific($FullControlFilesAce)
$Acl.RemoveAccessRuleSpecific($ModifyAce)

# Notice that no changes were made. Neither ACE matched
$Acl | Get-AccessControlEntry -Principal Everyone -NotInherited

# This one will match, though, and it will remove access:
$Acl.RemoveAccessRuleSpecific($FullControlAce)

# Put it back for next demo
$Acl.AddAccessRule($FullControlAce)

# RemoveAccessRuleAll will remove all Allow ACEs for 'Everyone' (the AceType and Princpal are the only parts of the ACE
# that gets passed that matter)
$Acl.RemoveAccessRuleAll($ModifyAce)
$Acl | Get-AccessControlEntry -Principal Everyone -NotInherited

#Put it back
$Acl.AddAccessRule($FullControlAce)

# PurgeAccessRules will remove all DACL entries for the specified Principal (Everyone group in this case);
# PurgeAuditRules would remove all SACL entries for the specified Principal
$Acl.PurgeAccessRules([System.Security.Principal.NTAccount] "Everyone")
$Acl | Get-AccessControlEntry -Principal Everyone -NotInherited

#endregion

<########################################################
  Removing access with the PowerShellAccessControl module
#########################################################>

# Use $SD from previous script
$SD | Get-AccessControlEntry -NotInherited

# Remove-AccessControlEntry replaces the functionality of RemoveAccessRule, RemoveAccessRuleSpecific, 
# PurgeAccessRules, RemoveAuditRules, RemoveAuditRuleSpecific, and PurgeAuditRules.
# Default behavior matches normal Remove*Rule, where the specific access is removed, even if there isn't
# a perfectly matching ACE (This will remove Write access from 'Everyone', so 'Read' access should still
# be left):
$SD | Remove-AccessControlEntry -AceObject $Ace -PassThru |
      Get-AccessControlEntry -NotInherited

# -AceObject parameter can take an array of ACEs just like Add-AccessControlEntry (like in the last demo
# script, passing the same ACE over and over doesn't make any actual change to the DACL; this is just to
# show that you can pass more than one ACE object at a time):
$SD | Remove-AccessControlEntry -AceObject $Ace, $Ace

# Function can take New-AccessControlEntry parameters instead of -AceObject (another example that makes
# no actual change since 'Write' access has already been removed):
$SD | Remove-AccessControlEntry -Principal Everyone -FolderRights Write

# Function can take a SD object returned from Get-Acl:
$Acl | Remove-AccessControlEntry -Principal Everyone -FolderRights Write -PassThru |
       Get-AccessControlEntry -Principal Everyone -NotInherited

# The in memory SD was truly changed:
$Acl.Access | ft

# Multiple calls can be piped together when -PassThru parameter is used. Some useful Add/Remove 
# combinations can be used, like the following which grants 'Modify' access to the folder, subfolders, 
# and files (O CC CO), but then takes the delete right away from just folder object itself:
$Acl | Add-AccessControlEntry -Principal Users -FolderRights Modify -PassThru | 
       Remove-AccessControlEntry -Principal Users -FolderRights Delete, DeleteSubdirectoriesAndFiles, Write -AppliesTo Object -PassThru |
       Get-AccessControlEntry -NotInherited -Principal Users, Everyone


#region Note on methods other than SetAccessRule/SetAuditRule
# The function has optional parameters that handle the Set*RuleSpecific and Purge*Rules methods:

# Remove*RuleSpecific behavior occurs when the -Specific switch is specified
$Acl | Remove-AccessControlEntry -Principal Users -FolderRights Write -Specific

# To get the Purge*Rules behavior, just supply a -Principal and the -PurgeAccessRules and/or 
# -PurgeAuditRules switches:
$Acl | Remove-AccessControlEntry -Principal Users -PurgeAccessRules -PurgeAuditRules

# The function doesn't directly implement the Remove*RuleAll method for a specific principal, but a 
# Get-AccessControlEntry call combined with Remove-AccessControlEntry could handle that:
$Acl | Get-AccessControlEntry -AceType AccessAllowed -Principal Users | 
       Remove-AccessControlEntry -SDObject $Acl
#endregion

#region Removing audit ACEs
# The Remove-AccessControlEntry will inspect the ACE that was supplied to/created by the function and 
# remove it from the proper ACL, so the syntax is exactly the same as removing an access ACE (just make
# sure you use the 'SystemAudit' -AceType. Don't forget to obtain the SD with the -Audit switch
#endregion


#region Some examples of non-folder objects:
# See the 02_adding_access demo script for examples of non-folder objects
#endregion