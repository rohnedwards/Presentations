$TestFolderPath = "$RootFolderPath\InheritSD"

#region Native PS method
# To add or remove access/audit rules with native PowerShell, an ACE object is required. The ACE object
# is passed to the .NET SD modification methods, and rules are added/replaced/merged/removed/purged, etc
# depending on the methods used.

# NOTE: In these examples, $Acl is a variable used to hold a security descriptor obtained by calling
#       Get-Acl (a built-in PS cmdlet), and $SD is a variable used to hold a security descriptor obtained
#       by calling Get-SecurityDescriptor (a function in the PowerShell Access Control module)

<###############################################
  Adding access with native PS cmdlets/.NET
###############################################>

# Native PS requires New-Object to create a FileSystemAccessRule via New-Object. This will create an ACE
# that gives the 'Everyone' group 'Write' access to the container it applies to, and any child containers
# and child objects (if it belongs to a folder, it will apply to subfolders and files)
$Ace = New-Object System.Security.AccessControl.FileSystemAccessRule (
    "Everyone",   #Principal
    "Write",      # Access - [System.Security.AccessControl.FileSystemRights]
    "ContainerInherit, ObjectInherit", # Inheritance Flags - [System.Security.AccessControl.InheritanceFlags]
    "None",       # Propagation Flags - [System.Security.AccessControl.PropagationFlags]
    "Allow"       # Access control type - [System.Security.AccessControl.AccessControlType]
)

# An audit ACE is very similar (object type name and last argument for constructor are different):
$AuditAce = New-Object System.Security.AccessControl.FileSystemAuditRule (
    "Everyone",   #Principal
    "Write",      # Access - [System.Security.AccessControl.FileSystemRights]
    "ContainerInherit, ObjectInherit", # Inheritance Flags - [System.Security.AccessControl.InheritanceFlags]
    "None",       # Propagation Flags - [System.Security.AccessControl.PropagationFlags]
    "Success, Failure"       # Audit flags - [System.Security.AccessControl.AuditFlags]
)

# The SD must be obtained before calling one of the access addition methods
$Acl = Get-Acl $TestFolderPath

<#
There are three methods that deal with adding allow/deny/audit rules. All three take a single ACE as their input:
  1. AddAccessRule/AddAuditRule
        This will add the ACE to the ACL. If there is already an ACE that matches the principal and AceType, this
        ACE is merged with the existing ACE, e.g., if 'Everyone' with 'Allow' 'Read' already exists and an ACE that
        grants 'Everyone' 'Allow' 'Write' access is passed, the DACL will contain an ACE that grants 'Everyone' 
        'Read and Write' access.
  2. SetAccessRule/SetAuditRule
        This will add the ACE to the ACL. If there is already an ACE that matches the principal and AceType, this
        ACE will overwrite the existing ACE, e.g., if 'Everyone' with 'Allow' 'Read' already exists and an ACE that
        grants 'Everyone' 'Allow' 'Write' access is passed, the DACL will contain an ACE that grants 'Everyone'
        just 'Write' access since the original ACE will be overwritten.
  3. ResetAccessRule
        This is only used for the DACL. If there are ACEs that match the principal of the ACE being passed, they are
        all removed and then the ACE passed to this method is applied. This differs from SetAccessRule because the
        AceType isn't checked, just the Principal. For example, if 'Everyone' is denied 'FullControl' access, and an
        ACE granting 'Everyone' 'Read' access is passed to this method, the Deny ACE will be removed (and if any
        other Allow or Deny ACEs existed for 'Everyone', they would be removed, too), and the new Allow ACE would
        be applied.
#>

# View original DACL (Using PAC module)
$Acl | Get-PacAccessControlEntry

# Add ACE created earlier using AddAccessRule (Since there is no 'Everyone' ACE, calling any of the three
# *AccessRule methods [Add/Set/Reset] will all do the same thing, which is just add the $Ace object)
$Acl.AddAccessRule($Ace)
$Acl | Get-PacAccessControlEntry

# DACL changes haven't been saved. Look at the DACL on the actual file:
Get-Item $Acl.Path | Get-PacAccessControlEntry

# The $Acl security descriptor only exists in memory right now. To save it, we'd call one of the 
# following commands:
$Acl | Set-Acl  # Be aware that there are a lot of instances where this will fail
   # or #
(Get-Item $Acl.Path).SetAccessControl($Acl) # This will set the DACL


#region Compare Add/Set/Reset rule methods
# Create some more ACEs (we'll cheat and use New-PacAccessControlEntry):
$ReadFilesAce = New-PacAccessControlEntry -Principal Everyone -FolderRights Read -AppliesTo ChildObjects
$ReadFoldersAce = New-PacAccessControlEntry -Principal Everyone -FolderRights Read -AppliesTo ChildContainers
$DenyDeleteAce = New-PacAccessControlEntry -AceType Deny -Principal Everyone -FolderRights Delete, DeleteSubdirectoriesAndFiles -AppliesTo Object

# Look at the explicit 'Everyone' ACEs (There should be a single allow 'Write' ACE):
$Acl | Get-PacAccessControlEntry -Principal Everyone -ExcludeInherited

# Add the ACE that grants read files
$Acl.AddAccessRule($ReadFilesAce)

# Notice that after this there are two ACEs. That's b/c one applies to the folder, subfolders, 
# and files, while the other only applies to files
$Acl | Get-PacAccessControlEntry -Principal Everyone -ExcludeInherited

# Add the other two ACEs:
$Acl.AddAccessRule($ReadFoldersAce)
$Acl.AddAccessRule($DenyDeleteAce)

# Two more ACEs were added, but there's only three ACEs that show up now instead of four.
# AddAccessRule merged $ReadFoldersAce with the ACE from $ReadFilesAce. It now applies to subfolders
# and files. There's also a Deny ACE, too
$Acl | Get-PacAccessControlEntry -Principal Everyone -ExcludeInherited

# Watch what happens when SetAccessRule is used, though:
$Acl.SetAccessRule($ReadFilesAce)

# There's just one Allow ACE, and it only has the access that was in $ReadFilesAce. Instead of merging
# the ACE, all ACEs that matched the type (Allow) and principal (Everyone) were removed, then the new
# ACE was applied. The Deny ACE was left alone (it didn't match the type)
$Acl | Get-PacAccessControlEntry -Principal Everyone -ExcludeInherited

# So, Add* merges access/audit entries, and Set* overwrites them (as long as the type (Allow/Deny/Audit)
# matches).

# Now use ResetAccessRule (if this is run, it will put the DACL back in the state it would have been in
# without running the code in this region):
$Acl.ResetAccessRule($Ace)

# Now the DACL only contains any access rights that are in $Ace. This is similar to SetAccessRule, except
# it took out all ACEs that matched 'Everyone' instead of matching on the AceType of the ACE supplied
# (notice the Deny ACE is gone).
$Acl | Get-PacAccessControlEntry -Principal Everyone -ExcludeInherited
#endregion
#endregion

#region PAC module method
<########################################################
  Adding access with the PowerShellAccessControl module
#########################################################>

# To create an ACE, we can use New-PacAccessControlEntry to create an ACE that defaults to an Allow
# ACE that applies to the folder, subfolders, and files. This ACE can be used with the .NET methods above:
$PacAce = New-PacAccessControlEntry -Principal Everyone -FolderRights Write

#region Comparision of $PacAce and $Ace (from .NET methods above)
# $PacAce is actually a different type of object, so you can't directly compare them. You can convert
# it to a FileSystemAccessRule (which is what $Ace is), though:
$PacAce -as [System.Security.AccessControl.FileSystemAccessRule]

# You can also have New-PacAccessControlEntry output a FileSystemAccessRule
$PacAceAsFSRule = New-PacAccessControlEntry -Principal Everyone -FolderRights Write -OutputType System.Security.AccessControl.FileSystemAccessRule

# $PacAce converts the Everyone name to a SID, so that will appear to be different, but the system will
# eventually convert $Ace's principal to a SID. Otherwise, the two ACE objects are identical:
$Ace | Get-Member -MemberType Properties | ForEach-Object {
    Compare-Object $Ace $PacAceAsFSRule -Property $_.Name
}
#endregion

#region More New-Object vs New-AccessControlEntry examples
# Create an ACE that denies write access that applies only to subfolders:
$PacTest = New-PacAccessControlEntry -Principal Everyone -FolderRights Write -AceType Deny -AppliesTo ChildContainers
$NativeTest = New-Object System.Security.AccessControl.FileSystemAccessRule("Everyone", "Write", "ContainerInherit", "InheritOnly", "Deny") 

# Create an ACE that grants write access that only applies to an object itself
$PacTest = New-PacAccessControlEntry -Principal Everyone -FileRights Write -AppliesTo Object
$NativeTest = New-Object System.Security.AccessControl.FileSystemAccessRule("Everyone", "Write", "None", "None", "Allow")
# Alternate constructor: $NativeTest = New-Object System.Security.AccessControl.FileSystemAccessRule("Everyone", "Write", "Allow")

# Create an Audit ACE:
$PacTest = New-PacAccessControlEntry -Principal Everyone -FolderRights Write -AceType Audit -AuditFlags Success, Failure
$NativeTest = New-Object System.Security.AccessControl.FileSystemAuditRule ("Everyone", "Write", "ContainerInherit, ObjectInherit", "None", "Success, Failure")

# Create a registry access rule:
$PacTest = New-PacAccessControlEntry -Principal Everyone -RegistryRights WriteKey
$NativeTest = New-Object System.Security.AccessControl.RegistryAccessRule ("Everyone", "WriteKey", "ContainerInherit", "None", "Allow")

# Create an AD rule:
# SEE THE 07_active_directory.ps1 DEMO SCRIPT
#endregion

# Get-PacSecurityDescriptor can be used as a replacement to Get-Acl:
$SD = Get-PacSecurityDescriptor $TestFolderPath

# Add-PacAccessControlEntry replaces the functionality of AddAccessRule, SetAccessRule, AddAuditRule, and
# SetAuditRule. By default, it behaves like the Add* methods (so it merges access instead of overwriting):
$SD | Add-PacAccessControlEntry -AceObject $PacAce

# -AceObject parameter can take an array of ACEs (this won't actually do anything since we're trying to
# add the same ACE that's already been added twice, but it won't hurt anything either):
$SD | Add-PacAccessControlEntry -AceObject $PacAce, $Ace

# Function can take New-PacAccessControlEntry parameters directly instead of -AceObject:
$SD | Add-PacAccessControlEntry -Principal Everyone -FolderRights Read

# Function can take a SD object returned from Get-Acl:
$Acl | Get-PacAccessControlEntry -Principal Everyone
$Acl | Add-PacAccessControlEntry -Principal Everyone -FolderRights Read
$Acl | Get-PacAccessControlEntry -Principal Everyone

# Multiple calls can be piped together when -PassThru parameter is used:
$Acl | Add-PacAccessControlEntry -Principal Users -FolderRights FullControl -PassThru | 
       Add-PacAccessControlEntry -AceType Deny -Principal Users -FolderRights Delete, DeleteSubdirectoriesAndFiles, Write -AppliesTo Object
$Acl | Get-PacAccessControlEntry -Principal Everyone, Users -ExcludeInherited

# NOTE: The Deny ACE added in the previous step isn't a good idea since it will deny all users (even 
# admins). There are situations where this is desirable (prevent accidental deletion), but usually 
# removing access is a better solution (see the next demo script)

#region Note on SetAccessRule/SetAuditRule and ResetAccessRule functionality
# To get the "Set" behavior mentioned in the native PS section above, use the -Overwrite switch:
$Acl | Get-PacAccessControlEntry -Principal Users
$Acl | Add-PacAccessControlEntry -Principal Users -FolderRights Read -Overwrite -PassThru |
       Get-PacAccessControlEntry -Principal Users -ExcludeInherited

# To get the ResetAccessRule behavior, use something like this (we're skipping ahead a little bit and
# using the Remove-AccessControlEntry function):
$Acl | Remove-PacAccessControlEntry -Principal Users -PurgeAccessRules -PassThru |
       Add-PacAccessControlEntry -Principal Users -FolderRights Read -PassThru |
       Get-PacAccessControlEntry -Principal Users -ExcludeInherited
#endregion

#region Adding audit ACEs
# The Add-AccessControlEntry will inspect the ACE that was supplied to/created by the function and add it 
# to the proper ACL, so the syntax is exactly the same as adding an access ACE (just make sure you use the
# 'AuditFlags' parameter (you use 'Audit' AceType, but it's optional). Don't forget to obtain the SD with 
# the -Audit switch (there is an optional switch parameter you can pass to the function to create a new 
# SACL; see help for more info)
#endregion

# $Acl and $SD don't match anymore (remember, they're both just in memory SDs):
$Acl, $SD | Get-PacAccessControlEntry -ExcludeInherited

# If we combine Get-AccessControl entry with Add-AccessControlEntry, we can take all of the ACEs from $Acl
# and add them to the $SD security descriptor (this different than fully replacing the SD, which is also
# possible with Set-SecurityDescriptor; see below):
$Acl | Get-PacAccessControlEntry -ExcludeInherited | Add-PacAccessControlEntry -InputObject $SD
$Acl, $SD | Get-PacAccessControlEntry -ExcludeInherited

# All of the changes can be saved out with the Set-PacSecurityDescriptor function (notice that a .NET Get-Acl
# object is being passed):
$Acl | Set-PacSecurityDescriptor

# The SD can be saved to a completely different object:
Get-PacAccessControlEntry $RootFolderPath\DontInheritSD
Set-PacSecurityDescriptor -Path $RootFolderPath\DontInheritSD -SDObject $Acl
Get-PacAccessControlEntry $RootFolderPath\DontInheritSD


# One last thing to note about the Add-PacAccessControlEntry function: it doesn't require you
# to first get the SD, then make changes, then save them with Set-PacSecurityDescriptor. It
# will do all of that for you (under certain conditions)

# This command will immediately apply the SD b/c of the -Apply switch (you will be prompted
# before saving it; to suppress prompt, use -Force)
$SD | Add-PacAccessControlEntry -Principal Everyone -FolderRights Write -Apply

# This command will immediately apply the SD w/o the -Apply switch b/c the input object was
# not a SD object. Internally, the function recognizes that it didn't get a SD object as
# input, so it calls Get-SecurityDescriptor internally, and as long as the call doesn't fail,
# it adds the access, then tries to call Set-SecurityDescriptor automatically. Again, you
# will be prompted, so use -Force to suppress the prompt
"$RootFolderPath\InheritSD" | Add-PacAccessControlEntry -Principal Everyone -FolderRights Write

#region Some examples of non-folder objects:

Get-Service bits | Add-PacAccessControlEntry -Principal Users -AccessMask (New-PacAccessMask -ServiceRights Start, Stop)
gwmi __systemsecurity | Add-PacAccessControlEntry -Principal Users -AccessMask (New-PacAccessMask -WmiNamespaceRights RemoteEnable)
Get-Printer | select -first 1 | Add-PacAccessControlEntry -Principal Users -AccessMask (New-PacAccessMask -PrinterRights ManagePrinter)
gi HKCU:\Software\ | Add-PacAccessControlEntry -Principal Users -RegistryRights ReadKey
#endregion
#endregion