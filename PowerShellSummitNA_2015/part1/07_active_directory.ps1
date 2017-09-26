# PAC module can work well with AD objects, too. Compare this native PS:
Import-Module ActiveDirectory
Get-Acl -Path "AD:\$((Get-ADUser $env:USERNAME).DistinguishedName)" | select -exp Access

# With this PAC module output
Get-ADUser $env:USERNAME | Get-AccessControlEntry

# Notice that GUIDs aren't shown; the actual friendly names for the properties, property sets,
# extended rights, validated rights, and class objects are shown (there is a speed sacrifice,
# though)

# Get-AccessControlEntry allows some very useful filtering:
Get-ADUser $env:USERNAME | Get-AccessControlEntry -ObjectAceType *Number, *Information -InheritedObjectAceType user

# Those results should include a lot of ACEs. If you look closely, each ACE applies to a user object (either because it
# only applies to a user object, or because there is no limiting InheritedObjectAceType, so the ACE applies to all objects)
# and the permission granted gives permission to something that ends in 'Number' or 'Information' (there are properties and
# property sets that fit that description). If there is an ACE that grants read or write 'All Properties' or 'All PropertySets',
# then that ACE meets the requirement.

# We can slightly change that last filter to not include the 'All Properties' and/or 'All PropertySets' and/or all object types
# by using the -Specific switch
Get-ADUser $env:USERNAME | Get-AccessControlEntry -ObjectAceType *Number, *Information -InheritedObjectAceType user -Specific



# We can create new ACEs, and the new ACEs will work with Get-Acl SD objects:

# Read all properties:
New-AccessControlEntry -Principal $env:USERNAME -ActiveDirectoryRights ReadProperty

# Perform all extended rights:
New-AccessControlEntry -Principal $env:USERNAME -ActiveDirectoryRights ExtendedRight

# Reset password extended right for user objects:
New-AccessControlEntry -Principal $env:USERNAME -ActiveDirectoryRights ExtendedRight -ObjectAceType (Get-ADObjectAceGuid -ExtendedRight Reset-Password) -InheritedObjectAceType (Get-ADObjectAceGuid -ClassObject user)

# This does the same thing as the previous example, but it doesn't use the Get-ADObjectAceGuid helper function. Also, the 
# -ActiveDirectoryRights parameter isn't necessary (if you're creating an ACE for a property or class object, it's recommended 
# to still supply the permissions since there are two possible permissions for those types of objects)
New-AccessControlEntry -Principal $env:USERNAME -ObjectAceType Reset-Password -InheritedObjectAceType user

# One last example on this. This almost does what the previous command does, except it will not uniquely identify an ObjectAceType
# and InheritedObjectAceType, so you'll be prompted to choose one:
New-AccessControlEntry -Principal $env:USERNAME -ObjectAceType *pass* -InheritedObjectAceType *user*

#region Create the same ACE with native PowerShell
New-Object System.DirectoryServices.ActiveDirectoryAccessRule (
    [System.Security.Principal.NTAccount] $env:USERNAME,
    [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
    [System.Security.AccessControl.AccessControlType]::Allow,
    "00299570-246d-11d0-a768-00aa006e0529",
    [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All,
    "bf967aba-0de6-11d0-a285-00aa003049e2"
)
#endregion

# Being able to easily create new ACEs like this means that delegation from PS becomes very easy. If you know what ACEs
# are needed, just use Add-AccessControlEntry with the New-Ace params shown above. If you're not sure what rights are needed
# to do the desired task, you can take a before and after snapshot of an object and use the 'Delegation of Control Wizard'
# to see the rights that are added:

$OuPath = 'OU=TestOU,DC=testdomain,DC=local'
$UserName = "LimitedUser"

$Before = Get-ADObject $OuPath | Get-AccessControlEntry

# Run the 'Delegation of Control Wizard' and delegate some control to $UserName

$After = Get-ADObject $OuPath | Get-AccessControlEntry

# ObjectAceType, InheritedObjectAceType are also useful, but knowing the full name and type of each is enought
# to uniquely identify them.
Compare-Object $Before $After -Property Principal, AccessMaskDisplay, AppliesTo, InheritedObjectAceTypeDisplayName | ft

# Clean up:
$OuPath | Get-AccessControlEntry -Principal $UserName | Remove-AccessControlEntry -Specific

# Finally, let's look at Get-EffectiveAccess

# This example looks very similar to Get-EffectiveAccess for non-AD objects:
Get-ADObject $OuPath | Get-EffectiveAccess -Principal $UserName
Get-ADObject $OuPath | Get-EffectiveAccess -Principal $UserName -ListAllRights

# The real difference comes in with the -ObjectAceTypes parameter. This will show any effective access on any
# properties, property sets, validated writes, extended rights, and class objects that match any of the listed
# partial names. If there is no access, the ObjectAceType isn't listed:
Get-ADObject $OuPath | Get-EffectiveAccess -Principal $UserName -ObjectAceTypes *Information, *Number, *pass*

# When -ListAllRights is used, every single matching ObjectAceType gets listed:
Get-ADObject $OuPath | Get-EffectiveAccess -Principal $UserName -ObjectAceTypes *Information, *Number, *pass* -ListAllRights

# That was a lot. Lets say you're interested in whether or not a user has the Reset-Password right:
Get-ADUser $UserName | Get-EffectiveAccess -Principal $UserName -ObjectAceTypes Reset-Password -ListAllRights
Get-ADUser $UserName | Get-EffectiveAccess -Principal $UserName -ObjectAceTypes Change-Password -ListAllRights
