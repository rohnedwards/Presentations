
$NoAccessPath = "$RootFolderPath\NoAccess"
$AccessPath = "$RootFolderPath\SomeExtraAces"
$SomeOtherPrincipal = "LimitedUser"

# Let's try to change the owner of an object that we can currently access
$Acl = Get-Acl $AccessPath

# Look at the owner (SYSTEM since DSC created the folder and the DSC config didn't specify an owner):
$Acl.Owner

# Try to change it
$Acl.SetOwner([System.Security.Principal.NTAccount] $SomeOtherPrincipal)
$Acl | Set-Acl

# That should fail (same error as trying to modify a SD when you aren't the owner). Setting the owner to
# the currently logged in user would work, though.

# You can change it with Set-Owner, though
Set-Owner -Path $AccessPath -Principal $SomeOtherPrincipal
$Acl = Get-Acl $AccessPath
$Acl.Owner

# Now, lets take a look at a folder where we have no access at all:
dir $NoAccessPath
Get-Acl $NoAccessPath
$NoAccessPath | Get-EffectiveAccess

# None of those commands work because the DACL is empty, so we don't have any access to the object. Let's 
# try to add some access:
$NoAccessPath | Add-AccessControlEntry -Principal $env:USERNAME -FolderRights FullControl

# That doesn't work, either. To get into it, we'll need to take ownership. Native PS would have to rely on 
# the 'takeown.exe' program. We'll use the PAC module's 'Set-Owner' instead (no -Principal defaults to the
# taking ownership):
Set-Owner -Path $NoAccessPath

# We still can't view the folder contents, but we can at least see the DACL:
dir $NoAccessPath
Get-AccessControlEntry $NoAccessPath
Get-Acl $NoAccessPath

# Let's try to add an ACE giving the current user access:
Get-Acl $NoAccessPath | Add-AccessControlEntry -Principal $env:USERNAME -FolderRights FullControl -PassThru | Set-Acl

# That failed. Set-Acl won't let us modify the DACL even though we are the owner. Let's take Set-Acl off and use the
# -Apply switch (which calls Set-SecurityDescriptor):
Get-Acl $NoAccessPath | Add-AccessControlEntry -Principal $env:USERNAME -FolderRights FullControl -Apply

# This command would have worked, too:
# $NoAccessPath | Add-AccessControlEntry -Principal $env:USERNAME -FolderRights FullControl

# Finally, we can get a directory listing:
dir $NoAccessPath
