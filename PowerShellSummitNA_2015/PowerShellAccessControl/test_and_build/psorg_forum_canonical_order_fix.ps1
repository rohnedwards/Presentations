$Acl = Get-Acl "Put path to bad SD here"

# This should return false:
$Acl.AreAccessRulesCanonical

# Convert to a raw SD:
$RawSD = New-Object System.Security.AccessControl.RawSecurityDescriptor($Acl.Sddl)

# Create a new DACL
$NewDacl = New-Object System.Security.AccessControl.RawAcl(
    [System.Security.AccessControl.RawAcl]::AclRevision,
    $RawSD.DiscretionaryAcl.Count  # Capacity of ACL
)

# Put in reverse canonical order and insert each ACE (I originally had a different method that
# preserved the order as much as it could, but that order isn't preserved later when we put this
# back into a DirectorySecurity object)
$RawSD.DiscretionaryAcl | Sort-Object @{E={$_.IsInherited}; Descending=$true}, AceQualifier | ForEach-Object {
    $NewDacl.InsertAce(0, $_)
}

# Replace the DACL with the re-ordered one
$RawSD.DiscretionaryAcl = $NewDacl

# Commit those changes back to the original SD object (but not to disk yet):
$Acl.SetSecurityDescriptorSddlForm($RawSD.GetSddlForm("Access"))

# This should return true now
$Acl.AreAccessRulesCanonical

# Commit changes to disk
$Acl | Set-Acl
