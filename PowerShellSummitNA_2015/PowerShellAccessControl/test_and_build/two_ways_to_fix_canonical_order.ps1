$NonCanonicalSdPath = $PathToTestFolder
$Acl = Get-Acl $NonCanonicalSdPath

# Convert to a raw SD:
$RawSD = New-Object System.Security.AccessControl.RawSecurityDescriptor($Acl.Sddl)

# Create a new DACL
$NewDacl = New-Object System.Security.AccessControl.RawAcl(
    [System.Security.AccessControl.RawAcl]::AclRevision,
    $RawSD.DiscretionaryAcl.Count  # Capacity of ACL
)

<#
$Inherited = @{
    AccessAllowed = @()
    AccessDenied = @()
}

$NotInherited = @{
    AccessAllowed = @()
    AccessDenied = @()
}

foreach ($Ace in $RawSD.DiscretionaryAcl) {
    if ($Ace.IsInherited) { $Ht = $Inherited }
    else { $Ht = $NotInherited }

    $Ht[$Ace.AceQualifier.ToString()] += $Ace
}

$NotInherited.AccessDenied, $NotInherited.AccessAllowed, $Inherited.AccessDenied, $Inherited.AccessAllowed | 
    ForEach-Object { $_ } | 
    ForEach-Object {
        if ($_) { # null test
            $NewDacl.InsertAce($NewDacl.Count, $_)
        }
    }
#>

$RawSD.DiscretionaryAcl | Sort-Object @{E={$_.IsInherited}; Descending=$true}, AceQualifier | ForEach-Object {
    $NewDacl.InsertAce(0, $_)
}

$RawSD.DiscretionaryAcl = $NewDacl
$Acl.SetSecurityDescriptorSddlForm($RawSD.GetSddlForm("All"))
