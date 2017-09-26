# This returns two OUs:
dir 'AD:\DC=local,DC=test' | where Name -match "domain users"

$OUs = dir 'AD:\DC=local,DC=test' | where Name -match "domain users"

$AcesToAdd = Compare-Object ($OUs[0] | Get-AccessControlEntry -Principal self) ($OUs[1] | Get-AccessControlEntry -Principal self) -Property AceType, Principal, AccessMask, InheritedFrom, AppliesTo, ObjectAceType, InheritedObjectAceType | 
    New-AccessControlEntry

$SD = Get-SecurityDescriptor $OUs[0] | Add-AccessControlEntry -AceObject $AcesToAdd -Verbose -PassThru
