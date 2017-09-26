
Get-AccessControlEntry d:\temp -ExcludeInherited | Add-AccessControlEntry -InputObject (Disable-AclInheritance D:\temp\perm_test\icacls -PassThru) -PassThru -Confirm | tee -var SD

Disable-AclInheritance D:\temp\perm_test\icacls -PassThru | Add-AccessControlEntry -AceObject (Get-AccessControlEntry d:\temp -ExcludeInherited) -PassThru | tee -var SD2



Get-AccessControlEntry D:\temp\perm_test\canonicaltest, D:\temp\perm_test\icacls
Add-AccessControlEntry -Path D:\temp\perm_test\canonicaltest -Principal mehaffeym -FolderRights CreateDirectories -AppliesTo ChildContainers, ChildObjects -WhatIf