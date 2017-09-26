# I was also trying to create a SD that would have a DACL that wasn't the same size b/w Raw and Common SD; this didn't work, so will have to keep trying.

$PathToTestFolder = "C:\powershell\access_control\windows_folder_test"
New-Item $PathToTestFolder -ItemType directory

$SourceFolder = "C:\Windows"
$SourceSD = Get-SecurityDescriptor $SourceFolder

Set-SecurityDescriptor -Path $PathToTestFolder -SDObject $SourceSD -Sections Dacl

$SD = Get-SecurityDescriptor $PathToTestFolder

$RawSD = New-Object System.Security.AccessControl.RawSecurityDescriptor $SD.GetSecurityDescriptorSddlForm("All")
$RawSD.DiscretionaryAcl[10].AccessMask = $RawSD.DiscretionaryAcl[9].AccessMask

$RawSD.DiscretionaryAcl.InsertAce(0, (New-AccessControlEntry -Principal Syd -AceType AccessDenied -FolderRights Write -OutputRuleType System.Security.AccessControl.CommonAce))
$RawSD.DiscretionaryAcl.InsertAce(0, (New-AccessControlEntry -Principal Users -FolderRights ListDirectory -OutputRuleType System.Security.AccessControl.CommonAce))
$mod = Get-Module PowerShellAccessControl
& $mod { SetSecurityInfo -SdPath (New-Object ROE.PowerShellAccessControl.SecurityDescriptorStringPath $PathToTestFolder) -ObjectType FileObject -DiscretionaryAcl $RawSD.DiscretionaryAcl }

$BadSd = Get-SecurityDescriptor $PathToTestFolder
$BadSd.AreAccessRulesCanonical

$CommonSd = New-Object System.Security.AccessControl.CommonSecurityDescriptor $true, $false, $RawSD