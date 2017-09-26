Import-Module PowerShellAccessControl

$DscSddlTestFolder = "C:\powershell\dsc_demo\dsc_ace_test"
$DscOutputFolder = "C:\powershell\dsc_demo\dsc_configs"
$DscSddlTestRegKey = "HKLM:\SOFTWARE\dsc_demo\dsc_ace_test"

# We need to start fresh:
Split-Path $DscSddlTestFolder | Remove-Item -Confirm
Split-Path $DscSddlTestRegKey | Remove-Item -Confirm

# Make sure paths exist (could be done w/ DSC)
New-Item $DscSddlTestFolder, $DscOutputFolder -ItemType directory | Out-Null
New-Item $DscSddlTestRegKey -Force | Out-Null

# Change some permissions
Split-Path $DscSddlTestFolder -Parent | 
    Disable-PacAclInheritance -Apply -PassThru -Force | 
    Add-PacAccessControlEntry -Principal Users -FolderRights Modify -PassThru | 
    Add-PacAccessControlEntry -Principal Administrators -FolderRights FullControl -Apply -Force

Configuration cAceTest {
    param(
        [string[]] $ComputerName = "localhost"
    )

    Import-DscResource -Module PowerShellAccessControl

    Node $ComputerName {

        cAccessControlEntry UsersModifyFolder {
            Ensure = "Present"
            Path = $DscSddlTestFolder
            AceType = "Allow"
            ObjectType = "Directory"
            AccessMask = New-PacAccessMask -FolderRights Modify
            Principal = "Users"
        }

        cAccessControlEntry UsersDenyDeleteFolder {
            Ensure = "Present"
            Path = $DscSddlTestFolder
            AceType = "Deny"
            ObjectType = "Directory"
            AccessMask = New-PacAccessMask -FolderRights Delete
            Principal = "Users"
            AppliesTo = "Object"
        }

        cAccessControlEntry EveryoneCantDeleteFolder {
            Ensure = "Absent"
            Path = $DscSddlTestFolder
            AceType = "Allow"
            ObjectType = "Directory"
            AccessMask = New-PacAccessMask -FolderRights Delete
            Principal = "Everyone"
            AppliesTo = "Object"
        }

        cAccessControlEntry EveryoneAuditFailuresOnFolder {
            Ensure = "Present"
            Path = $DscSddlTestFolder
            AceType = "Audit"
            ObjectType = "Directory"
            AccessMask = New-PacAccessMask -FolderRights FullControl
            Principal = "Everyone"
            AuditFlags = "Failure"
        }
    }
}
cAceTest -OutputPath $DscOutputFolder

<#
That configuration ensures the following:
1. ACE is present: Allow Users Modify permission to the Folder, SubFolders, and Files (not specific)
2. ACE is present: Deny Users Delete permission to the Folder only (not specific)
3. Access is absent: Allow Everyone Delete permission to the Folder only (not specific)
4. ACE is present: Audit all Failed access for the Folder, SubFolders, and Files (not specific)
#>
$SDOption = New-PacSDOption -Audit
Get-PacAccessControlEntry $DscSddlTestFolder -PacSDOption $SDOption
Start-DscConfiguration $DscOutputFolder -Wait -Verbose
Get-PacAccessControlEntry $DscSddlTestFolder -PacSDOption $SDOption

<#
Let's revisit the four conditions above:
ACE is present: Allow Users Modify permission to the Folder, SubFolders, and Files (not specific)

That ACE was added. Users had no explicit ACEs, but there was an inherited ACE that granted this. Since TestInheritedAces wasn't specified (so it was $false), the inherited ACE didn't count, and a new one was created. What happens when you change that ACE to Allow FullControl?
#>
Add-PacAccessControlEntry $DscSddlTestFolder -AceType Allow -Principal Users -FolderRights FullControl -Apply -PassThru | Get-PacAccessControlEntry
Test-DscConfiguration

<#
It still passes because Modify is included in Full control, and Specific wasn't set to $true

Next condition:
ACE is present: Deny Users Delete permission to the Folder only (not specific)

This is just like the previous check. We could modify this ACE, but as long as Delete is present for the Folder, it will be considered in compliance.

Next condition:
Access is absent: Allow Everyone Delete permission to the Folder only (not specific)

Everyone clearly doesn't have Delete permission. What happens if we give them FullControl?
#>
Add-PacAccessControlEntry $DscSddlTestFolder -AceType Allow -Principal Everyone -FolderRights FullControl -Apply -PassThru | Get-PacAccessControlEntry
Test-DscConfiguration

# Test fails. Run it again:
Start-DscConfiguration $DscOutputFolder -Wait -Verbose
Get-PacAccessControlEntry $DscSddlTestFolder -PacSDOption $SDOption

# Notice all the other access is still there. The only right missing is Delete from the Folder itself...

# Last condition is similar to the first 2, just four SACL instead of DACL.

# Start over:
Get-PacSecurityDescriptor $DscSddlTestFolder -Audit | Remove-PacAccessControlEntry -RemoveAllAccessEntries -RemoveAllAuditEntries -Apply
Get-PacAccessControlEntry $DscSddlTestFolder -PacSDOption $SDOption

Configuration cAceTest {
    param(
        [string[]] $ComputerName = "localhost"
    )

    Import-DscResource -Module PowerShellAccessControl

    Node $ComputerName {

        cAccessControlEntry UsersModifyFolder {
            Ensure = "Present"
            Path = $DscSddlTestFolder
            AceType = "Allow"
            ObjectType = "Directory"
            AccessMask = New-PacAccessMask -FolderRights Modify, Synchronize
            Principal = "Users"
            Specific = $true
            TestInheritedAces = $true
        }

        cAccessControlEntry EveryoneCantDeleteFolder {
            Ensure = "Absent"
            Path = $DscSddlTestFolder
            AceType = "Allow"
            ObjectType = "Directory"
            AccessMask = New-PacAccessMask -FolderRights Delete, Synchronize
            Principal = "Everyone"
            AppliesTo = "Object"
            Specific = $true
            TestInheritedAces = $true
        }
    }
}
cAceTest -OutputPath $DscOutputFolder

<#
Two conditions:
1. ACE is present: Allow Users Modify permission to the Folder, SubFolders, and Files (specific, and inherited ACEs will work)
2. Access is absent: Allow Everyone Delete permission to the Folder only (specific, and inherited ACEs will cause this to fail)
#>
Start-DscConfiguration $DscOutputFolder -Wait -Verbose
Get-PacAccessControlEntry $DscSddlTestFolder -PacSDOption $SDOption

# No change. The inherited Users ACE satisfies the check, and Everyone does not have 'Delete'. What if we give 'Everyone' FullControl again?
Add-PacAccessControlEntry $DscSddlTestFolder -Principal Everyone -FolderRights FullControl -Apply -PassThru | Get-PacAccessControlEntry
Test-DscConfiguration

# It still passes because the ACE doesn't exactly match the config (remember, Specific = $true). What if we put that ACE on the parent
Split-Path $DscSddlTestFolder | Add-PacAccessControlEntry -Principal Everyone -FolderRights Delete -AppliesTo ChildContainers, DirectChildrenOnly -Apply -PassThru
Get-PacAccessControlEntry $DscSddlTestFolder

Test-DscConfiguration
Start-DscConfiguration $DscOutputFolder -Wait -Verbose

# Can't fix it

