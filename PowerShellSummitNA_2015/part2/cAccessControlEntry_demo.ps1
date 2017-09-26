Import-Module PowerShellAccessControl

return  # Prevent running entire script

$DscSddlTestFolder = "C:\powershell\dsc_demo\dsc_ace_test\subfolder"
$DscOutputFolder = "C:\powershell\dsc_demo\dsc_configs"
$DscSddlTestRegKey = "HKLM:\SOFTWARE\dsc_demo\dsc_ace_test\subkey"

function PrepareDemo {
    param(
        [Switch] $Force
    )

    # We need to start fresh:
    Split-Path $DscSddlTestFolder | Remove-Item -ErrorAction SilentlyContinue -Recurse -Confirm:(-not $Force)
    Split-Path $DscSddlTestRegKey | Remove-Item -ErrorAction SilentlyContinue -Recurse -Confirm:(-not $Force)

    # Make sure paths exist (could be done w/ DSC)
    New-Item $DscSddlTestFolder, $DscOutputFolder -ItemType directory -ErrorAction SilentlyContinue | Out-Null
    New-Item $DscSddlTestRegKey -Force | Out-Null

    # Change some permissions
    Split-Path $DscSddlTestFolder -Parent | 
        Disable-PacAclInheritance -Apply -PassThru -Force | 
        Add-PacAccessControlEntry -Principal Users -FolderRights Modify -PassThru | 
        Add-PacAccessControlEntry -Principal Administrators -FolderRights FullControl -Apply -Force
}

PrepareDemo


# Define a configuration:
Configuration cAceTest {
    param(
        [string[]] $ComputerName = "localhost"
    )

    Import-DscResource -Module PowerShellAccessControl

    Node $ComputerName {

        # ACE that grants 'Users' 'Modify' file/folder rights to O CC CO (folder, subfolders, files)
        # Make sure that ACE is present on $DscSddlTestFolder
        cAccessControlEntry UsersModifyFolder {
            Ensure = "Present"
            Path = $DscSddlTestFolder
            AceType = "Allow"
            ObjectType = "Directory"
            AccessMask = New-PacAccessMask -FolderRights Modify
            Principal = "Users"
        }

        # ACE that denies 'Users' the 'Delete' file/folder right to O (the file/folder only)
        # Make sure that this ACE is present on $DscSddlTestFolder
        cAccessControlEntry UsersDenyDeleteFolder {
            Ensure = "Present"
            Path = $DscSddlTestFolder
            AceType = "Deny"
            ObjectType = "Directory"
            AccessMask = New-PacAccessMask -FolderRights Delete
            Principal = "Users"
            AppliesTo = "Object"
        }

        # ACE that allows 'Everyone' 'Delete' file/folder rights to O (the file/folder only)
        # Make sure that this ACE DOES NOT exist on $DscSddlTestFolder (so only the specific
        # access granted by this ACE will be removed if an ACE with these rights is present)
        cAccessControlEntry EveryoneCantDeleteFolder {
            Ensure = "Absent"
            Path = $DscSddlTestFolder
            AceType = "Allow"
            ObjectType = "Directory"
            AccessMask = New-PacAccessMask -FolderRights Delete
            Principal = "Everyone"
            AppliesTo = "Object"
        }

        # ACE that audits failures for any accesses by the 'Everyone' group
        # Make sure that this ACE is present on $DscSddlTestFolder
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
Condition #1 above required Users to have Modify permission.

There was already an inherited ACE granting that, but disnce TestInheritedAces wasn't specified (it was effectively
set to $false), the inherited ACEs weren't checked.

What happens if we give Users FullControl instead of Modify permissions?#>
Add-PacAccessControlEntry $DscSddlTestFolder -AceType Allow -Principal Users -FolderRights FullControl -Apply -PassThru | Get-PacAccessControlEntry
Test-DscConfiguration

<#
It still passes because Modify is included in Full control, and Specific wasn't set to $true

Condition #2 above required Users to be denied Delete permission to the folder only.

This is just like the previous check. We could modify this ACE, but as long as Delete is present for the Folder, it will be considered in compliance.

Condition #3 above required that Everyone not have Delete permission to the Folder only. There were no ACEs granting Everyone any access, so that
condition is met without having to do any work. What happens if we give them FullControl?
#>
Add-PacAccessControlEntry $DscSddlTestFolder -AceType Allow -Principal Everyone -FolderRights FullControl -Apply -PassThru | Get-PacAccessControlEntry
Test-DscConfiguration

# Test fails. Run it again:
Start-DscConfiguration $DscOutputFolder -Wait -Verbose
Get-PacAccessControlEntry $DscSddlTestFolder -PacSDOption $SDOption

# Notice all the other access is still there. The only right missing is Delete from the Folder itself...

# Last condition is similar to the first 2, just for SACL instead of DACL.

# Start over:
#PrepareDemo
Get-PacSecurityDescriptor $DscSddlTestFolder -Audit | Remove-PacAccessControlEntry -RemoveAllAccessEntries -RemoveAllAuditEntries -Apply
Get-PacAccessControlEntry $DscSddlTestFolder -PacSDOption $SDOption

<#
Two conditions:
1. ACE is present: Allow Users Modify permission to the Folder, SubFolders, and Files (the ACE is specific; inherited ACEs will be checked)
2. Access is absent: Allow Everyone Delete permission to the Folder only (the ACE is specific; inherited ACEs will be checked)
#>
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

Start-DscConfiguration $DscOutputFolder -Wait -Verbose
Get-PacAccessControlEntry $DscSddlTestFolder -PacSDOption $SDOption

# No change to SD made. The inherited Users ACE satisfies the check, and Everyone does not have 'Delete'. What if we give 'Everyone' FullControl again?
Add-PacAccessControlEntry $DscSddlTestFolder -Principal Everyone -FolderRights FullControl -Apply -PassThru | Get-PacAccessControlEntry
Test-DscConfiguration

# It still passes because the ACE doesn't exactly match the config (remember, Specific = $true). What if we put that ACE on the parent
Split-Path $DscSddlTestFolder | Add-PacAccessControlEntry -Principal Everyone -FolderRights Delete -AppliesTo ChildContainers, DirectChildrenOnly
Get-PacAccessControlEntry $DscSddlTestFolder

Test-DscConfiguration
Start-DscConfiguration $DscOutputFolder -Wait -Verbose

# Can't fix it because the ACE that's breaking compliance is being inherited. 

