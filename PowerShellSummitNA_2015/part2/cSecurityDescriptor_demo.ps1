Import-Module PowerShellAccessControl

return  # Prevent running entire script

$DscSddlTestFolder = "C:\powershell\dsc_demo\dsc_sd_test\subfolder"
$DscSddlTestFile = "$DscSddlTestFolder\file"
$DscOutputFolder = "C:\powershell\dsc_demo\dsc_configs"
$DscSddlTestRegKey = "HKLM:\SOFTWARE\dsc_demo\dsc_sd_test\subkey"

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
    New-Item $DscSddlTestFile -ItemType file | Out-Null

    # Change some permissions
    Split-Path $DscSddlTestFolder -Parent | 
        Disable-PacAclInheritance -Apply -PassThru -Force | 
        Add-PacAccessControlEntry -Principal Users -FolderRights Modify -PassThru | 
        Add-PacAccessControlEntry -Principal Administrators -FolderRights FullControl -Apply -Force
}

PrepareDemo

<# 
    Define a configuration that sets the owner to 'Administrators' on
    the $DscSddlTestFolder folder
    No other parts of the folder's security descriptor are tested/modified.
#>
Configuration SdOwnerTest {
    param(
        [string[]] $ComputerName = "localhost"
    )

    Import-DscResource -Module PowerShellAccessControl

    Node $ComputerName {

        cSecurityDescriptor TestFolderSdOwner {  # This sets the owner to Administrators
            Path = $DscSddlTestFolder
            ObjectType = "Directory"
            Owner = "Administrators"
        }
    }
}
SdOwnerTest -OutputPath $DscOutputFolder

# Take ownership of the folder:
Set-PacOwner $DscSddlTestFolder
$DscSddlTestFolder | Get-PacSecurityDescriptor

# Now run DSC configuration:
Start-DscConfiguration $DscOutputFolder -Verbose -Wait

# Check owner:
$DscSddlTestFolder | Get-PacSecurityDescriptor
Test-DscConfiguration

# Change the owner
Set-PacOwner $DscSddlTestFolder -Principal Users -Apply -PassThru -Force
Test-DscConfiguration
Get-DscConfiguration

Start-DscConfiguration $DscOutputFolder -Verbose -Wait

# If you Test/Get now, it's good. Note that only the owner is touched. You can change any other part of the security descriptor, and the test won't care:
Get-PacAccessControlEntry $DscSddlTestFolder -Principal Everyone
Add-PacAccessControlEntry $DscSddlTestFolder -Principal Everyone -FolderRights FullControl -Force

# This will still be true
Test-DscConfiguration

<#
    Define a configuration that sets the owner to 'Administrators' on
    the $DscSddlTestFolder folder, and that ensures the DACL has
    4 ACEs explicitly defined.
#>
Configuration SdOwnerDaclTest {
    param(
        [string[]] $ComputerName = "localhost"
    )

    Import-DscResource -Module PowerShellAccessControl

    Node $ComputerName {

        cSecurityDescriptor SdOwnerDaclTest {
            Path = $DscSddlTestFolder
            ObjectType = "Directory"
            Owner = "Administrators"
            Access = @"
                Principal, FolderRights
                Everyone, "ReadAndExecute, Synchronize"
                Administrators, FullControl
                SYSTEM, FullControl
                Users, "ReadAndExecute, Synchronize"
"@
        }
    }
}
SdOwnerDaclTest -OutputPath $DscOutputFolder

# Now, look at the folder's current DACL:
Get-PacAccessControlEntry $DscSddlTestFolder  # Before
Start-DscConfiguration $DscOutputFolder -Verbose -Wait
Get-PacAccessControlEntry $DscSddlTestFolder  # After

# All of the ACEs were created, even though there were some inherited ACEs that would have worked. Try it
# with an identical configuration, except TestInheritedAces = $true:
Configuration SdOwnerDaclTestInherited {
    param(
        [string[]] $ComputerName = "localhost"
    )

    Import-DscResource -Module PowerShellAccessControl

    Node $ComputerName {

        cSecurityDescriptor SdOwnerDaclTest {
            Path = $DscSddlTestFolder
            ObjectType = "Directory"
            Owner = "Administrators"
            Access = @"
                Principal, FolderRights
                Everyone, "ReadAndExecute, Synchronize"
                Administrators, FullControl
                SYSTEM, FullControl
                Users, "ReadAndExecute, Synchronize"
"@
            TestInheritedAces = $true
        }
    }
}
SdOwnerDaclTestInherited -OutputPath $DscOutputFolder

Start-DscConfiguration $DscOutputFolder -Verbose -Wait
Get-PacAccessControlEntry $DscSddlTestFolder

# A warning is displayed because there is a 'Users' ACE that isn't in our
# DACL CSV being inherited. Since we told the resource to test inherited ACEs,
# it sees that but can't fix it. Let's modify it:
Test-DscConfiguration # fails
Split-Path $DscSddlTestFolder |
    Add-PacAccessControlEntry -Principal Users -FolderRights ReadAndExecute -Overwrite
Get-PacAccessControlEntry $DscSddlTestFolder

Test-DscConfiguration # still fails because now there are two Users ACEs
Start-DscConfiguration $DscOutputFolder -Verbose -Wait
Get-PacAccessControlEntry $DscSddlTestFolder
Test-DscConfiguration # Now it works



# Let's go back to the original Owner/DACL configuration that didn't have TestInheritedAces 
# (so it was treated as being equal to $False)
SdOwnerDaclTest -OutputPath $DscOutputFolder

Start-DscConfiguration $DscOutputFolder -Verbose -Wait

# We're back to having four explicit ACEs since inherited ACEs aren't being checked
Get-PacAccessControlEntry $DscSddlTestFolder

<# 
A configuration for a registry key that tests the Owner, DACL, and 
SACL (including inheritance on both ACLs)

Owner: Current demo user
DACL: Inheritance Disabled with 2 ACEs:
  Allow Users FullControl to the Key and Subkeys
  Deny Users Delete to the Key only

SACL: Inheritance Enabled with 1 ACE:
  Audit Everyone Successful and Failed CreateSubKey
#>
Configuration SdSaclRegKeyTest {
    param(
        [string[]] $ComputerName = "localhost"
    )

    Import-DscResource -Module PowerShellAccessControl

    Node $ComputerName {

        cSecurityDescriptor SdRegKeySaclTest { 
            Path = $DscSddlTestRegKey
            ObjectType = "RegistryKey"
            Owner = $env:USERNAME
            AccessInheritance = "Disabled"
            Access = @"
                AceType, Principal, RegistryRights, AppliesTo
                Deny, Users, Delete, Object
                Allow, Users, FullControl, "Object, ChildContainers"
"@
            AuditInheritance = "Enabled"
            Audit = @"
                Principal, AccessMask, AuditFlags
                Everyone, 4, "Success, Failure"
"@
        }
    }
}
SdSaclRegKeyTest -OutputPath $DscOutputFolder

$SDOption = New-PacSDOption -Audit
Get-PacAccessControlEntry $DscSddlTestRegKey -PacSDOption $SDOption
Start-DscConfiguration $DscOutputFolder -Verbose -Wait
Get-PacAccessControlEntry $DscSddlTestRegKey -PacSDOption $SDOption

# Change SACL inheritance
Disable-PacAclInheritance $DscSddlTestRegKey -SystemAcl -PacSDOption $SDOption
Enable-PacAclInheritance $DscSddlTestRegKey # Defaults to DACL
Split-Path $DscSddlTestRegKey | Add-PacAccessControlEntry -AceType Audit -Principal Everyone -AuditFlags Failure -RegistryRights FullControl -PacSDOption $SdOption
Get-PacAccessControlEntry $DscSddlTestRegKey -PacSDOption $SDOption

# Fix it
Start-DscConfiguration $DscOutputFolder -Verbose -Wait
Get-PacAccessControlEntry $DscSddlTestRegKey -PacSDOption $SDOption


# File test:
Configuration SdFileTest {
    param(
        [string[]] $ComputerName = "localhost"
    )

    Import-DscResource -Module PowerShellAccessControl

    Node $ComputerName {

        cSecurityDescriptor SdFileTest {  # This sets the owner to Administrators
            Path = $DscSddlTestFile
            ObjectType = "File"
            Owner = $env:USERNAME
            AccessInheritance = "Disabled"
            Access = @"
                AceType, Principal, FileRights
                Allow, Users, FullControl
                Allow, Everyone, "Read, Synchronize"
"@
            AuditInheritance = "Enabled"
            Audit = @"
                Principal, AccessMask, AuditFlags
                Everyone, 2032127, "Success, Failure"
"@
        }
    }
}
SdFileTest -OutputPath $DscOutputFolder


Get-PacAccessControlEntry $DscSddlTestFile -PacSDOption $SDOption
Start-DscConfiguration $DscOutputFolder -Verbose -Wait
