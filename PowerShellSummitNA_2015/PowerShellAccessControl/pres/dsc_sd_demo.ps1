Import-Module PowerShellAccessControl

$DscSddlTestFolder = "C:\powershell\dsc_demo\dsc_sd_test"
$DscOutputFolder = "C:\powershell\dsc_demo\dsc_configs"
$DscSddlTestRegKey = "HKLM:\SOFTWARE\dsc_demo\dsc_sd_test"

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

# First see current owner:
Set-PacOwner $DscSddlTestFolder
$DscSddlTestFolder | Get-PacSecurityDescriptor


# Now run DSC configuration:
Start-DscConfiguration $DscOutputFolder -Verbose -Wait

# Check owner:
$DscSddlTestFolder | Get-PacSecurityDescriptor
Test-DscConfiguration -Verbose

# Change the owner
Set-PacOwner $DscSddlTestFolder -Principal Users -Apply -PassThru -Force
Test-DscConfiguration -Verbose
Get-DscConfiguration

Start-DscConfiguration $DscOutputFolder -Verbose -Wait

# If you Test/Get now, it's good. Note that only the owner is touched. You can change any other part of the security descriptor, and the test won't care:
Get-PacAccessControlEntry $DscSddlTestFolder -Principal Everyone
Add-PacAccessControlEntry $DscSddlTestFolder -Principal Everyone -FolderRights FullControl -Force

# This will still be true
Test-DscConfiguration

# Create a new configuration that tests the owner and DACL:
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
# with TestInheritedAces:
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

<#
Starting from this:

    Path       : C:\powershell\dsc_demo\dsc_sd_test
    Owner      : BUILTIN\Administrators
    Inheritance: DACL Inheritance Enabled


AceType    Principal                                AccessMask                               InheritedFrom                           AppliesTo                              
-------    ---------                                ----------                               -------------                           ---------                              
Allow      Administrators                           FullControl                              C:\powershell\dsc_demo\                 O CC CO                                
Allow      otheruser                                Read, Synchronize                        C:\powershell\dsc_demo\                 O CC CO                                

The config won't be able to succeed if you TestInheritedAces. Afterwards, you get this:

    Path       : C:\powershell\dsc_demo\dsc_sd_test
    Owner      : BUILTIN\Administrators
    Inheritance: DACL Inheritance Enabled


AceType    Principal                                AccessMask                               InheritedFrom                           AppliesTo                              
-------    ---------                                ----------                               -------------                           ---------                              
Allow      Everyone                                 ReadAndExecute, Synchronize              <not inherited>                         O CC CO                                
Allow      SYSTEM                                   FullControl                              <not inherited>                         O CC CO                                
Allow      Users                                    ReadAndExecute, Synchronize              <not inherited>                         O CC CO                                
Allow      Administrators                           FullControl                              C:\powershell\dsc_demo\                 O CC CO                                
Allow      otheruser                                Read, Synchronize                        C:\powershell\dsc_demo\                 O CC CO                                

The 'otheruser' inherited ACE messes it up. Notice a new Administrators ACE isn't created (the inherited one works).

What happens if you change the Administrators ACE to not be FullControl:

AceType    Principal                                AccessMask                               InheritedFrom                           AppliesTo                              
-------    ---------                                ----------                               -------------                           ---------                              
Allow      Administrators                           Write, ReadAndExecute,                   C:\powershell\dsc_demo\                 O CC CO                                
                                                    ChangePermissions, TakeOwnership,                                                                                       
#>

# To do that, run this:
Split-Path $DscSddlTestFolder | 
    Remove-PacAccessControlEntry -Principal administrators -FolderRights Delete, DeleteSubdirectoriesAndFiles
Get-PacAccessControlEntry $DscSddlTestFolder

# Now there is no longer an ACE granting Administrators FullControl. Running config again should create a new one.
# NOTE: An entire ACE is created. Remember, the resource is attempting to make the ACL(s) match exactly. TestInheritedAces allows inherited ACEs to count, but if the exact ACE isn't there, one will be created.
Start-DscConfiguration $DscOutputFolder -Verbose -Wait
Get-PacAccessControlEntry $DscSddlTestFolder

# Let's fix the inherited ACE to be FullControl again and rerun the config. The explicit ACE should be gone:
Split-Path $DscSddlTestFolder | 
    Add-PacAccessControlEntry -Principal administrators -FolderRights FullControl -Apply -PassThru |
    Get-PacAccessControlEntry

Start-DscConfiguration $DscOutputFolder -Verbose -Wait
Get-PacAccessControlEntry $DscSddlTestFolder

# Remember, that other inherited ACE is going to keep the configuration from being compliant:
Test-DscConfiguration

# Let's get rid of that
Split-Path $DscSddlTestFolder | 
    Get-PacAccessControlEntry -Principal (New-Object ROE.PowerShellAccessControl.PrincipalAceFilter "Administrators", $false, $true) -ExcludeInherited | 
    Remove-PacAccessControlEntry

Get-PacAccessControlEntry $DscSddlTestFolder
Test-DscConfiguration

# Test returns true b/c the ACL is right now: there are 4 entries, with matching AceType, Principal, AccessMask, and AppliesTo. One is inherited, but that's allowed because TestInheritedAces is true. Try it again with the identical configuration, but w/o TestInheritedAces:
Configuration SdOwnerDaclTestInheritedFalse {
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
            TestInheritedAces = $false
        }
    }
}
SdOwnerDaclTestInheritedFalse -OutputPath $DscOutputFolder

Start-DscConfiguration $DscOutputFolder -Verbose -Wait
Get-PacAccessControlEntry $DscSddlTestFolder
Test-DscConfiguration

# Notice that the inherited Administrators ACE wasn't good anymore, so an explicit one was created.

<# 
Registry test:

Owner: Current demo user
DACL: Inheritance Enabled with 2 ACEs:
Allow Users FullControl to the Key and Subkeys
Deny Users Delete to the Key only

SACL: Inheritance Disabled with 1 ACE:
Audit Everyone Successful and Failed CreateSubKey
#>
Configuration SdSaclRegKeyTest {
    param(
        [string[]] $ComputerName = "localhost"
    )

    Import-DscResource -Module PowerShellAccessControl

    Node $ComputerName {

        cSecurityDescriptor SdRegKeySaclTest {  # This sets the owner to Administrators
            Path = $DscSddlTestRegKey
            ObjectType = "RegistryKey"
            Owner = $env:USERNAME
            AccessInheritance = "Enabled"
            Access = @"
                AceType, Principal, RegistryRights, AppliesTo
                Deny, Users, Delete, Object
                Allow, Users, FullControl
"@
            AuditInheritance = "Disabled"
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



# File test:
$DscSddlTestFile = "$DscSddlTestFolder\file"
New-Item $DscSddlTestFile -ItemType file | Out-Null
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
                Allow, limiteduser, FullControl
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
