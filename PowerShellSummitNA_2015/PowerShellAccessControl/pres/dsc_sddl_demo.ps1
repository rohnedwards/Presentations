Import-Module PowerShellAccessControl

$DscSddlTestFolder = "C:\powershell\dsc_demo\dsc_sddl_test"
$DscOutputFolder = "C:\powershell\dsc_demo\dsc_configs"
$DscSddlTestRegKey = "HKLM:\SOFTWARE\dsc_demo\dsc_sddl_test"

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

Configuration SddlOwnerTest {
    param(
        [string[]] $ComputerName = "localhost"
    )

    Import-DscResource -Module PowerShellAccessControl

    Node $ComputerName {

        cSecurityDescriptorSddl TestFolderSdOwner {  # This sets the owner to Administrators
            Path = $DscSddlTestFolder
            ObjectType = "Directory"
            Sddl = "O:BA"
        }
    }
}
SddlOwnerTest -OutputPath $DscOutputFolder

# First see current owner:
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
$SddlOwnerDaclTestSddlString = "O:BAD:AI(A;OICI;0x1200a9;;;WD)(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)(A;OICIID;0x1200a9;;;BU)"
Configuration SddlOwnerDaclTest {
    param(
        [string[]] $ComputerName = "localhost"
    )

    Import-DscResource -Module PowerShellAccessControl

    Node $ComputerName {

        cSecurityDescriptorSddl SddlOwnerDaclTest {  # This sets the owner to Administrators
            Path = $DscSddlTestFolder
            ObjectType = "Directory"
            Sddl = $SddlOwnerDaclTestSddlString
        }
    }
}
SddlOwnerDaclTest -OutputPath $DscOutputFolder

# What does that Sddl string mean?
$SD = New-PacSecurityDescriptor -ObjectType FileObject -IsContainer -Sddl $SddlOwnerDaclTestSddlString
$SD.Access

# Notice there are inherited ACEs. This will be important later

# Now, look at the folder's current DACL:
Get-PacAccessControlEntry $DscSddlTestFolder  # Before
Start-DscConfiguration $DscOutputFolder -Verbose -Wait
Get-PacAccessControlEntry $DscSddlTestFolder  # After

# Compare that to $SD, and notice that the inherited ACEs don't match, but the LCM says it's compliant
$SD.Access
Test-DscConfiguration -Verbose
Get-DscConfiguration

# That's because TestInheritedAces is false; if we change it to true, this happens:
Configuration SddlOwnerDaclTestInherited {
    param(
        [string[]] $ComputerName = "localhost"
    )

    Import-DscResource -Module PowerShellAccessControl

    Node $ComputerName {

        cSecurityDescriptorSddl SddlOwnerDaclTestInherited {  # This sets the owner to Administrators
            Path = $DscSddlTestFolder
            ObjectType = "Directory"
            Sddl = $SddlOwnerDaclTestSddlString
            TestInheritedAces = $true
        }
    }
}
SddlOwnerDaclTestInherited -OutputPath $DscOutputFolder
Start-DscConfiguration $DscOutputFolder -Verbose -Wait
Test-DscConfiguration -Verbose
Get-DscConfiguration

# Right now, resource can't change it itself. You'd need another resource to change the parent; we'll change it manually:
Split-Path $DscSddlTestFolder | 
    Remove-PacAccessControlEntry -RemoveAllAccessEntries -PassThru | 
    Add-PacAccessControlEntry -AceObject ($SD.Access | where IsInherited | New-PacAccessControlEntry) -Apply

# Now Test works:
Test-DscConfiguration -Verbose
  
# Let's make some ACL changes:
Disable-PacAclInheritance $DscSddlTestFolder -PreserveExistingAces -PassThru | 
    Add-PacAccessControlEntry -Principal Everyon -FolderRights FullControl -AppliesTo ChildContainers, ChildObjects -Apply

Test-DscConfiguration -Verbose


$SddlOwnerDaclTestSddlString = "S:AI(AU;FA;KA;;;WD)(AU;SA;SD;;;WD)"
Configuration SddlSaclRegKeyTest {
    param(
        [string[]] $ComputerName = "localhost"
    )

    Import-DscResource -Module PowerShellAccessControl

    Node $ComputerName {

        cSecurityDescriptorSddl SddlRegKeySaclTest {  # This sets the owner to Administrators
            Path = $DscSddlTestRegKey
            ObjectType = "RegistryKey"
            Sddl = $SddlOwnerDaclTestSddlString
            TestInheritedAces = $true
        }
    }
}
SddlSaclRegKeyTest -OutputPath $DscOutputFolder

$SDOption = New-PacSDOption -Audit
Get-PacAccessControlEntry $DscSddlTestRegKey -PacSDOption $SDOption -AceType Audit
Start-DscConfiguration $DscOutputFolder -Verbose -Wait
Get-PacAccessControlEntry $DscSddlTestRegKey -PacSDOption $SDOption -AceType Audit


