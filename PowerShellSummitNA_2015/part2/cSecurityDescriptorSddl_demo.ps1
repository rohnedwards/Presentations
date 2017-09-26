Import-Module PowerShellAccessControl

return  # Prevent running entire script

$DscSddlTestFolder = "C:\powershell\dsc_demo\dsc_sddl_test\subfolder"
$DscSddlTestFile = "$DscSddlTestFolder\file"
$DscOutputFolder = "C:\powershell\dsc_demo\dsc_configs"
$DscSddlTestRegKey = "HKLM:\SOFTWARE\dsc_demo\dsc_sddl_test\subkey"

function PrepareDemo {
    param(
        [Switch] $Force
    )

    # We need to start fresh:
    Split-Path $DscSddlTestFolder | Remove-Item -ErrorAction SilentlyContinue -Confirm
    Split-Path $DscSddlTestRegKey | Remove-Item -ErrorAction SilentlyContinue -Confirm

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
Set-PacOwner $DscSddlTestFolder -Principal Users -Apply -PassThru -Force

# Now run DSC configuration:
Start-DscConfiguration $DscOutputFolder -Verbose -Wait

# Check owner:
$DscSddlTestFolder | Get-PacSecurityDescriptor

# Create a new configuration that tests the owner and DACL:
$SddlOwnerDaclTestSddlString = "O:BAD:AI(A;OICI;0x1200a9;;;WD)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)"
Configuration SddlOwnerDaclTest {
    param(
        [string[]] $ComputerName = "localhost"
    )

    Import-DscResource -Module PowerShellAccessControl

    Node $ComputerName {

        cSecurityDescriptorSddl SddlOwnerDaclTest {  
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

# This is the same as the Owner/DACL example in cSecurityDescriptor

# Now, look at the folder's current DACL:
Get-PacAccessControlEntry $DscSddlTestFolder  # Before
Start-DscConfiguration $DscOutputFolder -Verbose -Wait
Get-PacAccessControlEntry $DscSddlTestFolder  # After

# Compare that to $SD, and notice that the inherited ACEs make it so the DACL isn't
# exactly as defined, but they are being ignored
$SD.Access

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

Get-PacAccessControlEntry $DscSddlTestFolder

# Right now, resource can't change it itself. You'd need another resource to change the parent; we'll change it manually. Let's
# put the 4 desired ACEs in the parent's DACL:
Split-Path $DscSddlTestFolder | 
    Get-PacAccessControlEntry -ExcludeInherited |
    Remove-PacAccessControlEntry -RemoveAllAccessEntries -PassThru | 
    Add-PacAccessControlEntry -AceObject $SD.Access -Apply -Force

# This still won't work. Remember, SDDL said that the 4 ACEs aren't inherited
Start-DscConfiguration $DscOutputFolder -Verbose -Wait

# To fix it, we need to get rid of the inherited ACEs:
Split-Path $DscSddlTestFolder | 
    Get-PacAccessControlEntry -ExcludeInherited |
    Remove-PacAccessControlEntry -RemoveAllAccessEntries -PassThru |
    Add-PacAccessControlEntry -Principal Everyone -FolderRights ReadAndExecute -AppliesTo Object -Apply -Force

# Now Test works w/o running configuration again:
Test-DscConfiguration -Verbose

  
# Let's make some ACL changes:
Get-PacAccessControlEntry $DscSddlTestFolder
Disable-PacAclInheritance $DscSddlTestFolder -PreserveExistingAces -PassThru | 
    Add-PacAccessControlEntry -Principal Everyone -FolderRights FullControl -AppliesTo ChildContainers, ChildObjects -Apply
Get-PacAccessControlEntry $DscSddlTestFolder

Start-DscConfiguration $DscOutputFolder -Verbose -Wait
Get-PacAccessControlEntry $DscSddlTestFolder


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


