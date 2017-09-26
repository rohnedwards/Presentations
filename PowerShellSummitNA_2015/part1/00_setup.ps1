#requires -version 4

# Set up folder structure for testing:
$RootFolderPath = "C:\powershell\access_control"

Configuration PresentationSetup {

    Import-DscResource -Module PowerShellAccessControl

    $InheritSD = "$RootFolderPath\InheritSD"
    $NoAccess = "$RootFolderPath\NoAccess"
    $DontInheritSD = "$RootFolderPath\DontInheritSD"
    $SomeExtraAces = "$RootFolderPath\SomeExtraAces"
    $TestFile = "$RootFolderPath\SomeExtraAces\testfile.txt"

    Node $env:ComputerName {

        File InheritSd {
            Ensure = "Present"
            Type = "Directory"
            DestinationPath = $InheritSD
        }

        File NoAccess {
            Ensure = "Present"
            Type = "Directory"
            DestinationPath = $NoAccess
        }

        File DontInheritSD {
            Ensure = "Present"
            Type = "Directory"
            DestinationPath = $DontInheritSD
        }

        File SomeExtraAces {
            Ensure = "Present"
            Type = "Directory"
            DestinationPath = $SomeExtraAces
        }

        File TestFile {
            Ensure = "Present"
            Type = "File"
            Contents = "This is a test"
            DestinationPath = $TestFile
        }

        # Root folder needs an audit ACE
        cAccessControlEntry RootAuditAce {
            Path = $RootFolderPath
            ObjectType = "Directory"
            Principal = "Everyone"
            AceType = "Audit"
            AuditFlags = "Success"
            AccessMask = New-PacAccessMask -FolderRights Delete
            DependsOn = "[File]InheritSd"  # Root folder path will have to exist after this child folder has been created
        }

        # InheritSd should have no access, but inheritance should be enabled
        cSecurityDescriptor InheritSd {
            Path = $InheritSD
            ObjectType = "Directory"
            AccessInheritance = "Enabled"
            AuditInheritance = "Enabled"
            Access = ""
            Audit = ""
            DependsOn = "[File]InheritSd"
        }

        # No access should have a blank DACL, so inheritance is off
        cSecurityDescriptor NoAccess {
            Path = $NoAccess
            ObjectType = "Directory"
            AccessInheritance = "Disabled"
            Owner = "SYSTEM"
            Access = ""
            DependsOn = "[File]NoAccess"
        }

        cSecurityDescriptor DontInherit {
            Path = $DontInheritSD
            ObjectType = "Directory"
            AccessInheritance = "Disabled"
            Access = @"
"AceType","Principal","FolderRights","AppliesTo"
"Allow","NT AUTHORITY\Authenticated Users","Modify, Synchronize","Object, ChildContainers, ChildObjects"
"Allow","NT AUTHORITY\SYSTEM","FullControl","Object, ChildContainers, ChildObjects"
"Allow","BUILTIN\Administrators","FullControl","Object, ChildContainers, ChildObjects"
"Allow","BUILTIN\Users","ReadAndExecute, Synchronize","Object, ChildContainers, ChildObjects"
"@
            DependsOn = "[File]NoAccess"
        }

        cAccessControlEntry SomeExtraAces1 {
            Ensure = "Present"
            Path = $SomeExtraAces
            ObjectType = "Directory"
            Principal = "Everyone"
            AceType = "Allow"
            AccessMask = New-PacAccessMask -FolderRights Modify
            AppliesTo = "ChildContainers, ChildObjects"
            DependsOn = "[File]SomeExtraAces"
        }

        cAccessControlEntry SomeExtraAces2 {
            Ensure = "Present"
            Path = $SomeExtraAces
            ObjectType = "Directory"
            Principal = "Everyone"
            AceType = "Audit"
            AuditFlags = "Failure"
            AccessMask = [System.Security.AccessControl.FileSystemRights]::FullControl
            DependsOn = "[File]SomeExtraAces"
        }

        cAccessControlEntry SomeExtraAces3 {
            Ensure = "Present"
            Path = $SomeExtraAces
            ObjectType = "Directory"
            Principal = "Users"
            AceType = "Audit"
            AuditFlags = "Success, Failure"
            AppliesTo = "Object, ChildContainers, ChildObjects, DirectChildrenOnly"
            AccessMask = New-PacAccessMask -FolderRights Delete
            DependsOn = "[File]SomeExtraAces"
        }

        cAccessControlEntry SomeExtraAces4 {
            Ensure = "Present"
            Path = $SomeExtraAces
            ObjectType = "Directory"
            Principal = "Guests"
            AceType = "Deny"
            AppliesTo = "Object, ChildContainers, ChildObjects, DirectChildrenOnly"
            AccessMask = New-PacAccessMask -FolderRights Write
            DependsOn = "[File]SomeExtraAces"
        }
    }
}

$Config = PresentationSetup -OutputPath "$RootFolderPath\PresentationSetup"
Start-DscConfiguration (Split-Path $Config) -Verbose -Wait