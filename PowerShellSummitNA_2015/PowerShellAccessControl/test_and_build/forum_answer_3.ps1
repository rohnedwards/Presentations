$ExperimentalIoPath = "C:\Users\rohne_000\Downloads\PowerShellAccessControl_3.0_beta_20140729\PowerShellAccessControl\bin\Microsoft.Experimental.IO.dll"
Add-Type -Path $ExperimentalIoPath
Add-Type @"

using System;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Collections.Generic;
using Microsoft.Experimental.IO;

namespace HSG {

    public class Helper {
        // http://msdn.microsoft.com/en-us/library/windows/desktop/aa446645%28v=vs.85%29.aspx
        [DllImport("advapi32.dll", EntryPoint = "GetNamedSecurityInfoW", CharSet = CharSet.Unicode)]
        internal static extern uint GetNamedSecurityInfo(
            string ObjectName,
            System.Security.AccessControl.ResourceType ObjectType,
            SecurityInformation SecurityInfo,
            out IntPtr pSidOwner,
            out IntPtr pSidGroup,
            out IntPtr pDacl,
            out IntPtr pSacl,
            out IntPtr pSecurityDescriptor
        );
        [DllImport("advapi32.dll")]
        internal static extern Int32 GetSecurityDescriptorLength(
            IntPtr pSecurityDescriptor
        );
        [DllImport("kernel32.dll", SetLastError=true)]
        internal static extern IntPtr LocalFree(
            IntPtr hMem
        );

        [Flags]
        public enum SecurityInformation : uint {
            Owner           = 0x00000001,
            Group           = 0x00000002,
            Dacl            = 0x00000004,
            Sacl            = 0x00000008
        }

	    public static CommonSecurityDescriptor GetSecurityDescriptor(string path, System.Security.AccessControl.ResourceType objectType, SecurityInformation securityInformation, bool isContainer) {
		    IntPtr pOwner, pGroup, pDacl, pSacl, pSecurityDescriptor;
		    pOwner = pGroup = pDacl = pSacl = pSecurityDescriptor = IntPtr.Zero;
			
		    uint exitCode;
			
			exitCode = GetNamedSecurityInfo(path, objectType, securityInformation, out pOwner, out pGroup, out pDacl, out pSacl, out pSecurityDescriptor);

		    if (exitCode != 0) {
			    throw new Exception((new System.ComponentModel.Win32Exception(Convert.ToInt32(exitCode))).Message);
		    }

		    if (pSecurityDescriptor == IntPtr.Zero) {
			    throw new Exception(String.Format("No security descriptor available for {0} object with path {1}", objectType, path));
		    }

		    byte[] binarySd;
		    try {
			    int sdSize = GetSecurityDescriptorLength(pSecurityDescriptor);
				
			    binarySd = new byte[sdSize];
			    Marshal.Copy(pSecurityDescriptor, binarySd, 0, sdSize);
		    }
		    catch(Exception e) {
			    throw e;
		    }
		    finally {
			    if (LocalFree(pSecurityDescriptor) != IntPtr.Zero) {
				    throw new Exception(String.Format("Error freeing memory for security descriptor at path {0}", path));
			    }
		    }
			
		    return new CommonSecurityDescriptor(isContainer, false, binarySd, 0);
	    }

        public class LongPathFileSystemItem {
            public LongPathFileSystemItem(string path, bool isContainer) {
                this.Path = path;
                this.IsContainer = isContainer;
            }

            public string Path { get; private set; }
            public bool IsContainer { get; private set; }
        }

        public static List<LongPathFileSystemItem> GetChildItemLongPath(string path, bool recurse) {
            List<LongPathFileSystemItem> results = new List<LongPathFileSystemItem>();

            try {
                // Get directories
                foreach (string folderName in LongPathDirectory.EnumerateDirectories(path)) {
                    if (recurse) {
                        results.AddRange(GetChildItemLongPath(folderName, true));
                    }

                    results.Add(new LongPathFileSystemItem(folderName, true));
                }

                // Get files:
                foreach (string fileName in LongPathDirectory.EnumerateFiles(path)) {
                    results.Add(new LongPathFileSystemItem(fileName, false));
                }
            }
            catch (Exception e) {
                // Not the best way to handle errors, but didn't want to terminate
                results.Add(new LongPathFileSystemItem(string.Format("Error enumerating FS objects for '{0}': {1}", path, e.Message), false));
            }

            return results;
        }

        public static List<string> GetFileSystemObjectsWithSpecificSddl(string path, string sddl, bool recurse) {
            List<string> results = new List<string>();
            string currentSddl;

            foreach (LongPathFileSystemItem childItem in GetChildItemLongPath(path, recurse)) {
                if (childItem.Path.StartsWith("Error")) {
                    results.Add(childItem.Path);
                    continue;
                }
                try {
                    currentSddl = GetSecurityDescriptor(
                        string.Format(@"\\?\{0}", childItem.Path), 
                        ResourceType.FileObject,
                        SecurityInformation.Owner | SecurityInformation.Group | SecurityInformation.Dacl,
                        childItem.IsContainer
                    ).GetSddlForm(AccessControlSections.All);
                }
                catch (Exception e) {
                    results.Add(string.Format("Error getting security descriptor for '{0}': {1}", childItem.Path, e.Message));
                    continue;
                }

                if (sddl == currentSddl) {
                    results.Add(childItem.Path);
                }
            }
            
            return results;
        }
    }		
}
"@ -ReferencedAssemblies $ExperimentalIoPath

function Search-Sddl {
    [OutputType([string])]
    [CmdletBinding()]
    param(
        [string] $Path,
        [string] $Sddl,
        [switch] $Recurse
    )
    process {

        [HSG.Helper]::GetFileSystemObjectsWithSpecificSddl($Path, $SddlToFind, $Recurse) | ForEach-Object {
            if ($_ -match "^Error") { Write-Error $_ }
            else { $_ }
        }
    }
}

$PathToSearch = "c:\windows"
$SddlToFind = Get-Acl C:\Windows\system32 | select -exp sddl


$GetAclTime = measure-command {
$GetAcl = Get-ChildItem $PathToSearch -Recurse -Force | % { try { Get-Acl $_.FullName } catch {}} | ? sddl -eq $SddlToFind
}

$CSharpTime3 = measure-command {
$CSharp3 = Search-Sddl -Path $PathToSearch -Sddl $SddlToFind -Recurse
}