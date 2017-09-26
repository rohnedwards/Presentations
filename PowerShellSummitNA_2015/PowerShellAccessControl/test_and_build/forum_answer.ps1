$ExperimentalIoPath = "C:\Users\edwardsr\Downloads\PowerShellAccessControl_3.0_beta_20140729\PowerShellAccessControl\bin\Microsoft.Experimental.IO.dll"
Add-Type -Path $ExperimentalIoPath
Add-Type @"

using System;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Collections.Generic;
using Microsoft.Experimental.IO;

namespace Test6 {

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

        public class PathAndSddl {
            public PathAndSddl(string path, string sddl) {
                Path = path;
                Sddl = sddl;
            }

            public string Path { get; private set; }
            public string Sddl { get; private set; }
        }

        public static PathAndSddl GetSddl(string path) {
            string sddl;

            try {
                sddl = GetSecurityDescriptor(path, ResourceType.FileObject).GetSddlForm(AccessControlSections.All);
            }
            catch (Exception e) {
                sddl = string.Format("ERROR: {0}", e.Message);
            }

            return new PathAndSddl(path, sddl);
        }

        public static RawSecurityDescriptor GetSecurityDescriptor(string path, System.Security.AccessControl.ResourceType objectType) {
            return GetSecurityDescriptor(path, ResourceType.FileObject, SecurityInformation.Owner | SecurityInformation.Group | SecurityInformation.Dacl);
        }

	    public static RawSecurityDescriptor GetSecurityDescriptor(string path, System.Security.AccessControl.ResourceType objectType, SecurityInformation securityInformation) {
		    IntPtr pOwner, pGroup, pDacl, pSacl, pSecurityDescriptor;
		    pOwner = pGroup = pDacl = pSacl = pSecurityDescriptor = IntPtr.Zero;
			
		    uint exitCode;
			
			exitCode = GetNamedSecurityInfo(path, objectType, securityInformation, out pOwner, out pGroup, out pDacl, out pSacl, out pSecurityDescriptor);

		    if (exitCode != 0) {
			    throw new Exception(String.Format("Error getting security descriptor for {0} object with path {1}: {2}", objectType, path, new System.ComponentModel.Win32Exception(Convert.ToInt32(exitCode))));
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
			
		    return new RawSecurityDescriptor(binarySd, 0);
	    }

        public static List<string> GetChildItemPathName(string path, bool recurse) {
            List<string> results = new List<string>();

            // Get directories:
            try {
                foreach (string folderName in LongPathDirectory.EnumerateDirectories(path)) {
                    if (recurse) {
                        results.AddRange(GetChildItemPathName(folderName, true));
                    }

                    results.Add(folderName);
                }

                // Get files:
                foreach (string fileName in LongPathDirectory.EnumerateFiles(path)) {
                    results.Add(fileName);
                }
            }
            catch (Exception e) {
                // Not the best way to handle errors, but didn't want to terminate
                results.Add(string.Format("Error enumerating FS objects for '{0}': {1}", path, e.Message));
            }


            return results;
        }

        public static List<string> GetFileSystemObjectsWithSpecificSddl(string path, string sddl, bool recurse) {
            List<string> results = new List<string>();
            string currentSddl;

            foreach (string childPath in GetChildItemPathName(path, recurse)) {
                try {
                    currentSddl = GetSecurityDescriptor(childPath, ResourceType.FileObject).GetSddlForm(AccessControlSections.All);
                }
                catch (Exception e) {
                    results.Add(string.Format("Error getting security descriptor for '{0}': {1}", childPath, e.Message));
                    continue;
                }

                if (childPath.StartsWith("Error") || sddl == currentSddl) {
                    results.Add(childPath);
                }
            }
            
            return results;
        }
    }		
}
"@ -ReferencedAssemblies $ExperimentalIoPath


function Get-ChildItemLongPath {
    [CmdletBinding()]
    param(
        [string] $Path,
        [switch] $Recurse
    )

    process {
        try {
            # Get directories:
            foreach( $CurrentPath in [Microsoft.Experimental.IO.LongPathDirectory]::EnumerateDirectories($Path) ) {
                if ($Recurse) {
                    & $PSCmdlet.MyInvocation.MyCommand -Path $CurrentPath -Recurse
                }

                $CurrentPath
            }

            # Get files:
            [Microsoft.Experimental.IO.LongPathDirectory]::EnumerateFiles($Path)
        }
        catch {
            Write-Error ("Error on '{0}': {1}" -f $Path, $_.Exception.Message)
        }
    }
}

function Search-Sddl {
    [CmdletBinding()]
    param(

    )
}

measure-command {
$sddls = Get-ChildItemLongPath d:\temp -Recurse | % { 
    [Test2.Helper]::GetSddl($_)
}
}

measure-command {
$sddls2 = Get-ChildItem d:\temp -Recurse | % { try { get-acl $_.FullName } catch {}} | select fullname, sddl
}

[Test6.Helper]::GetFileSystemObjectsWithSpecificSddl("D:\temp", $SddlToSearch, $true)