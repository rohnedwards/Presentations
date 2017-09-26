namespace ROE.PowerShellAccessControl {
    namespace PInvoke {
		internal class File {
			[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
			internal static extern SafeFileHandle CreateFile(
				string lpFileName,
				int dwDesiredAccess,
				uint dwShareMode,
				IntPtr lpSecurityAttributes,
				uint dwCreationDisposition,
				uint dwFlagsAndAttributes,
				IntPtr hTemplateFile
			);
		
		}

		internal class Registry {
			[DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
			internal static extern int RegCreateKeyEx(
				IntPtr hKey,
				string lpSubKey,
				int Reserved,
				string lpClass,
				RegOptions dwOptions,
				int samDesired,
				IntPtr lpSecurityAttributes,
				out SafeRegistryHandle phkResult,
				out RegResult lpdwDisposition
			);

			[Flags]
			internal enum ERegistryAccess : uint {
				GenericRead = 0x80000000,
				GenericWrite = 0x40000000,
				GenericExecute = 0x20000000,
				GenericAll = 0x10000000,
				AccessSystemSecurity = 0x01000000
			}

			[Flags]
			internal enum RegOptions {
				NonVolatile   = 0,
				Volatile      = 1,
				CreateLink    = 2,
				BackupRestore = 4,
				OpenLink      = 8
			}

			internal enum RegResult {
				CreatedNewKey     = 1,
				OpenedExistingKey = 2
			}
		}

        public class advapi32 {
            // http://msdn.microsoft.com/en-us/library/windows/desktop/aa379166(v=vs.85).aspx
            [DllImport("advapi32.dll", EntryPoint="LookupAccountSid", SetLastError=true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            static extern bool __LookupAccountSid(
                string lpSystemName,
                [MarshalAs(UnmanagedType.LPArray)] byte[] Sid,
                System.Text.StringBuilder lpName,
                ref UInt32 cchName,
                System.Text.StringBuilder lpReferencedDomainName,
                ref UInt32 cchReferencedDomainName,
                out SidNameUse peUse
            );  

            public static Int32 LookupAccountSid(string lpSystemName, byte[] Sid, System.Text.StringBuilder lpName, ref UInt32 cchName, System.Text.StringBuilder lpReferencedDomainName, ref UInt32 cchReferencedDomainName, out SidNameUse peUse) {
                if (__LookupAccountSid(lpSystemName, Sid, lpName, ref cchName, lpReferencedDomainName, ref cchReferencedDomainName, out peUse)) {
                    return 0;
                }
                else {
                    return System.Runtime.InteropServices.Marshal.GetLastWin32Error();
                }
            }

            // http://msdn.microsoft.com/en-us/library/windows/desktop/aa379159(v=vs.85).aspx
            [DllImport("advapi32.dll", EntryPoint="LookupAccountName", SetLastError=true)]
            static extern bool __LookupAccountName(
                string lpSystemName,
                string lpAccountName,
                [MarshalAs(UnmanagedType.LPArray)] byte[] Sid,
                ref UInt32 cbSid,
                System.Text.StringBuilder lpReferencedDomainName,
                ref UInt32 cchReferencedDomainName,
                out SidNameUse peUse
            );
			
            public static Int32 LookupAccountName(string lpSystemName, string lpAccountName, byte[] Sid, ref UInt32 cbSid, System.Text.StringBuilder lpReferencedDomainName, ref UInt32 cchReferencedDomainName, out SidNameUse peUse) {
                if (__LookupAccountName(lpSystemName, lpAccountName, Sid, ref cbSid, lpReferencedDomainName, ref cchReferencedDomainName, out peUse)) {
                    return 0;
                }
                else {
                    return System.Runtime.InteropServices.Marshal.GetLastWin32Error();
                }
            }

            [DllImport("advapi32.dll", EntryPoint = "GetInheritanceSourceW", CharSet = CharSet.Unicode)]
            public static extern UInt32 GetInheritanceSource(
                    [MarshalAs(UnmanagedType.LPTStr)] string ObjectName,
                    System.Security.AccessControl.ResourceType ObjectType,
                    SecurityInformation SecurityInfo,
                    [MarshalAs(UnmanagedType.Bool)]bool Container,
                    ref Guid[] ObjectClassGuids,   // double pointer
                    UInt32 GuidCount,
                    byte[] Acl,
                    IntPtr pfnArray,
                    ref GenericMapping GenericMapping,
                    IntPtr InheritArray                
            );

            [DllImport("advapi32.dll")]
            public static extern UInt32 FreeInheritedFromArray(
                IntPtr InheritArray,
                UInt16 AceCnt,
                IntPtr pfnArray
            );
        }

        public class kernel32 {
            // http://msdn.microsoft.com/en-us/library/windows/desktop/aa366730%28v=vs.85%29.aspx
// SetLastError is true, but I'm not checking it yet...
            [DllImport("kernel32.dll", SetLastError=true)]
            internal static extern IntPtr LocalFree(
                IntPtr hMem
            );

		}
		
		namespace Enums {
            // http://msdn.microsoft.com/en-us/library/windows/desktop/aa379601(v=vs.85).aspx
            public enum SidNameUse {
                User            = 1,
                Group,
                Domain,
                Alias,
                WellKnownGroup,
                DeletedAccount,
                Invalid,
                Unknown,
                Computer,
                Label
            }
		}
	}
}



