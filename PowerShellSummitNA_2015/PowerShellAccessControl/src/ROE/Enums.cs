namespace ROE.PowerShellAccessControl {
	namespace Enums {

		public enum AceType {
			Allow,
			Deny,
			Audit
		}

		[Flags]
		public enum GetAceDisplayOptions {
			None                 = 0x0,
			DontMapGenericRights = 0x1,
			HideUndefinedRights  = 0x2,
			ShowDetailedRights   = 0x4,

			IncludeNumericAccessMask = 0x10,
			DontLookupAdRights   = 0x20,
			DontMergeAces        = 0x40
		}

// Enum to control different access mask view types:
// This should be able to remove this:
public enum RightsDictionaryViewType {
	Default,
	NoCombinedRights
}

        // Share enumeration from: http://blogs.msdn.com/b/helloworld/archive/2008/06/10/common-accessmask-value-when-configuring-share-permission-programmatically.aspx
        [Flags]
        public enum ShareRights {
            FullControl      = 0x001f01ff,
            Read             = 0x001200a9, 
            Change           = 0x001301bf
        }

        // Enum info from here: http://msdn.microsoft.com/en-us/library/cc244650.aspx
        // Generic mappings (used in a future release):
        //   - Read: Server object: ReadServer; Printer object: ReadPrinter; job object: ReadJob
        //   - Write: Server object: WriteServer; Printer object: WritePrinter; job object: WriteJob
        //   - Execute: look at previous two, and you get the picture :)
        //   - All: Same as above, but using 'AllAccess'
        [Flags]
        public enum PrinterRights {
            AdministerJob = 0x00010,
            ReadSpoolFile = 0x00020,
            ExecuteJob    = ReadPermissions | AdministerJob,
            ReadJob       = ReadPermissions | ReadSpoolFile,
            WriteJob      = ReadPermissions | AdministerJob,
            JobFullControl= Synchronize | ReadSpoolFile | Delete | TakeOwnership | ChangePermissions,
            UsePrinter    = 0x00008,
            AdministerPrinter = 0x00004,
            ManagePrinter  = 0x00040,            
            Print = ReadPermissions | UsePrinter,
            PrinterFullControl  = TakeOwnership | ChangePermissions | ReadPermissions | Delete | AdministerPrinter | UsePrinter,
            //ManageDocuments   = 0xf0030,
            AdministerServer  = 0x000001,
            EnumerateServer   = 0x000002,
            ServerFullControl = TakeOwnership | ChangePermissions | Delete | WriteServer,
            ReadAndExecuteServer     = ReadPermissions | EnumerateServer,
            WriteServer       = ReadAndExecuteServer | AdministerServer,
            Delete    = 0x010000,  // Standard rights below
            ReadPermissions   = 0x020000,
            ChangePermissions = 0x040000,
            TakeOwnership     = 0x080000,
            //RightsRequired    = 0x0d0000,  // Removing this; just confuses things
            Synchronize       = 0x100000
        }

        [Flags]
        public enum WmiNamespaceRights {
            EnableAccount   = 0x000001,
            ExecuteMethods  = 0x000002,
            FullWrite       = 0x000004,
            PartialWrite    = 0x000008,
            ProviderWrite   = 0x000010,
            RemoteEnable    = 0x000020,
            ReadSecurity    = 0x020000,
            EditSecurity    = 0x040000
        }

        // Just Generic rights (see below)
        [Flags]
        public enum WsManAccessRights {
            Full    = 0x10000000,
            Read    = -2147483648, // 0x80000000
            Write   = 0x40000000,
            Execute = 0x20000000 
        }

        [Flags]
        public enum ServiceAccessRights {
            QueryConfig         = 0x0001,
            ChangeConfig        = 0x0002,
            QueryStatus         = 0x0004,
            EnumerateDependents = 0x0008,
            Start               = 0x0010,
            Stop                = 0x0020,
            PauseResume         = 0x0040,
            Interrogate         = 0x0080,
            UserDefinedControl  = 0x0100,
            Delete              = 0x010000,   // StandardDelete
            ReadPermissions     = 0x020000,   // StandardReadPermissions/StandardWrite
            Write               = ReadPermissions | ChangeConfig,
            Read                = ReadPermissions | QueryConfig | QueryStatus | Interrogate | EnumerateDependents,
            ChangePermissions   = 0x040000,   // StandardChangePermissions
            ChangeOwner         = 0x080000,   // StandardChangeOwner
    //        Execute             = ReadPermissions | Start | Stop | PauseResume | UserDefinedControl,
            FullControl         = QueryConfig | ChangeConfig | QueryStatus | EnumerateDependents | Start | Stop | PauseResume | Interrogate | UserDefinedControl | Delete | ReadPermissions | ChangePermissions | ChangeOwner
        }

        // http://msdn.microsoft.com/en-us/library/windows/desktop/aa446632%28v=vs.85%29.aspx
        [Flags]
        public enum GenericAceRights {
            GenericAll     = 0x10000000,
            GenericExecute = 0x20000000,
            GenericWrite   = 0x40000000,
            GenericRead    = -2147483648 // 0x80000000
        }

        // http://msdn.microsoft.com/en-us/library/windows/desktop/aa379607%28v=vs.85%29.aspx
        [Flags]
        public enum StandardAccessRights {
            StandardDelete            = 0x010000,
            StandardReadPermissions   = 0x020000,
            StandardSynchronize       = 0x100000,
            StandardChangePermissions = 0x040000,
            StandardChangeOwner       = 0x080000,
            StandardAll               = 0x1f0000,
            //StandardExecute           = 0x020000,
            //StandardRead              = 0x020000,
            //StandardWrite             = 0x020000
            StandardRequired          = 0x0d0000,
        }

        [Flags]
        public enum ProcessAccessRights {
            Terminate        = 0x000001,
            CreateThread     = 0x000002,
            SetSessionId     = 0x000004,
            MemoryOperations = 0x000008,
            ReadMemory       = 0x000010,
            WriteMemory      = 0x000020,
            DuplicateHandle  = 0x000040,
            CreateProcess    = 0x000080,
            SetQuota         = 0x000100,
            SetInformation   = 0x000200,
            QueryInformation = 0x000400,
            SuspendResume    = 0x000800,
            QueryLimitedInfo = 0x001000,  // Since this bit is new to Vista+, new AllAccess was created
            AllAccessLegacy  = 0x1f0fff,
            AllAccess        = 0x1fffff,  // Top three bits of object specific rights appear to be unused
            Delete           = 0x010000,
            ReadPermissions  = 0x020000,
            ChangePermissions= 0x040000,
            TakeOwnership    = 0x080000,
            Synchronize      = 0x100000
        }

        [Flags]
        // May go back to using DirectoryServices enum
        public enum ActiveDirectoryRights {
            CreateChild       = 0x000001,
            DeleteChild       = 0x000002,
			CreateAndDeleteChild = 0x003,
            ListChildren      = 0x000004,
            ValidatedWrite    = 0x000008,
            ReadProperty      = 0x000010,
            WriteProperty     = 0x000020,
			ReadAndWriteProperty = 0x030,
            DeleteSubtree     = 0x000040,
            ListContents      = 0x000080,
            ExtendedRight     = 0x000100,
            Delete            = 0x010000,
            ReadPermissions   = 0x020000,
            ChangePermissions = 0x040000,
            TakeOwnership     = 0x080000,
            Synchronize       = 0x100000,
            GenericRead       = ListChildren | ReadProperty | ListContents | ReadPermissions,
            GenericWrite      = ValidatedWrite | WriteProperty | ReadPermissions,
            GenericExecute    = ListChildren | ReadPermissions,
            FullControl       = CreateChild | DeleteChild | ListChildren | ValidatedWrite | ReadProperty | WriteProperty | DeleteSubtree | ListContents | ExtendedRight | Delete | ReadPermissions | ChangePermissions | TakeOwnership
        }

        [Flags]
        public enum AppliesTo {
            Object = 1,
            ChildContainers = 2,
            ChildObjects = 4,
			DirectChildrenOnly = 8
        }

        [Flags]
        public enum SystemMandatoryLabelMask {
			None = 0,
            NoWriteUp = 1,
            NoReadUp = 2,
            NoExecuteUp = 4
        }

        // There are more than defined here. See http://msdn.microsoft.com/en-us/library/cc230369.aspx
        [Flags]
        public enum SecurityInformation : uint {
            Owner           = 0x00000001,
            Group           = 0x00000002,
            Dacl            = 0x00000004,
            Sacl            = 0x00000008,
            All             = 0x0000000f,
            Label           = 0x00000010,
            Attribute       = 0x00000020,
            Scope           = 0x00000040,
            ProtectedDacl   = 0x80000000,
            ProtectedSacl   = 0x40000000,
            UnprotectedDacl = 0x20000000,
            UnprotectedSacl = 0x10000000
        }

        [Flags]
        public enum GetSecurityInformation : uint {
			None                    = 0x0,
            Owner                   = 0x00000001,
            Group                   = 0x00000002,
            Access                  = 0x00000004,
            Audit                   = 0x00000008,
            AllAccessAndAudit       = 0x0000000f,
            Label                   = 0x00000010,
            Attribute               = 0x00000020,
            CentralAccessPolicy     = 0x00000040
        }

		public struct GenericMapping {
			public Int32 GenericRead, GenericWrite, GenericExecute, GenericAll;
			
			public GenericMapping(Int32 read, Int32 write, Int32 execute, Int32 all) {
				this.GenericRead = read;
				this.GenericWrite = write;
				this.GenericExecute = execute;
				this.GenericAll = all;
			}
		}

		// Used with GetInheritanceSource
        public struct InheritArray {
            public Int32 GenerationGap;
            [MarshalAs(UnmanagedType.LPTStr)] public string AncestorName;
        }
	}
}



