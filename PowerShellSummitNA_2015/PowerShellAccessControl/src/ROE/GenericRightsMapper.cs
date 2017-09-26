namespace ROE.PowerShellAccessControl {
	public class GenericRightsMapper {

		public static GenericMapping FileSystemRights {
			get { return new GenericMapping(1179785, 1179926, 1179808, 2032127); }
		}
		
		public static GenericMapping WsManAccessRights {
			get { return new GenericMapping(-2147483648, 1073741824, 536870912, 268435456); }
		}
		
		public static GenericMapping ActiveDirectoryRights {
			get { return new GenericMapping(131220, 131112, 131076, 983551); }
		}
		
		public static GenericMapping RegistryRights {
			get { return new GenericMapping(131097, 131078, 131129, 983103); }
		}
		
		public static GenericMapping PrinterRights {
			get { return new GenericMapping(131080, 131080, 131080, 983052); }
		}

		public static GenericMapping GetGenericMapping(Type accessRightType) {
			switch (accessRightType.Name) {
				case "FileSystemRights":
					return FileSystemRights;
				
				case "WsManAccessRights":
					return WsManAccessRights;
					
				case "ActiveDirectoryRights":
					return ActiveDirectoryRights;
					
				case "RegistryRights":
					return RegistryRights;
					
				case "PrinterRights":
					return PrinterRights;
					
				default:
					throw new Exception("No generic mapping exists");
			}
		}		
	}
}



