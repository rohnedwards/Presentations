namespace ROE.PowerShellAccessControl {
	public class AdaptedActiveDirectorySecurityDescriptorPathInformation : AdaptedSecurityDescriptorPathInformation {
		public AdaptedActiveDirectorySecurityDescriptorPathInformation() {
				this.IsDS = true;
				this.IsContainer = true;
				this.ObjectType = ResourceType.DSObjectAll;
				this.AccessRightType = typeof(Enums.ActiveDirectoryRights);
		}
		
		public AdaptedActiveDirectorySecurityDescriptorPathInformation(string distinguishedName, string objectClass) : this() {
				this.DsObjectClass = objectClass;
				this.SdPath = new SecurityDescriptorStringPath(
					distinguishedName
				);

		}
		
		public string DsObjectClass { get; set; }
		
	}

	public class AdaptedSecurityDescriptorPathInformation {
	
		public AdaptedSecurityDescriptorPathInformation(string sdPath, string displayName, ResourceType objectType, bool isContainer) {
			this.IsContainer = isContainer;
			this.ObjectType = objectType;
			
			SecurityDescriptorStringPath stringPath = new SecurityDescriptorStringPath(sdPath);
			if (displayName != null) {
				stringPath.DisplayName = displayName;
			}
			
			this.SdPath = stringPath;
		}
		
		public AdaptedSecurityDescriptorPathInformation() {
		}
		
		public bool IsDS { get; set; }
		
		public bool IsContainer { get; set; }
		
		public ResourceType ObjectType { get; set; }

		internal bool BypassAclMode { get; set; }
		
		public SecurityDescriptorPath SdPath { get; set; }
		
		public Type AccessRightType {
			get {
				if (_accessRightType == null) {
					switch (this.ObjectType) {
						case ResourceType.FileObject:
							_accessRightType = typeof(FileSystemRights);
							break;
							
						case ResourceType.RegistryKey:
							_accessRightType = typeof(RegistryRights);
							break;
							
						case ResourceType.DSObjectAll:
						case ResourceType.DSObject:
							_accessRightType = typeof(Enums.ActiveDirectoryRights);
							break;
							
						case ResourceType.LMShare:
							_accessRightType = typeof(ShareRights);
							break;
						
						case ResourceType.Service:
							_accessRightType = typeof(ServiceAccessRights);
							break;
						
						case ResourceType.Printer:
							_accessRightType = typeof(PrinterRights);
							break;
						
						default:
							_accessRightType = typeof(int);
							break;
					}
				}
				return _accessRightType;
			}
			set { _accessRightType = value; }
		}
		private Type _accessRightType;
	
		// This is mostly used by ProviderDefined objects (WMI namespaces and WSMAN security objects).
		// It allows the SD set method to determine what to do based off of the original object (mose useful
		// for WMI namespaces since gwmi or gcim could have been used...)
		internal Type InstanceType { get; set; }
		
		public override string ToString() {
			return this.SdPath.ToString();
		}
	}
	
	public class SecurityDescriptorPath {
	
		internal SecurityDescriptorPath(string displayName) {
			DisplayName = displayName;
		}
		
		public string DisplayName { get; internal set; }

		public override string ToString() {
			return DisplayName;
		}
	}
	
	public class SecurityDescriptorStringPath : SecurityDescriptorPath {
		
		public SecurityDescriptorStringPath(string path, string displayName) : base(displayName) {
			Path = path;
			base.DisplayName = displayName;
		}
		
		public SecurityDescriptorStringPath(string path) : this(path, path) {
		}
		
		public string Path { get; private set; }
	}

	public class SecurityDescriptorSafeHandle : SecurityDescriptorPath {
		
		public SecurityDescriptorSafeHandle(SafeHandle handle, string displayName) : base(displayName) {
			Handle = handle;
//			base.DisplayName = displayName;
		}
		
		public SecurityDescriptorSafeHandle(SafeHandle handle) : this(handle, "<Safe Handle>") {
		}
		
		public SafeHandle Handle { get; private set; }
	}

	public class SecurityDescriptorHandleRef : SecurityDescriptorPath {
		
		public SecurityDescriptorHandleRef(HandleRef handle, string displayName) : base(displayName) {
			Handle = handle;
			this.IsInvalid = false;
		}
		
		public SecurityDescriptorHandleRef(HandleRef handle) : this(handle, "<HandleRef>") {
		}
		
		public HandleRef Handle { get; private set; }
		public bool IsInvalid { get; private set; }
		
		public void SetHandleRefAsInvalid() {
			if (this.IsInvalid == false) {
				this.Handle = new HandleRef(null, IntPtr.Zero);
				this.IsInvalid = true;
			}
		}
	}
}
