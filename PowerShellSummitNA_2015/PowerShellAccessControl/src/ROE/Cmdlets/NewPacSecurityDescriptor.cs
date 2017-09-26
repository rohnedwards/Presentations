namespace ROE.PowerShellAccessControl {

	[Cmdlet(VerbsCommon.New, "PacSecurityDescriptor")]
	[OutputType(new Type[] { typeof(AdaptedSecurityDescriptor) })]
	public class NewPacSecurityDescriptorCommand : Cmdlet {

		#region Parameters
        [Parameter(Mandatory=true, ParameterSetName="BySddl")]
        public string Sddl { get; set; }
		
        [Parameter(Mandatory=true, ParameterSetName="ByBinaryForm")]
        public byte[] BinarySD { get; set; }
		
        [Parameter()]
		[Alias("AccessMaskEnumeration")]
        public Type AccessRightType { 
			get { return _accessMaskEnumeration; }
			set { 
				bool isFlagsEnum = false;

				foreach (object custAttr in value.GetCustomAttributes(true)) {
					if (custAttr is FlagsAttribute) {
						isFlagsEnum = true;
						break;
					}
				}
				if (isFlagsEnum) {
					_accessMaskEnumeration = value; 
				}
				else {
					throw new Exception("AccessMaskEnumeration must be a flags enumeration");
				}
			}
		}
		Type _accessMaskEnumeration;
		
        [Parameter()]
        public string Path { get; set; }
		
        [Parameter()]
        public ResourceType ObjectType { get; set; }
		
        [Parameter()]
        public SwitchParameter IsContainer { get; set; }
		
        [Parameter()]
        public string DsObjectClass { get; set; }
		
		#endregion

		protected override void ProcessRecord() {
			AdaptedSecurityDescriptorPathInformation pathInfo;
			
			if (this.DsObjectClass == null) {
				pathInfo = new AdaptedSecurityDescriptorPathInformation();
				pathInfo.IsContainer = this.IsContainer;
			}
			else {
				pathInfo = new AdaptedActiveDirectorySecurityDescriptorPathInformation();
				((AdaptedActiveDirectorySecurityDescriptorPathInformation) pathInfo).DsObjectClass = this.DsObjectClass;
			}

			if (this.Path != null) {
				pathInfo.SdPath = new SecurityDescriptorStringPath(this.Path);
			}
			
			if (this.ObjectType != null) {
				pathInfo.ObjectType = this.ObjectType;
			}
			
			if (this.AccessRightType != null) { 
				pathInfo.AccessRightType = this.AccessRightType;
			}
			
			if (pathInfo is AdaptedActiveDirectorySecurityDescriptorPathInformation) {
				if (this.Sddl != null) {
					WriteObject(new AdaptedActiveDirectorySecurityDescriptor(pathInfo, this.Sddl));
				}
				else if (this.BinarySD != null) {
					WriteObject(new AdaptedActiveDirectorySecurityDescriptor(pathInfo, this.BinarySD, 0));
				}
				else {
					WriteError(new ErrorRecord(
						new Exception("Unable to determine SDDL or BinarySD form of security descriptor"),
						"",
						ErrorCategory.InvalidData,
						null
					));
				}
			}
			else {
				if (this.Sddl != null) {
					WriteObject(new AdaptedSecurityDescriptor(pathInfo, this.Sddl));
				}
				else if (this.BinarySD != null) {
					WriteObject(new AdaptedSecurityDescriptor(pathInfo, this.BinarySD, 0));
				}
				else {
					WriteError(new ErrorRecord(
						new Exception("Unable to determine SDDL or BinarySD form of security descriptor"),
						"",
						ErrorCategory.InvalidData,
						null
					));
				}
			}
		}
	}
}