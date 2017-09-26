namespace ROE.PowerShellAccessControl {

	[Cmdlet(VerbsCommon.New, "PacAccessMask")]
	public class NewPacAccessMaskCommand : PSCmdlet {

		[Parameter(Mandatory = true, ParameterSetName="FolderRights")]
		[Alias(new string[] { "FileRights", "FileSystemRights" })]
        public FileSystemRights FolderRights { get; set; }

		[Parameter(Mandatory = true, ParameterSetName="RegistryRights")]
        public RegistryRights RegistryRights { get; set; }

		[Parameter(Mandatory = true, ParameterSetName="ActiveDirectoryRights")]
        public Enums.ActiveDirectoryRights ActiveDirectoryRights { get; set; }

		[Parameter(Mandatory = true, ParameterSetName="ShareRights")]
        public Enums.ShareRights ShareRights { get; set; }

		[Parameter(Mandatory = true, ParameterSetName="PrinterRights")]
        public Enums.PrinterRights PrinterRights { get; set; }

		[Parameter(Mandatory = true, ParameterSetName="WmiNamespaceRights")]
        public Enums.WmiNamespaceRights WmiNamespaceRights { get; set; }

		[Parameter(Mandatory = true, ParameterSetName="ServiceRights")]
        public Enums.ServiceAccessRights ServiceRights { get; set; }

		[Parameter(Mandatory = true, ParameterSetName="ProcessRights")]
        public Enums.ProcessAccessRights ProcessRights { get; set; }

		[Parameter(Mandatory = true, ParameterSetName="GenericAccessMask")]
        public int AccessMask { get; set; }

		protected override void ProcessRecord() {
			object returnValue;
			
			switch (this.ParameterSetName) {
				
				case "FolderRights":
					returnValue = this.FolderRights;
					break;
				
				case "RegistryRights":
					returnValue = this.RegistryRights;
					break;
				
				case "ActiveDirectoryRights":
					returnValue = this.ActiveDirectoryRights;
					break;
					
				case "ShareRights":
					returnValue = this.ShareRights;
					break;
				
				case "PrinterRights":
					returnValue = this.PrinterRights;
					break;
					
				case "WmiNamespaceRights":
					returnValue = this.WmiNamespaceRights;
					break;
				
				case "ServiceRights":
					returnValue = this.ServiceRights;
					break;
					
				case "ProcessRights":
					returnValue = this.ProcessRights;
					break;
					
				case "GenericAccessMask":
					returnValue = this.AccessMask;
					break;
					
				default:
					WriteError(new ErrorRecord(
						new Exception(string.Format("Unknown ParameterSetName: {0}", this.ParameterSetName)),
						"",
						ErrorCategory.InvalidData,
						this.ParameterSetName
					));
					return;
			}
			
			WriteObject(returnValue);
		}
	}
}
