namespace ROE.PowerShellAccessControl {

	[Cmdlet(VerbsCommon.New, "PacSDOption", DefaultParameterSetName = "FullSecurityInformationSectionsSelect")]
	public class NewPacSdOptionCommand : PSCmdlet {
		
		[Parameter()]
		public SwitchParameter BypassAclCheck { get; set; }

		[Parameter()]
		public SwitchParameter LiteralPath { get; set; }

		[Parameter()]
		public ResourceType ObjectType { get; set; }
		
		[Parameter()]
		public SwitchParameter Recurse { get; set; }

		[Parameter()]
		public SwitchParameter Directory {
			get {  // If neither file or directory were specified, then both should be true
				if (_directory == null && _file == null) {
					return true;
				}
				else if (_directory == null) {
					return (bool) (_directory = false);
				}
				else {
					return (bool) _directory; 
				}
			}
			set { _directory = value; }
		}
		private bool? _directory;

		[Parameter()]
		public SwitchParameter File {
			get {  // If neither file or directory were specified, then both should be true
				if (_file == null && _directory == null) {
					return true;
				}
				else if (_file == null) {
					return (bool) (_file = false);
				}
				else {
					return (bool) _file; 
				}
			}
			set { _file = value; }
		}
		private bool? _file;

		[Parameter(ParameterSetName="FullSecurityInformationSectionsSelect")]
		public GetSecurityInformation SecurityDescriptorSections { get; set; }
		
		[Parameter(ParameterSetName="SecurityInformationSectionsAddition")]
		[Alias("Audit")]
		public SwitchParameter GetSacl { get; set; }
		
		[Parameter(ParameterSetName="SecurityInformationSectionsAddition")]
		[Alias("Label")]
		public SwitchParameter GetLabel { get; set; }
		
		protected override void ProcessRecord() {
			PacSdOption options = new PacSdOption();
			
			options.Recurse = this.Recurse;
			options.ObjectType = this.ObjectType;
			options.BypassAclCheck = this.BypassAclCheck;
			options.File = this.File;
			options.Directory = this.Directory;
			options.LiteralPath = this.LiteralPath;

			if (ParameterSetName == "SecurityInformationSectionsAddition") {
				options.SecurityDescriptorSections = (GetSecurityInformation) PacSdOption.DefaultGetSecurityDescriptorSections;
				if (this.GetSacl) {
					options.SecurityDescriptorSections |= GetSecurityInformation.Audit;
				}
				
				if (this.GetLabel) {
					options.SecurityDescriptorSections |= GetSecurityInformation.Label;
				}
			}
			else {
				options.SecurityDescriptorSections = this.SecurityDescriptorSections;
			}
			
			WriteObject(options);
		}
	}
	
	public class PacSdOption {
	
		public PacSdOption() {
// This is not set so that if a user doesn't specify it, it will remain 0. GetSecurityDescriptor is set to change this
// to the default of getting Owner, Group, and Access, and SetSecurityDescriptor will behave differently...
//			SecurityDescriptorSections = GetSecurityInformation.AllAccessAndAudit ^ GetSecurityInformation.Audit;
			File = true;
			Directory = true;
		}

		#region Properties
		public bool BypassAclCheck { get; set; }
		public bool LiteralPath { get; set; }
		public bool Recurse { get; set; }
		public bool File { get; set; }
		public bool Directory { get; set; }
		public ResourceType ObjectType { get; set; }
		public GetSecurityInformation SecurityDescriptorSections { get; set; }


		public const GetSecurityInformation DefaultGetSecurityDescriptorSections = GetSecurityInformation.AllAccessAndAudit ^ GetSecurityInformation.Audit;
		public const SecurityInformation DefaultSetSecurityDescriptorSections = SecurityInformation.Dacl;
		#endregion
	
	}

}