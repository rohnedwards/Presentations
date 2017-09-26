namespace ROE.PowerShellAccessControl {

	[Cmdlet(VerbsCommon.Get, "PacAccessControlEntry")]
	[OutputType(new Type[] { typeof(PacAuthorizationRule), typeof(PacObjectAccessRule), typeof(PacObjectAuditRule) })]
	public class GetPacAccessControlEntryCommand : PacModuleCmdlet {
		#region Parameters
		[Parameter()]
		public SwitchParameter ExcludeInherited { get; set; }

		[Parameter()]
		public SwitchParameter ExcludeExplicit { get; set; }
		
		[Parameter()]
		public Enums.AceType[] AceType { get; set; }
		
		[Parameter()]
		public PrincipalAceFilter[] Principal { get; set; }
		
		[Parameter()]
		[Alias(new string[] { "FileRights", "FileSystemRights" })]
        public FileSystemRights FolderRights { get; set; }

		[Parameter()]
        public RegistryRights RegistryRights { get; set; }

		[Parameter()]
        public Enums.ActiveDirectoryRights ActiveDirectoryRights { get; set; }

		[Parameter()]
        public AccessMaskAceFilter[] AccessMask { get; set; }

		[Parameter()]
		public ObjectAceTypeFilter[] ObjectAceType { get; set; }

		[Parameter()]
		public InheritedObjectAceTypeFilter[] InheritedObjectAceType { get; set; }

		[Parameter()]
		public AppliesTo AppliesTo { get; set; }

		[Parameter()]
		public AuditFlags AuditFlags { get; set; }

		[Parameter()]
		public SwitchParameter Specific { get; set; }

		[Parameter()]
		public GetAceDisplayOptions DisplayOptions {
			get { return _getAceDisplayOptions; }
			set { _getAceDisplayOptions = value; }
		}
		private GetAceDisplayOptions _getAceDisplayOptions = 0;
		#endregion

		private AdaptedAceFilter[] _aceFilters;

		protected override void BeginProcessing() {

			base.BeginProcessing();

			List<AdaptedAceFilter> aceFiltersList = new List<AdaptedAceFilter>();
		
			if (this.AceType != null) {
				aceFiltersList.Add(new AceTypeAceFilter(this.AceType, this.Specific));
			}

			if (this.AppliesTo != 0) {
				aceFiltersList.Add(new AppliesToAceFilter(this.AppliesTo, this.Specific));
			}

			if (this.MyInvocation.BoundParameters.ContainsKey("AuditFlags")) {
				aceFiltersList.Add(new AuditFlagsAceFilter(this.AuditFlags, this.Specific));
			}
			
			int numericAccessMaskFilter = 0;
			numericAccessMaskFilter |= (int) this.FolderRights;
			numericAccessMaskFilter |= (int) this.RegistryRights;
			numericAccessMaskFilter |= (int) this.ActiveDirectoryRights;

			if (numericAccessMaskFilter != 0) {
				aceFiltersList.Add(new AccessMaskAceFilter(numericAccessMaskFilter, this.Specific));
			}
			if (this.AccessMask != null) {
				aceFiltersList.AddRange(this.AccessMask);
			}
			
			if (this.Principal != null) {
				for (int i = 1; i < this.Principal.Length; i++) {
					this.Principal[0].AddAdditionalFilter(this.Principal[i]);
				}
				aceFiltersList.Add(this.Principal[0]); 
			}

			if (this.ObjectAceType != null) {
				for (int i = 1; i < this.ObjectAceType.Length; i++) {
					this.ObjectAceType[0].AddAdditionalFilter(this.ObjectAceType[i]);
				}
				aceFiltersList.Add(this.ObjectAceType[0]); 
			}
			
			if (this.InheritedObjectAceType != null) {
				for (int i = 1; i < this.InheritedObjectAceType.Length; i++) {
					this.InheritedObjectAceType[0].AddAdditionalFilter(this.InheritedObjectAceType[i]);
				}
				aceFiltersList.Add(this.InheritedObjectAceType[0]); 
			}
			
			_aceFilters = aceFiltersList.ToArray();
		}


		protected override void ProcessRecord() {

			bool? specific = null;
			if (this.MyInvocation.BoundParameters.ContainsKey("Specific")) {
				specific = this.Specific.IsPresent;
			}

			bool outputGenerated;
			foreach (AdaptedSecurityDescriptor currentSd in this.GetAdaptedSecurityDescriptor(this.InputObject)) {
				outputGenerated = false;
				try {
					// Get DACL entries
					foreach (AdaptedCommonAce currentAce in currentSd.GetAccessRules(
						!this.ExcludeExplicit, 
						!this.ExcludeInherited, 
						typeof(PacPrincipal), 
						this.DisplayOptions,
						_aceFilters,
						specific
					)) { 
						
						outputGenerated = true;
						WriteObject(currentAce);
					}

					// Get SACL entries
					foreach (AdaptedCommonAce currentAce in currentSd.GetAuditRules(
						!this.ExcludeExplicit, 
						!this.ExcludeInherited, 
						typeof(PacPrincipal),
						this.DisplayOptions,
						_aceFilters,
						specific
					)) {
						
						outputGenerated = true;
						WriteObject(currentAce);
					}	
				}
				catch (System.Management.Automation.PipelineStoppedException e) {
					// Pipeline was stopped (maybe Select-Object), so no need to write error
				}
				catch (Exception e) {
					WriteError(new ErrorRecord(
						new Exception(string.Format("Error getting ACE(s) for '{0}': {1}", currentSd.Path.ToString(), e.Message)), 
						"", 
						ErrorCategory.InvalidData, 
						currentSd
					));
				}
				
				if (outputGenerated == false) {
					WriteWarning(string.Format("No ACEs were returned for '{0}'", currentSd.Path.ToString()));
				}
			}
		}
	}

}
