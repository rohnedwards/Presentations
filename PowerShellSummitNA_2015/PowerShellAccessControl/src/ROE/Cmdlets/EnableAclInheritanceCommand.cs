namespace ROE.PowerShellAccessControl {

	public class SetPacAclInheritanceCommand : PacModuleModificationCmdlet {
		#region Parameters
		[Parameter()]
		[Alias("DACL","Access")]
        public SwitchParameter DiscretionaryAcl { get; set; }
        
		[Parameter()]
		[Alias("SACL","Audit")]
        public SwitchParameter SystemAcl { get; set; }
   		#endregion

		protected override void BeginProcessing() {
			base.BeginProcessing();

			if (this.SystemAcl == false) {
				// At least one switch must be set, so make sure DACL is set if SACL wasn't provided
				this.DiscretionaryAcl = true;
			}
		}

		#region Static methods
		internal void SetAclProtection(PSObject[] securityDescriptors, bool isProtected, bool preserveInheritance) {
			dynamic securityDescriptor;
			foreach (object currentSD in this.GetObjectSecurityPSObjectOrAdaptedSecurityDescriptorObject(securityDescriptors)) {

				// securityDescriptor must be an ObjectSecurity or AdaptedSecurityDescriptor object:
				StringBuilder sdDisplayPath = new StringBuilder(); // Used in ShouldProcess() call
				StringBuilder shouldProcessDisplayString = new StringBuilder();

				if (currentSD is PSObject) {
					try {
						sdDisplayPath.Append( ((PSObject) currentSD).Properties["PSPath"].Value );
						sdDisplayPath.Append("");
					}
					catch {
					}

					try {
						securityDescriptor = (ObjectSecurity) ((PSObject) currentSD).BaseObject;
					}
					catch {
						throw new Exception( "make this an error" );
					}
					sdDisplayPath.AppendFormat("(.NET {0} object)", securityDescriptor.GetType().Name);
				}	
				else if (currentSD is AdaptedSecurityDescriptor) {	
					securityDescriptor = (AdaptedSecurityDescriptor) currentSD;
					sdDisplayPath.Append( securityDescriptor.Path.ToString() );
					
				}
				else {

					// This shouldn't be able to happen if ProcessRecord() is written correctly
					WriteError(new ErrorRecord(
						new Exception("securityDescriptor is of unknown type"),
						"",
						ErrorCategory.InvalidData,
						null
					));
					return;
				}

				try {
					if (this.DiscretionaryAcl) {
						shouldProcessDisplayString.Clear();
						if (isProtected) {
							shouldProcessDisplayString.AppendFormat("Disable DACL Inheritance for '{0}' (Preserve inheritance = {1})", sdDisplayPath.ToString(), preserveInheritance );
						}
						else {
							shouldProcessDisplayString.AppendFormat("Enable DACL Inheritance for '{0}'", sdDisplayPath.ToString() );
						}
						
						if (ShouldProcess(
							shouldProcessDisplayString.ToString(),
							shouldProcessDisplayString.ToString(),
							"DACL Inheritance"
						)) {

							securityDescriptor.SetAccessRuleProtection(isProtected, preserveInheritance);
						}
					}
					
					if (this.SystemAcl) {
						shouldProcessDisplayString.Clear();
						if (isProtected) {
							shouldProcessDisplayString.AppendFormat("Disable SACL Inheritance for '{0}' (Preserve inherited entries? {1})", sdDisplayPath.ToString(), preserveInheritance );
						}
						else {
							shouldProcessDisplayString.AppendFormat("Enable SACL Inheritance for '{0}'", sdDisplayPath.ToString() );
						}
						
						if (ShouldProcess(
							shouldProcessDisplayString.ToString(),
							shouldProcessDisplayString.ToString(),
							"SACL Inheritance"
						)) {

							securityDescriptor.SetAuditRuleProtection(isProtected, preserveInheritance);
						}
					}
				}
				catch (Exception e) {
					WriteError(new ErrorRecord(
						new Exception(string.Format("Error setting ACL inheritance for '{0}': {1}", sdDisplayPath.ToString(), e.Message )),
						"",
						ErrorCategory.InvalidData,
						securityDescriptor
					));
				}

				if (this._currentApply) {
					SetPacSecurityDescriptor(
						new PSObject[] { new PSObject(securityDescriptor) },	// InputObject
						ConvertSingleSecurityDescriptorToAdaptedSecurityDescriptor(securityDescriptor), //SDObject
						GetSecurityInformationSections(securityDescriptor)
					);
				}

				if (this.PassThru) {
					WriteObject(securityDescriptor);
				}

				this.ResetCurrentApplySwitch();
			}
		}
		
		#endregion
	}



	[Cmdlet(VerbsLifecycle.Enable, "PacAclInheritance", SupportsShouldProcess = true)]
	[OutputType(new Type[] { typeof(ObjectSecurity), typeof(AdaptedSecurityDescriptor) })]
	public class EnablePacAclInheritanceCommand : SetPacAclInheritanceCommand {
		
		#region Cmdlet blocks
		protected override void BeginProcessing() {
			base.BeginProcessing();
		}
		
		protected override void ProcessRecord() {
			this.SetAclProtection(
				this.InputObject,
				false,
				false   // Doesn't matter
			);
		}
		#endregion
	}

	[Cmdlet(VerbsLifecycle.Disable, "PacAclInheritance", SupportsShouldProcess = true)]
	[OutputType(new Type[] { typeof(ObjectSecurity), typeof(AdaptedSecurityDescriptor) })]
	public class DisablePacAclInheritanceCommand : SetPacAclInheritanceCommand {
		
		[Parameter()]
		public SwitchParameter PreserveExistingAces { get; set; }
		#region Cmdlet blocks
		protected override void BeginProcessing() {
			base.BeginProcessing();
		}
		
		protected override void ProcessRecord() {
			this.SetAclProtection(
				this.InputObject,
				true,
				this.PreserveExistingAces
			);
		}
		#endregion
	}
}