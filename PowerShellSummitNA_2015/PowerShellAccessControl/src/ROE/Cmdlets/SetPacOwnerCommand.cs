 namespace ROE.PowerShellAccessControl {
/*
	Responsible for taking an arbitrary object and giving an AdaptedSecurityDescriptorPathInformation instance.
	
	This cmdlet provides static methods that other Cmdlets can use to get the same functionality as this one
	without having to duplicate code.
*/
	[Cmdlet(VerbsCommon.Set, "PacOwner", SupportsShouldProcess = true)]
	public class SetPacOwnerCommand : PacModuleModificationCmdlet {
		#region Parameters

		[Parameter(Position = 1)]
		public PacPrincipal Principal { get; set; }
		
		#endregion

		private SecurityIdentifier _currentUserSid;
		
		#region Cmdlet blocks
		protected override void BeginProcessing() {
			base.BeginProcessing();

			_currentUserSid = System.Security.Principal.WindowsIdentity.GetCurrent().User;
		}
		protected override void ProcessRecord() {
		
			if (this.Principal == null) {
				try {
					this.Principal = new PacPrincipal(_currentUserSid);
				}
				catch (Exception e) {
					WriteError(new ErrorRecord(
						new Exception(string.Format("Error getting PacPrincipal for current user '{0}': {1}", System.Security.Principal.WindowsIdentity.GetCurrent().Name, e.Message)),
						"",
						ErrorCategory.InvalidData,
						null
					));
					return;
				}
			}
		
			foreach (PSObject currentInputObject in this.InputObject) {
				if (currentInputObject.BaseObject is AdaptedSecurityDescriptor || currentInputObject.BaseObject is ObjectSecurity) {
					SetOwnerOnSingleSecurityDescriptor(currentInputObject.BaseObject);
				}
				else {
					this.SetCurrentApplySwitch();

					AdaptedSecurityDescriptor currentConvertedSd;
					RawSecurityDescriptor rawSD;
					byte[] rawSDBinaryForm;
					bool sdSectionsSpecified = true;

					GetSecurityInformation getSdSections = this._securityDescriptorSections;
					if (getSdSections == 0) { 
						sdSectionsSpecified = false;
						getSdSections = PacSdOption.DefaultGetSecurityDescriptorSections; 
					}

					foreach ( AdaptedSecurityDescriptorPathInformation pathInfo in GetPathInfoFromPSObject(new PSObject[] { currentInputObject }) ) {
						// Try to get AdaptedSecurity descriptor. This will honor the SecurityInformation sections
						// requested. This will fail if you don't have access, though:
						rawSDBinaryForm = null;
						try {
							rawSDBinaryForm = GetSecurityInfo(pathInfo, getSdSections);
							currentConvertedSd = AdaptedSecurityDescriptor.GetAdaptedSecurityDescriptor(pathInfo, rawSDBinaryForm, getSdSections);
						}
						catch (Exception e) {
							// Might not have permission. Try to create an SD with just the owner section
							if (sdSectionsSpecified) {
								WriteError(new ErrorRecord(
									new Exception(string.Format("Unable to get security descriptor for '{0}' with the following sections: {1}. Message: {2} (Try calling Set-Owner without providing security descriptor sections).", pathInfo.SdPath.ToString(), getSdSections, e.Message)),
									"",
									ErrorCategory.InvalidData,
									pathInfo
								));
								continue;
							}
							else {
								WriteWarning(string.Format("Unable to get '{0}' sections of the security descriptor for '{1}'. Creating a security descriptor with just the owner section present...", getSdSections, pathInfo.SdPath.ToString()));
								rawSD = new RawSecurityDescriptor(string.Format("O:{0}", this.Principal.SecurityIdentifier.ToString()));
								rawSDBinaryForm = new byte[rawSD.BinaryLength];
								rawSD.GetBinaryForm(rawSDBinaryForm, 0);
								currentConvertedSd = AdaptedSecurityDescriptor.GetAdaptedSecurityDescriptor(pathInfo, rawSDBinaryForm, GetSecurityInformation.Owner);
	//							currentConvertedSd._ownerModified = true;
							}
						}

						SetOwnerOnSingleSecurityDescriptor(currentConvertedSd);
					}

					this.ResetCurrentApplySwitch();
				}
			}
		}
		#endregion

		#region Static methods
		private void SetOwnerOnSingleSecurityDescriptor(dynamic securityDescriptor) {
			// ProcessRecord() can receive SD objects (good) or arbitrary objects that require Get-SecurityDescriptor functionality, which can return more than
			// one instance. To try to keep it so that all objects go through the same code path, this method was created :)
			
			StringBuilder shouldProcessDisplaySb = new StringBuilder();
			shouldProcessDisplaySb.Append("Set owner ");
			
			if (securityDescriptor is AdaptedSecurityDescriptor) {
				shouldProcessDisplaySb.AppendFormat("on '{0}' ", securityDescriptor.Path.ToString());
			}
			shouldProcessDisplaySb.AppendFormat("to '{0}'", this.Principal);
			string shouldProcessDisplayString = shouldProcessDisplaySb.ToString();
			
			if (ShouldProcess(shouldProcessDisplayString, shouldProcessDisplayString, "Set Owner")) {
				try {
					securityDescriptor.SetOwner(this.Principal.SecurityIdentifier);
				}
				catch (Exception e) {
					WriteError(new ErrorRecord(
						new Exception(string.Format("Error setting owner: {0}", e.Message)),
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
			}

			if (this.PassThru) {
				WriteObject(securityDescriptor);
			}
		}
		#endregion
	}
}