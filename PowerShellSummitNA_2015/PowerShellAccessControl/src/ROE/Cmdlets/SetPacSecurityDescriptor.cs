 namespace ROE.PowerShellAccessControl {

	[Cmdlet(VerbsCommon.Set, "PacSecurityDescriptor", SupportsShouldProcess = true)]
	[OutputType(new Type[] { typeof(AdaptedSecurityDescriptor) })]
	public class SetPacSecurityDescriptorCommand : PacModuleModificationCmdlet {

		#region Parameters
        [Parameter(Position = 1)]
		public PSObject SDObject { get; set; }
		AdaptedSecurityDescriptor _adaptedSdObject;

/*
        [Parameter(Position = 0)]
        public PSObject[] InputObject { get; set; }
*/
        new internal SwitchParameter Apply { get { return true; } } // Trying to hide -Apply param

/*        
		[Parameter()]
		public SwitchParameter BypassAclCheck { get; set; }
		
		[Parameter()]
        public GetSecurityInformation Sections { get; set; }
*/
		#endregion

		#region Private/Internal properties and fields

		private static SecurityInformation GetRealSecurityInformationSections(SecurityInformation startingSections, AdaptedSecurityDescriptor adaptedSdObject) {
			SecurityInformation realSections = (SecurityInformation) startingSections;
			
			if (adaptedSdObject != null && (realSections & SecurityInformation.Dacl) != 0) {
				// Need to set bit specifying whether or not Dacl is protect or unprotected
				if (adaptedSdObject.AreAccessRulesProtected == true) {
					realSections |= SecurityInformation.ProtectedDacl;
				}
				else {
					realSections |= SecurityInformation.UnprotectedDacl;
				}
			}
			else if ((realSections & (SecurityInformation.ProtectedDacl | SecurityInformation.UnprotectedDacl)) != 0) {
				realSections |= SecurityInformation.Dacl;
			}

			if (adaptedSdObject != null && (realSections & SecurityInformation.Sacl) != 0) {
				// Need to set bit specifying whether or not Dacl is protect or unprotected
				if (adaptedSdObject.AreAuditRulesProtected == true) {
					realSections |= SecurityInformation.ProtectedSacl;
				}
				else {
					realSections |= SecurityInformation.UnprotectedSacl;
				}
			}
			else if ((realSections & (SecurityInformation.ProtectedSacl | SecurityInformation.UnprotectedSacl)) != 0) {
				realSections |= SecurityInformation.Sacl;
			}
			
			return realSections;
		}
		#endregion
		
		protected override void BeginProcessing() {
			base.Apply = true; // Always set this (BypassAclCheck mode checks for it)
			base.BeginProcessing();
		}

		protected override void ProcessRecord() {

			// Can be 0 if user didn't specify -PacSDOption
			SecurityInformation setSdSections = (SecurityInformation) base._securityDescriptorSections;

			// -InputObject comes from parent cmdlet, and it accepts pipeline input. If user provides -InputObject but no -SDObject,
			// assume they're trying to commit changes, so assign the input object to the SDObject
			if (this.SDObject == null && this.InputObject.Length == 1) {
				WriteDebug("No -SDObject -InputObject specified; setting SDObject to InputObject[0]");
				this.SDObject = this.InputObject[0];
			}
			
			#region Check to make sure there's one (and only one) SDObject after SD resolution
			// If this was already an Adapted SD object, we'll be able to use the GetRequestedSecurityInformation() and
			// GetModifiedSecurityInformation() methods
			IEnumerable<AdaptedSecurityDescriptor> adaptedSds = this.GetAdaptedSecurityDescriptor(
				new PSObject[] { this.SDObject }
			);
			
			int adaptedSdCount = 0;
			foreach (AdaptedSecurityDescriptor currentAdaptedSecurityDescriptor in adaptedSds) {
				if (adaptedSdCount > 1) {
throw new Exception ("Terminating error because there's more than one SDObject");			
				}
				_adaptedSdObject = currentAdaptedSecurityDescriptor;
				adaptedSdCount++;
			}
			

			if (adaptedSdCount == 0) {
//return;
throw new Exception ("Terminating error because there are 0 SDObjects");			
			}
			
			#endregion
			
			// This can't happen since PacModuleCmdlet sets InputObject as a mandatory parameter:			
			if (this.InputObject == null) {
				WriteVerbose("No -InputObject specified; setting InputObject to SDObject");
				this.InputObject = new PSObject[] { this.SDObject };
			}

			if (setSdSections == 0) {
				WriteDebug("SD sections weren't specified, so assigning modified sections from SDObject");
				setSdSections = _adaptedSdObject.GetModifiedSecurityInformation();
			}

			if (setSdSections == 0) {
				WriteDebug(string.Format("No modified sections detected, so using DefaultSetSecurityDescriptorSections: {0}", PacSdOption.DefaultSetSecurityDescriptorSections));
				setSdSections = PacSdOption.DefaultSetSecurityDescriptorSections;
				
				// Alternative
//				setSdSections = _adaptedSdObject.GetRequestedSecurityInformation();
			}
			
			if ((setSdSections & SecurityInformation.Owner) != 0) {
				WriteDebug("Owner section is present; attempting to enable SeRestorePrivilege");
				
				// Don't change anything if error enabling these? (EnablePrivilege() will write a warning)
				base.EnablePrivilege("SeRestorePrivilege");
				base.EnablePrivilege("SeTakeOwnerShipPrivilege");
//						setSdSections ^= SecurityInformation.Owner;
			}

			SetPacSecurityDescriptor(this.InputObject, _adaptedSdObject, setSdSections);
		}

		protected override void EndProcessing() {

			// Revert any privileges that were enabled
			Dispose();
		}

		#region Static methods
/*
		internal void SetPacSecurityDescriptorHelper(PSObject[] inputObject, AdaptedSecurityDescriptor adaptedSdObject, SecurityInformation setSdSections) {
			
			foreach (AdaptedSecurityDescriptorPathInformation pathInfo in GetPathInfoFromPSObject(
					inputObject
				)) {

				if (pathInfo.ObjectType != adaptedSdObject.ObjectType && !(pathInfo.ObjectType.ToString().StartsWith("Registry") && adaptedSdObject.ObjectType.ToString().StartsWith("Registry"))) {
					// Object types don't match
					WriteError(new ErrorRecord(
						new Exception(string.Format("'{0}' object type ({1}) doesn't match the object type for '{2}' ({3})", adaptedSdObject.Path.ToString(), adaptedSdObject.ObjectType, pathInfo.SdPath.ToString(), pathInfo.ObjectType)),
						"",
						ErrorCategory.InvalidData,
						pathInfo
					));
					continue;
				}
				
				if (ShouldProcess(
						string.Format("Set security descriptor for '{0}' {1} ({2})", pathInfo.SdPath.ToString(), pathInfo.ObjectType, GetRealSecurityInformationSections(setSdSections, adaptedSdObject)),
						string.Format("Do you want to set the security descriptor for '{0}' {1} ({2} sections)", pathInfo.SdPath.ToString(), pathInfo.ObjectType, GetRealSecurityInformationSections(setSdSections, adaptedSdObject)),
						"Set Security Descriptor"
					)) {

					SetSecurityInfo(pathInfo, adaptedSdObject, GetRealSecurityInformationSections(setSdSections, adaptedSdObject));
				}
			}
		}
		internal void SetSecurityInfo(AdaptedSecurityDescriptorPathInformation pathInfo, AdaptedSecurityDescriptor adaptedSD, SecurityInformation securityInformation) {
			
			if (securityInformation == 0) { return; }

			RawSecurityDescriptor rawSD = adaptedSD.RawSD;
			
			#region Get binary forms
			byte[] ownerBinaryForm, groupBinaryForm, daclBinaryForm, saclBinaryForm;
			if (rawSD.Owner != null) {
				ownerBinaryForm = new byte[rawSD.Owner.BinaryLength];
				rawSD.Owner.GetBinaryForm(ownerBinaryForm, 0);
			}
			else {
				ownerBinaryForm = new byte[0];
			}
			
			if (rawSD.Group != null) {
				groupBinaryForm = new byte[rawSD.Group.BinaryLength];
				rawSD.Group.GetBinaryForm(groupBinaryForm, 0);
			}
			else {
				groupBinaryForm = new byte[0];
			}
			
			if (rawSD.DiscretionaryAcl != null) {
				daclBinaryForm = new byte[rawSD.DiscretionaryAcl.BinaryLength];
				rawSD.DiscretionaryAcl.GetBinaryForm(daclBinaryForm, 0);
			}
			else {
				daclBinaryForm = new byte[0];
			}
			
			if (rawSD.SystemAcl != null) {
				saclBinaryForm = new byte[rawSD.SystemAcl.BinaryLength];
				rawSD.SystemAcl.GetBinaryForm(saclBinaryForm, 0);
			}
			else {
				saclBinaryForm = new byte[0];
			}
			#endregion

			int exitCode;
			ResourceType objectType = pathInfo.ObjectType;

			if (this.PacSDOption.BypassAclCheck && (objectType == ResourceType.RegistryKey || objectType == ResourceType.RegistryWow6432Key)) {
				objectType = ResourceType.KernelObject;
			}
			
			SecurityDescriptorPath sdPath = pathInfo.SdPath;

			WriteDebug(string.Format("SetSecurityInfo() for {0} with path of '{1}' ({3}) and sections '{2}' (SD size is {4})", objectType, sdPath, securityInformation, sdPath.GetType().Name, rawSD.BinaryLength));
			
			bool yesToAll = false, noToAll = false;
			if (this._force || ShouldContinue(
				string.Format("Do you want to set the security descriptor with the following properties on the '{0}' {1}?\n\n{2}", pathInfo.SdPath.ToString(), pathInfo.ObjectType, adaptedSD.ToString(securityInformation, 0, false, false, true)),
				"Set Security Descriptor",
				ref yesToAll,
				ref noToAll
			)) {
				if (sdPath is SecurityDescriptorStringPath) {
					exitCode = advapi32.SetNamedSecurityInfo(
						((SecurityDescriptorStringPath) sdPath).Path, 
						objectType, 
						securityInformation, 
						ownerBinaryForm, 
						groupBinaryForm, 
						daclBinaryForm, 
						saclBinaryForm
					);
				}
				else if (sdPath is SecurityDescriptorSafeHandle) {
					SecurityDescriptorSafeHandle safeHandleSdPath = (SecurityDescriptorSafeHandle) sdPath;

					if (safeHandleSdPath.Handle.IsClosed || safeHandleSdPath.Handle.IsInvalid) {
// This only fixes if BypassAclMode was used and handle was closed b/c of that; if SafeHandle was used outside of that, this won't fix it being closed or invalid
						WriteDebug("SetSecurityInfo(): Current path info SafeHandle is closed or invalid; calling FinalizePathInfo()");
						pathInfo = FinalizePathInfo(pathInfo);
						
						safeHandleSdPath = (SecurityDescriptorSafeHandle) pathInfo.SdPath;
					}
					
					exitCode = advapi32.SetSecurityInfo(
						safeHandleSdPath.Handle, 
						objectType, 
						securityInformation, 
						ownerBinaryForm, 
						groupBinaryForm, 
						daclBinaryForm, 
						saclBinaryForm
					);

					if (pathInfo.BypassAclMode) {
						// Close handle (SetSecurityInfo() can re-open it if necessary)
						WriteDebug("SetSecurityInfo(): Closing BypassAclMode handle");
						safeHandleSdPath.Handle.Dispose();
					}
				}
				else if (sdPath is SecurityDescriptorHandleRef) {
					exitCode = advapi32.SetSecurityInfo(
						((SecurityDescriptorHandleRef) sdPath).Handle.Handle, 
						objectType, 
						securityInformation, 
						ownerBinaryForm, 
						groupBinaryForm, 
						daclBinaryForm, 
						saclBinaryForm
					);
	WriteWarning(string.Format("DEBUG: Security descriptor for '{0}' set; need to release HandleRef?"));
				}
				else {
					throw new Exception("Unknown Path format");
				}
				
				if (exitCode != 0) {
					WriteError(new ErrorRecord(
						new Exception(string.Format("Error setting security descriptor on '{0}' ({1}): {2}", sdPath.ToString(), objectType, (new Win32Exception(exitCode)).Message)),
						"",
						ErrorCategory.InvalidData,
						pathInfo
					));
				}
			}
		}
*/
		#endregion
	}
}
