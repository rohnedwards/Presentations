namespace ROE.PowerShellAccessControl {

	public class ModifyPacAccessControlEntryCmdlet : PacModuleModificationCmdlet {
		
		#region Parameters
		[Parameter(Mandatory = true, ParameterSetName = "ByAceObject")]
		public AuthorizationRule[] AceObject { get; set; }
		
        [Parameter(ValueFromPipelineByPropertyName = true, ParameterSetName="GenericAccessMask")]
        [Parameter(ValueFromPipelineByPropertyName = true, ParameterSetName="FolderRights")]
        [Parameter(ValueFromPipelineByPropertyName = true, ParameterSetName="RegistryRights")]
        [Parameter(ValueFromPipelineByPropertyName = true, ParameterSetName="ActiveDirectoryRights")]
        [Parameter(ValueFromPipelineByPropertyName = true, ParameterSetName="ActiveDirectoryRightsObjectAceType")]
		public Enums.AceType AceType { 
			get { return _aceType; }
			set { _aceType = value; }
		}
		private Enums.AceType _aceType = Enums.AceType.Allow;
		
        [Parameter(Mandatory = true, ValueFromPipelineByPropertyName = true, ParameterSetName="GenericAccessMask")]
        [Parameter(Mandatory = true, ValueFromPipelineByPropertyName = true, ParameterSetName="FolderRights")]
        [Parameter(Mandatory = true, ValueFromPipelineByPropertyName = true, ParameterSetName="RegistryRights")]
        [Parameter(Mandatory = true, ValueFromPipelineByPropertyName = true, ParameterSetName="ActiveDirectoryRights")]
        [Parameter(Mandatory = true, ValueFromPipelineByPropertyName = true, ParameterSetName="ActiveDirectoryRightsObjectAceType")]
		public virtual PacPrincipal Principal { get; set; }
		
		[Parameter(Mandatory = true, ValueFromPipelineByPropertyName = true, ParameterSetName = "GenericAccessMask")]
		public object AccessMask { 
			get { return _accessMask; }
			set {
				/*
					Must be one of the following:
						- Numeric
						- Flags enum
						- Access mask display
						
				*/
				if (value == null) {
					_numericAccessMask = 0;
					this.AccessRightType = typeof(int);
					return;
				}
				else if (value is PSObject) {
					value = ((PSObject) value).BaseObject;
				}

				Type valueType = value.GetType();
				switch (valueType.FullName) {
					
					case "System.Int32":
					case "System.Int16":
					case "System.UInt32":
					case "System.UInt16":
						_numericAccessMask = (int) value;
						break;
					
					case "ROE.PowerShellAccessControl.AccessMaskDisplay":
						AccessMaskDisplay accessMaskDisp = (AccessMaskDisplay) value;
						this.AccessRightType = accessMaskDisp.AccessRightType;
						_numericAccessMask = accessMaskDisp.AccessMask;
						break;
						
					default:
						if (valueType.IsEnum && valueType.IsDefined(typeof(FlagsAttribute), false)) {
							this.AccessRightType = valueType;
							goto case "System.Int32";
						}
						else {
							try {
								value = Convert.ToInt32(value);
								goto case "System.Int32";
							}
							catch {
								throw new Exception(string.Format("Unsupported type for AccessMask: {0}", valueType.FullName));
							}
						}
						break;
				}
				
				_accessMask = value;
			} 
		}
		object _accessMask;
		private int _numericAccessMask = 0;
/*
		[Parameter(ParameterSetName = "GenericAccessMask")]
		public Type AccessRightType { 
			get { return _accessRightType; }
			set { _accessRightType = value; }
		}
		private Type _accessRightType = typeof(int);
*/
		internal Type AccessRightType { 
			get { return _accessRightType; }
			set { _accessRightType = value; }
		}
		private Type _accessRightType = typeof(int);
		

		[Parameter(Mandatory = true, ValueFromPipelineByPropertyName = true, ParameterSetName = "FolderRights")]
		[Alias(new string[] { "FileRights", "FileSystemRights" })]
		public FileSystemRights FolderRights { get; set; }

		[Parameter(Mandatory = true, ValueFromPipelineByPropertyName = true, ParameterSetName = "RegistryRights")]
		public RegistryRights RegistryRights { get; set; }

        [Parameter(Mandatory = true, ValueFromPipelineByPropertyName = true, ParameterSetName = "ActiveDirectoryRights")]
		public Enums.ActiveDirectoryRights ActiveDirectoryRights { get; set; }

        [Parameter(ValueFromPipelineByPropertyName = true, ParameterSetName = "ActiveDirectoryRights")]
        [Parameter(Mandatory = true, ValueFromPipelineByPropertyName = true, ParameterSetName="ActiveDirectoryRightsObjectAceType")]
        [Parameter(ParameterSetName="GenericAccessMask", ValueFromPipelineByPropertyName = true)]
		public ActiveDirectoryAceTypeInstance ObjectAceType { get; set; }

        [Parameter(ValueFromPipelineByPropertyName = true, ParameterSetName = "ActiveDirectoryRights")]
        [Parameter(ValueFromPipelineByPropertyName = true, ParameterSetName="ActiveDirectoryRightsObjectAceType")]
        [Parameter(ParameterSetName="GenericAccessMask", ValueFromPipelineByPropertyName = true)]
		public ActiveDirectoryInheritedAceTypeInstance InheritedObjectAceType { get; set; }

        [Parameter(ValueFromPipelineByPropertyName = true, ParameterSetName="GenericAccessMask")]
        [Parameter(ValueFromPipelineByPropertyName = true, ParameterSetName="FolderRights")]
        [Parameter(ValueFromPipelineByPropertyName = true, ParameterSetName="RegistryRights")]
        [Parameter(ValueFromPipelineByPropertyName = true, ParameterSetName="ActiveDirectoryRights")]
        [Parameter(ValueFromPipelineByPropertyName = true, ParameterSetName="ActiveDirectoryRightsObjectAceType")]
        public Enums.AppliesTo AppliesTo {
			get { return _appliesTo; }
			set { _appliesTo = value; }
		}
		private Enums.AppliesTo _appliesTo = AppliesTo.Object;

        [Parameter(ValueFromPipelineByPropertyName = true, ParameterSetName="GenericAccessMask")]
        [Parameter(ValueFromPipelineByPropertyName = true, ParameterSetName="FolderRights")]
        [Parameter(ValueFromPipelineByPropertyName = true, ParameterSetName="RegistryRights")]
        [Parameter(ValueFromPipelineByPropertyName = true, ParameterSetName="ActiveDirectoryRights")]
        [Parameter(ValueFromPipelineByPropertyName = true, ParameterSetName="ActiveDirectoryRightsObjectAceType")]
		public AuditFlags AuditFlags { get; set; }
		#endregion

		internal PacAuthorizationRule CreateNewPacRule() {
			// Figure out if AceType should be audit
			if (!this.MyInvocation.BoundParameters.ContainsKey("AceType") && this.AuditFlags != AuditFlags.None) {
				this.AceType = Enums.AceType.Audit;
			}

			// Need to figure out AccessMask if GenericAccessMask param set isn't being used
			Guid objectAceTypeGuid = Guid.Empty;
			Guid inheritedObjectAceTypeGuid = Guid.Empty;
			switch (this.ParameterSetName) {
				case "RegistryRights":
					this.AccessMask = this.RegistryRights;
//					this.AccessRightType = typeof(RegistryRights);
					break;

				case "FolderRights":
					this.AccessMask = this.FolderRights;
//					this.AccessRightType = typeof(FileSystemRights);
					break;

				case "ActiveDirectoryRights":
				case "ActiveDirectoryRightsObjectAceType":
					this.AccessMask = this.ActiveDirectoryRights;
//					this.AccessRightType = typeof(Enums.ActiveDirectoryRights);
					
					if (this.MyInvocation.BoundParameters.ContainsKey("ObjectAceType")) {
						objectAceTypeGuid = new Guid(this.ObjectAceType.AceTypeGuid);
					}
					if (this.MyInvocation.BoundParameters.ContainsKey("InheritedObjectAceType")) {
						inheritedObjectAceTypeGuid = new Guid(this.InheritedObjectAceType.AceTypeGuid);
					}

					if (this._numericAccessMask == 0) {
						if (objectAceTypeGuid == Guid.Empty) {
//							WriteError(new ErrorRecord(
								throw new Exception("-ObjectAceType must be specificed if -ActiveDirectoryRights isn't provided"); //,
//								"",
//								ErrorCategory.InvalidData,
//								null
//							));
						}
						else {
							switch (this.ObjectAceType.ObjectType) {
								case ActiveDirectoryObjectAceTypeGuidType.ClassObject:
									WriteWarning(string.Format("'{0}' ObjectAceType is a '{1}', so CreateChild rights are being assumed. If DeleteChild rights are needed, please provide a value for -ActiveDirectoryRights", this.ObjectAceType.DisplayName, this.ObjectAceType.ObjectType));
									this.AccessMask = Enums.ActiveDirectoryRights.ReadProperty;
									break;
									
								case ActiveDirectoryObjectAceTypeGuidType.Property:
								case ActiveDirectoryObjectAceTypeGuidType.PropertySet:
									WriteWarning(string.Format("'{0}' ObjectAceType is a '{1}', so ReadProperty rights are being assumed. If WriteProperty rights are needed, please provide a value for -ActiveDirectoryRights", this.ObjectAceType.DisplayName, this.ObjectAceType.ObjectType));
									this.AccessMask = Enums.ActiveDirectoryRights.ReadProperty;
									break;

								case ActiveDirectoryObjectAceTypeGuidType.ExtendedRight:
									this.AccessMask = Enums.ActiveDirectoryRights.ExtendedRight;
									break;
									
								case ActiveDirectoryObjectAceTypeGuidType.ValidatedWrite:
									this.AccessMask = Enums.ActiveDirectoryRights.ValidatedWrite;
									break;

								default:
									break;
							}
						}
						// Need to figure out
					}
					break;
					
				case "GenericAccessMask":
					// No more work needed
					break;

				default:
					throw new Exception(string.Format("Unknown parameter set: {0}", this.ParameterSetName));
			}

			// Get AccessRightType
			


			// Figure out AppliesTo if it wasn't specified
			if (!this.MyInvocation.BoundParameters.ContainsKey("AppliesTo")) {
				this.WriteDebug("AppliesTo wasn't specified, so determining it based on parameter set name");
				switch (this.AccessRightType.Name) {
					case "RegistryRights":
					case "WmiNamespaceRights":
					case "ActiveDirectoryRights":
					case "ActiveDirectoryRightsObjectAceType":
						this.AppliesTo = AppliesTo.Object | AppliesTo.ChildContainers;
						break;
						
					case "FileSystemRights":
						this.AppliesTo = AppliesTo.Object | AppliesTo.ChildContainers | AppliesTo.ChildObjects;
						break;
						
					default:
						this.AppliesTo = AppliesTo.Object;
						break;
				}
			}


			WriteDebug(string.Format("CreateNewPacRule(): AceType = {0}", this.AceType));
			WriteDebug(string.Format("CreateNewPacRule(): Principal = {0}", this.Principal));
			WriteDebug(string.Format("CreateNewPacRule(): AccessMask = {0}", this.AccessMask));
			return AdaptedSecurityDescriptor.CreateRule(
				this.AceType, 
				this.Principal, 
				this._numericAccessMask, 
				this.AppliesTo, 
				objectAceTypeGuid, 
				inheritedObjectAceTypeGuid, 
				this.AuditFlags, 
				this.AccessRightType
			);
		}

		internal void ModifyPacRule(PSObject[] securityDescriptors, AuthorizationRule[] aceObjects, AccessControlModification modification, bool createAcl) {

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
			
				bool isAuditAce = false;
				dynamic convertedAceObject;
				bool wasModified = false;
				Type expectedAceType;

if (this.ParameterSetName == "RemoveAllEntries" && this is RemovePacAccessControlEntryCommand) {
WriteDebug("ModifyPacRule(): RemoveAllEntries detected. Changing aceObjects array to match current SD ACL ACEs");
	RemovePacAccessControlEntryCommand removeAceInstance = (RemovePacAccessControlEntryCommand) this;
	List<AuthorizationRule> purgeAces = new List<AuthorizationRule>();
	
	// Doesn't matter if modification is in Remove or RemoveSpecific mode since
	// the current ACL(s) will be passed

	try {
		if (removeAceInstance.RemoveAllAccessEntries) {
			WriteDebug("  -> RemoveAllAccessEntries switch passed");
			foreach (AdaptedCommonAce ace in securityDescriptor.GetAccessRules(
				true,
				false,  // No need to include inherited
				typeof(SecurityIdentifier)
			)) {
				
				purgeAces.Add((AuthorizationRule) GenericAceConverter.Converter.ConvertTo(ace, typeof(AuthorizationRule)));
			}
		}
		
		if (removeAceInstance.RemoveAllAuditEntries) {
			WriteDebug("  -> RemoveAllAuditEntries switch passed");
			foreach (AdaptedCommonAce ace in securityDescriptor.GetAuditRules(
				true,
				false,  // No need to include inherited
				typeof(SecurityIdentifier)
			)) {

				purgeAces.Add((AuthorizationRule) GenericAceConverter.Converter.ConvertTo(ace, typeof(AuthorizationRule)));
			}
		}
	}
	catch (Exception e) {
		WriteError(new ErrorRecord(
			new Exception(string.Format("Error getting ACL entries to remove: {0}", e.Message)),
			"",
			ErrorCategory.InvalidData,
			currentSD
		));
		continue; // Next foreach iteration
	}

	aceObjects = purgeAces.ToArray();
}

				WriteDebug(string.Format("ModifyPacRule(): Modification type = {0}; looping through {1} ACEs...", modification, aceObjects.Length));
				foreach (AuthorizationRule aceObject in aceObjects) {
					//cmdletInstance.WriteDebug(string.Format("ACE '{0}' with modification {1}...", aceObject.ToString(), modification));
				
					shouldProcessDisplayString.Clear();
				
					// Figure out if this is an Audit ACE. Since  AceObject parameter is an Authorization rule, we can check
					// for AuditRule or PacAuditRule (no need to worry about GenericAce coming through)
					isAuditAce = false;
					if (aceObject is PacAuditRule || aceObject is AuditRule) {
						isAuditAce = true;
						WriteDebug("  -> ACE is Audit rule");
					}
					else {
						WriteDebug("  -> ACE is Access rule");
					}

					shouldProcessDisplayString.AppendFormat("{0} '{1}' to/from '{2}' ", modification, aceObject.ToString(), sdDisplayPath.ToString());
					if (isAuditAce) { shouldProcessDisplayString.Append("SACL"); }
					else { shouldProcessDisplayString.Append("DACL"); }

					if (!ShouldProcess(
						shouldProcessDisplayString.ToString(),
						shouldProcessDisplayString.ToString(),
						"ACL Modification"
					)) {
						continue;
					}

					if (isAuditAce) {
						expectedAceType = securityDescriptor.AuditRuleType;
						
						WriteDebug(string.Format("aceObject is of type {0}, but must be of type {1}; using GenericAceConverter...", aceObject.GetType().Name, expectedAceType.Name));
						try {
							convertedAceObject = GenericAceConverter.Converter.ConvertTo(aceObject, expectedAceType);
						}
						catch (Exception e) {
							WriteError(new ErrorRecord(
								new Exception(string.Format("Error converting ACE from to {0} type: {1}", expectedAceType.Name, e.Message)),
								"",
								ErrorCategory.InvalidData,
								aceObject
							));
							return;
						}
						
						if (securityDescriptor is ObjectSecurity) {
							securityDescriptor.ModifyAuditRule(modification, convertedAceObject, out wasModified);
						}
						else if (securityDescriptor is AdaptedSecurityDescriptor) {
							securityDescriptor.ModifyAuditRule(modification, convertedAceObject, out wasModified, createAcl);
						}
						else {
							WriteError(new ErrorRecord(
								new Exception(string.Format("securityDescriptor is unknown type: {0}", securityDescriptor.GetType().Name)),
								"",
								ErrorCategory.InvalidData,
								securityDescriptor
							));
							return;
						}
					}
					else {
						expectedAceType = securityDescriptor.AccessRuleType;
						
						WriteDebug(string.Format("aceObject is of type {0}, but must be of type {1}; using GenericAceConverter...", aceObject.GetType().Name, expectedAceType.Name));
						try {
							convertedAceObject = GenericAceConverter.Converter.ConvertTo(aceObject, expectedAceType);
						}
						catch (Exception e) {
							WriteError(new ErrorRecord(
								new Exception(string.Format("Error converting ACE from to {0} type: {1}", expectedAceType.Name, e.Message)),
								"",
								ErrorCategory.InvalidData,
								aceObject
							));
							return;
						}
						
						if (securityDescriptor is ObjectSecurity) {
							securityDescriptor.ModifyAccessRule(modification, convertedAceObject, out wasModified);
						}
						else if (securityDescriptor is AdaptedSecurityDescriptor) {
							securityDescriptor.ModifyAccessRule(modification, convertedAceObject, out wasModified, createAcl);
						}
						else {
							WriteError(new ErrorRecord(
								new Exception(string.Format("securityDescriptor is unknown type: {0}", securityDescriptor.GetType().Name)),
								"",
								ErrorCategory.InvalidData,
								securityDescriptor
							));
							return;
						}
					}
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

		protected override void ProcessRecord() {
			if (this.ParameterSetName != "ByAceObject") {
				WriteDebug("ProcessRecord(): AceObject parameter not used; populating it with CreateNewPacRule()");
				this.AceObject = new AuthorizationRule[] { this.CreateNewPacRule() };
			}
		}
	}


	[Cmdlet(VerbsCommon.New, "PacAccessControlEntry")]
	public class NewPacAccessControlEntryCommand : ModifyPacAccessControlEntryCmdlet {

		#region Parameters to hide
		/*
			Add-AccessControlEntry and Remove-AccessControlEntry have parametersets that have
			the exact parameters needed by this cmdlet. For that reason, I decided to make them
			all inherit from the same base cmdlet (which comes from another base that includes
			-InputObject and -PacCommandOption). New-AccessControlEntry has no concept of
			-InputObject, -PacCommandOption, -PassThru, -Apply, -AceObject, etc, so those are
			hidden with the new keyword here
		*/
		new PSObject[] InputObject { get { return null; } }
		new AuthorizationRule[] AceObject { get { return null; } }
		new SwitchParameter Force { get { return false; } }
		new SwitchParameter Apply { get { return false; } }
		new SwitchParameter PassThru { get { return false; } }
		new PacSdOption PacSDOption { get { return null; } }
		#endregion
		#region Parameters
		[Parameter()]
		public Type OutputType { get; set; }
		#endregion
		
		protected override void ProcessRecord() {
			try {
				PacAuthorizationRule newRule = base.CreateNewPacRule();
				
				if (this.OutputType == null) {
					WriteObject(newRule);
				}
				else {
					WriteObject(GenericAceConverter.Converter.ConvertTo(newRule, OutputType));
				}
			}
			catch (Exception e) {
				WriteError(new ErrorRecord(
					e,
					"",
					ErrorCategory.InvalidData,
					null
				));
			}
		}
	}


	[Cmdlet(VerbsCommon.Add, "PacAccessControlEntry", SupportsShouldProcess = true)]
	public class AddPacAccessControlEntryCommand : ModifyPacAccessControlEntryCmdlet {
		
		#region Parameters
        [Parameter()]
		public SwitchParameter AddEvenIfAclDoesntExist { get; set; }

        [Parameter()]
        [Alias("Set")]
        public SwitchParameter Overwrite { get; set; }
		#endregion
		
		protected override void BeginProcessing() {
			base.BeginProcessing();
		}
		
		protected override void ProcessRecord() {

			base.ProcessRecord();  // Populate AceObject property

			AccessControlModification modification;
			if (this.Overwrite) {
				modification = AccessControlModification.Set;
			}
			else {
				modification = AccessControlModification.Add;
			}

			base.ModifyPacRule(
				this.InputObject, 
				this.AceObject, 
				modification, 
				this.AddEvenIfAclDoesntExist
			);
		}
	}


	[Cmdlet(VerbsCommon.Remove, "PacAccessControlEntry", SupportsShouldProcess = true)]
	public class RemovePacAccessControlEntryCommand : ModifyPacAccessControlEntryCmdlet {
		
		#region Parameters
        [Parameter(Mandatory = true, ValueFromPipelineByPropertyName = true, ParameterSetName="GenericAccessMask")]
        [Parameter(Mandatory = true, ValueFromPipelineByPropertyName = true, ParameterSetName="FolderRights")]
        [Parameter(Mandatory = true, ValueFromPipelineByPropertyName = true, ParameterSetName="RegistryRights")]
        [Parameter(Mandatory = true, ValueFromPipelineByPropertyName = true, ParameterSetName="ActiveDirectoryRights")]
        [Parameter(Mandatory = true, ValueFromPipelineByPropertyName = true, ParameterSetName="ActiveDirectoryRightsObjectAceType")]
        [Parameter(Mandatory = true, ValueFromPipelineByPropertyName = true, ParameterSetName="PurgePrincipal")]
		public override PacPrincipal Principal { get; set; }

        [Parameter(ParameterSetName="RemoveAllEntries")]
		public SwitchParameter RemoveAllAccessEntries { get; set; }

        [Parameter(ParameterSetName="RemoveAllEntries")]
		public SwitchParameter RemoveAllAuditEntries { get; set; }

        [Parameter(ParameterSetName="PurgePrincipal")]
		public SwitchParameter PurgeAccessRules { get; set; }

        [Parameter(ParameterSetName="PurgePrincipal")]
		public SwitchParameter PurgeAuditRules { get; set; }

        [Parameter(ParameterSetName="GenericAccessMask")]
        [Parameter(ParameterSetName="FolderRights")]
        [Parameter(ParameterSetName="RegistryRights")]
        [Parameter(ParameterSetName="ActiveDirectoryRights")]
        [Parameter(ParameterSetName="ActiveDirectoryRightsObjectAceType")]
        public SwitchParameter Specific { get; set; }
		#endregion
		
		protected override void BeginProcessing() {
			base.BeginProcessing();
		}
		
		protected override void ProcessRecord() {

			WriteDebug("Remove-AccessControlEntry: ProcessRecord()");
			WriteDebug(string.Format("Remove-AccessControlEntry:   -> ParameterSetName = {0}", this.ParameterSetName));

			AccessControlModification modification;
			if (this.Specific) {
				modification = AccessControlModification.RemoveSpecific;
			}
			else {
				modification = AccessControlModification.Remove;
			}
WriteDebug(string.Format("Remove-AccessControlEntry:   -> Principal = {0}", this.Principal));
			List<AuthorizationRule> purgeAces;
			switch (this.ParameterSetName) {
				case "PurgePrincipal":
					// The SD objects have PurgeAccessRules() and PurgeAuditRules() methods,
					// but creating the following three ACEs (assuming both DACL and SACL
					// are to be cleared) should accomplish the same thing within the
					// framework of the ModifyPacRule() method

					WriteDebug("Remove-AccessControlEntry: PurgePrincipal mode");
					purgeAces = purgeAces = new List<AuthorizationRule>();
					modification = AccessControlModification.RemoveAll;

					if (this.PurgeAccessRules) {
						WriteDebug(string.Format("  -> PurgeAccessRules switch passed; changing modification to RemoveAll and creating Access ACE with '{0}' SID", this.Principal.SecurityIdentifier));
						purgeAces.Add(new PacAccessRule(
							this.Principal, 
							1, 							// Doesn't matter b/c of RemoveAll modification
							AppliesTo.Object, 			// Doesn't matter b/c of RemoveAll modification
							AccessControlType.Allow
						));

						purgeAces.Add(new PacAccessRule(
							this.Principal, 
							1, 							// Doesn't matter b/c of RemoveAll modification
							AppliesTo.Object, 			// Doesn't matter b/c of RemoveAll modification
							AccessControlType.Deny
						));
					}
					
					if (this.PurgeAuditRules) {
						WriteDebug(string.Format("  -> PurgeAuditRules switch passed; changing modification to RemoveAll and creating Audit ACE with '{0}' SID", this.Principal.SecurityIdentifier));
						purgeAces.Add(new PacAuditRule(
							this.Principal, 
							1, 						// Doesn't matter b/c of RemoveAll modification
							AppliesTo.Object, 		// Doesn't matter b/c of RemoveAll modification
							AuditFlags.Success  	// Doesn't matter
						));
					}
					this.AceObject = purgeAces.ToArray();
					break;
					
				case "RemoveAllEntries":
					WriteDebug("Remove-AccessControlEntry: RemoveAllEntries mode");
					// ModifyPacRule() will check the current ParameterSetName
					// If it is "RemoveAllEntries", it will change the ACE array it
					// is using to match all aces in the SD it is currently looking at.
					//
					// Dirty hack that was to refactor existing code. Will probably make
					// it cleaner at some point...
					break;
				
				default:
					base.ProcessRecord();  // Populate AceObject property
					break;
			}

	

			this.ModifyPacRule(
				this.InputObject, 
				this.AceObject, 
				modification, 
				false 
			);
		}
	}
}