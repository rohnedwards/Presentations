/*
_securityDescriptor field is private CommonSecurityDescriptor

Sddl and Binary forms of SD should be RawSecurityDescriptors, though, so that MIL, CAP, etc info is contained.
 
*/

namespace ROE.PowerShellAccessControl {

	public class AdaptedSecurityDescriptor {

		#region Constructors
		internal AdaptedSecurityDescriptor(AdaptedSecurityDescriptorPathInformation pathInfo, RawSecurityDescriptor rawSecurityDescriptor, GetSecurityInformation requestedSecurityInformation) {
			_pathInfo = pathInfo;
			this._securityDescriptor = new CommonSecurityDescriptor(pathInfo.IsContainer, pathInfo.IsDS, rawSecurityDescriptor);

			this._requestedSecurityInformation = (SecurityInformation) requestedSecurityInformation;
			if (this._requestedSecurityInformation == 0) {
				// Try to figure out what sections were included
				if (rawSecurityDescriptor.Owner != (SecurityIdentifier) null) {
					this._requestedSecurityInformation |= SecurityInformation.Owner;
				}

				if (rawSecurityDescriptor.Group != (SecurityIdentifier) null) {
					this._requestedSecurityInformation |= SecurityInformation.Group;
				}
				
				if (rawSecurityDescriptor.DiscretionaryAcl != (RawAcl) null) {
					this._requestedSecurityInformation |= SecurityInformation.Dacl;
				}

				if (rawSecurityDescriptor.SystemAcl != (RawAcl) null) {
					this._requestedSecurityInformation |= SecurityInformation.Sacl;
				}
			}


			// Force building of SACL inheritance array (it's set up to be lazy, but go ahead and do
			// it at object build time so that PS can handle the token privilege modifications since
			// Cmdlet that is building this will revert the SeSecurityPrivilege and lazy population
			// won't be able to use the privilege)
			if (this._securityDescriptor.SystemAcl != null) {
				this._saclInheritanceArray = this.GetInheritanceSource(this._securityDescriptor.SystemAcl);
			}

			
			if (pathInfo.BypassAclMode) {
//FIX ME
//Console.WriteLine("pathInfo in BypassAclMode; does DACL inheritance source work?");
				this._daclInheritanceArray = this.GetInheritanceSource(this._securityDescriptor.DiscretionaryAcl);
			}

			// See note below. RawSD may have some SACL entries that CommonSecurityDescriptor will throw away.
			if ((this._securityDescriptor.SystemAcl != null) &&
				(this._securityDescriptor.SystemAcl.BinaryLength != rawSecurityDescriptor.SystemAcl.BinaryLength)) {

				ProcessExtraAces(rawSecurityDescriptor);
			}

			// MIL, CAP, Attributes (and maybe more) are special ACES stored in the SACL. If any of those are
			// requested, but the actual audit ACEs aren't, you can end up with a situation where the CommonSecurityDescriptor
			// thinks you've got an empty ACL (there were ACEs present, but they ended up not being stored b/c
			// CSD object can't handle them). The following will fix that and set the SACL to null if it wasn't
			// requested.
			if (((_requestedSecurityInformation & SecurityInformation.Sacl) == 0) && 
			    (this._securityDescriptor.SystemAcl != null) && 
				(this._securityDescriptor.SystemAcl.Count == 0)
			) {
				this._securityDescriptor.SystemAcl = null;
			}

			this._originalAccessRuleProtectionEnabled = this.AreAccessRulesProtected;
			this._originalAuditRuleProtectionEnabled = this.AreAuditRulesProtected;
		}

		public AdaptedSecurityDescriptor(AdaptedSecurityDescriptorPathInformation pathInfo, RawSecurityDescriptor rawSecurityDescriptor) : this(pathInfo, rawSecurityDescriptor, 0) { }
		public AdaptedSecurityDescriptor(AdaptedSecurityDescriptorPathInformation pathInfo, string sddlForm) : this(pathInfo, new RawSecurityDescriptor(sddlForm), 0) { }
		internal AdaptedSecurityDescriptor(AdaptedSecurityDescriptorPathInformation pathInfo, string sddlForm, GetSecurityInformation requestedSecurityInformation) : this(pathInfo, new RawSecurityDescriptor(sddlForm), requestedSecurityInformation) { }

		public AdaptedSecurityDescriptor(AdaptedSecurityDescriptorPathInformation pathInfo, byte[] binaryForm, int offset) : this(pathInfo, new RawSecurityDescriptor(binaryForm, offset), 0) { }
		internal AdaptedSecurityDescriptor(AdaptedSecurityDescriptorPathInformation pathInfo, byte[] binaryForm, int offset, GetSecurityInformation requestedSecurityInformation) : this(pathInfo, new RawSecurityDescriptor(binaryForm, offset), requestedSecurityInformation) { }
		#endregion


		
		internal static AdaptedSecurityDescriptor GetAdaptedSecurityDescriptor(AdaptedSecurityDescriptorPathInformation pathInfo, byte[] binaryForm, GetSecurityInformation requestedSecurityInformation) {
			if (pathInfo.ObjectType == ResourceType.DSObjectAll) {
				return new AdaptedActiveDirectorySecurityDescriptor(pathInfo, binaryForm, 0, requestedSecurityInformation);
			}
			else {
				return new AdaptedSecurityDescriptor(pathInfo, binaryForm, 0, requestedSecurityInformation);
			}
		}
		
		public static AdaptedSecurityDescriptor GetAdaptedSecurityDescriptor(AdaptedSecurityDescriptorPathInformation pathInfo, byte[] binaryForm) {
			return GetAdaptedSecurityDescriptor(pathInfo, binaryForm, 0);
		}
		
		public static AuthorizationRule CreateRule(Enums.AceType aceType, PacPrincipal principal, int accessMask, AppliesTo appliesTo, AuditFlags auditFlags) {
			return CreateRule(aceType, principal, accessMask, appliesTo, Guid.Empty, Guid.Empty, auditFlags, typeof(int));
		}

		private static AceFlagsConverter AceFlagsConverter = new AceFlagsConverter();
		public static PacAuthorizationRule CreateRule(Enums.AceType aceType, PacPrincipal principal, int accessMask, AppliesTo appliesTo, Guid objectAceType, Guid inheritedObjectAceType, AuditFlags auditFlags, Type accessMaskEnumeration) {
			// Make sure AuditFlags and AceType are compatible
			if (auditFlags != 0 && aceType != Enums.AceType.Audit) {
				throw new Exception("AuditFlags were present, but AceType is not 'Audit'");
			}
			else if (aceType == Enums.AceType.Audit && auditFlags == 0) {
				throw new Exception("AuditFlags must be specified when AceType is 'Audit'");
			}

			switch (aceType) {
				case Enums.AceType.Allow:
				case Enums.AceType.Deny:
					AccessControlType accessControlType;
					if (aceType == Enums.AceType.Allow) {
						accessControlType = AccessControlType.Allow;
					}
					else {
						accessControlType = AccessControlType.Deny;
					}
					
					if (objectAceType == Guid.Empty && inheritedObjectAceType == Guid.Empty) {
						// Non-object ACE
						return new PacAccessRule(principal, accessMask, appliesTo, accessControlType, accessMaskEnumeration);
					}
					else {
						return new PacObjectAccessRule(principal, accessMask, appliesTo, objectAceType, inheritedObjectAceType, accessControlType, accessMaskEnumeration);
					}
					
				case Enums.AceType.Audit:

					if (objectAceType == Guid.Empty && inheritedObjectAceType == Guid.Empty) {
						// Non-object ACE
						return new PacAuditRule(principal, accessMask, appliesTo, auditFlags, accessMaskEnumeration);
					}
					else {
						return new PacObjectAuditRule(principal, accessMask, appliesTo, objectAceType, inheritedObjectAceType, auditFlags, accessMaskEnumeration);
					}
				
				default:
					throw new Exception (string.Format("Unknown AceType: {0}", aceType));
			}

		}
		
		#region private fields
		internal AdaptedSecurityDescriptorPathInformation _pathInfo;
		private CommonSecurityDescriptor _securityDescriptor;
		internal SecurityInformation _requestedSecurityInformation;
		internal bool _ownerModified; // SetOwner can change this outside of the class
		private bool _groupModified, _daclModified, _saclModified, _labelModified, _scopeModified, _attributeModified;
		private bool? _originalAccessRuleProtectionEnabled, _originalAuditRuleProtectionEnabled;
		#endregion
		
		#region Utility methods
		private void ProcessExtraAces(RawSecurityDescriptor rawSD) {
			// SD is saved internally as a CommonSecurityDescriptor, which can't handle special SACL ACEs like CAP, MIL, and
			// attributes. This method will get those ACEs before they're lost...
			if (rawSD.SystemAcl == null) { return; }

			foreach (GenericAce ace in rawSD.SystemAcl) {
				switch ((int) ace.AceType) {
					case 17:
						_mandatoryIntegrityLabel = new MandatoryIntegrityLabelAce((CustomAce) ace, this, null);
						break;
					
					default:
						break;
				}
			}
		}

		public SecurityInformation GetRequestedSecurityInformation() {
			return _requestedSecurityInformation;
		}

		public SecurityInformation GetModifiedSecurityInformation() {
			return GetModifiedSecurityInformation(false);
		}
	
		public SecurityInformation GetModifiedSecurityInformation(bool forSetSecurityInfo) {
			/*
				Used to tell what parts of a security descriptor have been modified
				
				forSetSecurityInformation is used to ensure (Un)ProtectedDacl and (Un)ProtectedSacl
				flags are always set or not. If it is true, that means the result is mean to be
				used in a call to SetSecurityInfo(), and those flags must always be set if
				Dacl and/or Sacl are set. If it is false, then the method is being used to show
				the user what has been changed on the SD, so those flags might not be needed.
			*/
			SecurityInformation modifiedSections = 0;
			
			if (this._ownerModified) { modifiedSections |= SecurityInformation.Owner; }
			if (this._groupModified) { modifiedSections |= SecurityInformation.Group; }

			// Set one of the DACL protection bits if they were changed or if this is being
			// used for a call to SetSecurityInfo
			if (this._originalAccessRuleProtectionEnabled != this.AreAccessRulesProtected ||
				(this._daclModified && forSetSecurityInfo == true)) {

				if (this.AreAccessRulesProtected == true) {
					modifiedSections |= SecurityInformation.ProtectedDacl;
				}
				else {
					modifiedSections |= SecurityInformation.UnprotectedDacl;
				}
			}
			
			if (this._daclModified ||
				(this._originalAccessRuleProtectionEnabled != this.AreAccessRulesProtected) && forSetSecurityInfo == true) { 

				modifiedSections |= SecurityInformation.Dacl;
			}
			
			if (this._originalAuditRuleProtectionEnabled != this.AreAuditRulesProtected ||
				(this._daclModified && forSetSecurityInfo == true)) {

				if (this.AreAuditRulesProtected == true) {
					modifiedSections |= SecurityInformation.ProtectedSacl;
				}
				else {
					modifiedSections |= SecurityInformation.UnprotectedSacl;
				}
			}

			if (this._saclModified || 
				(this._originalAuditRuleProtectionEnabled != this.AreAuditRulesProtected) && forSetSecurityInfo == true) {
 
				modifiedSections |= SecurityInformation.Sacl;
			}
			
			return modifiedSections;
		}

		private void InsertRawSaclAce(RawSecurityDescriptor rawSD, GenericAce ace, int index) {
			if (rawSD.SystemAcl == null) {
				rawSD.SystemAcl = new RawAcl(this.IsDS ? CommonAcl.AclRevisionDS : CommonAcl.AclRevision, 1);
			}
			
			rawSD.SystemAcl.InsertAce(index, ace);
		}
		private void InsertRawSaclAce(RawSecurityDescriptor rawSD, GenericAce ace) {
			int index;
			if (rawSD.SystemAcl == null) {
				index = 0;
			}
			else {
				index = rawSD.SystemAcl.Count;
			}
			
			InsertRawSaclAce(rawSD, ace, index);
		}
		
		internal RawSecurityDescriptor RawSD {
			// CommonSecurityDescriptor class can't handle CAP/MIL/etc, so it's up to
			// this property to convert the common SD to a raw SD, then make the extra
			// additions
			get { 
				RawSecurityDescriptor rawSD = new RawSecurityDescriptor(this._securityDescriptor.GetSddlForm(AccessControlSections.All));

				// Extra additions that common SD can't handle go here:
				if (this.MandatoryIntegrityLabel != null) {
					InsertRawSaclAce(rawSD, this.MandatoryIntegrityLabel.GetBaseAceObject());
Console.WriteLine("MIL has been added to RawSD; still need a way to get SDDL and binary forms from here that include this entry");
				}

				return rawSD;
			}
		}
		#endregion
/*		
		#region Factories
        public AccessRule AccessRuleFactory(
            PacPrincipal principal,
            int accessMask,
            bool isInherited,
            InheritanceFlags inheritanceFlags,
            PropagationFlags propagationFlags,
            AccessControlType type
		) {
            return new PacAccessRule(
                principal,
                accessMask,
                isInherited,
                inheritanceFlags,
                propagationFlags,
                type
			);
        }
        
        public AuditRule AuditRuleFactory(
            PacPrincipal principal,
            int accessMask,
            bool isInherited,
            InheritanceFlags inheritanceFlags,
            PropagationFlags propagationFlags,
            AuditFlags flags 
		) {
            return new PacAuditRule(
                principal,
                accessMask,
                isInherited,
                inheritanceFlags,
                propagationFlags,
                flags 
			);
        }

		#endregion
*/

		#region Inheritance methods/properties
		internal virtual Guid[] GetInheritanceGuidArray() {
			// GetInheritanceSource needs this. As far as I can tell, non AD objects just need an empty
			// GUID. AdaptedActiveDirectorySecurityDescriptor overrides this and gets an actual GUID.
			return new Guid[] {};
		}

		private InheritArray[] DaclInheritanceArray {
			get {
				return this._daclInheritanceArray ?? 
					( this._daclInheritanceArray = this.GetInheritanceSource(this._securityDescriptor.DiscretionaryAcl));
			}
		}
		private InheritArray[] _daclInheritanceArray;
	
		private InheritArray[] SaclInheritanceArray {
			get {
				return this._saclInheritanceArray ?? 
					( this._saclInheritanceArray = this.GetInheritanceSource(this._securityDescriptor.SystemAcl));
			}
		}
		private InheritArray[] _saclInheritanceArray;

		private InheritArray[] GetInheritanceSource(GenericAcl acl) {
			if (acl == null) { return null; }

			// First, make sure we have a generic rights mapper for the enum type:
			GenericMapping genericMapping;
			try {
				genericMapping = GenericRightsMapper.GetGenericMapping(this.AccessRightType);
			}
			catch {
				return new InheritArray[0];
			}

			// Make sure ObjectType is supported
			switch (this.ObjectType) {
				case ResourceType.FileObject:
				case ResourceType.RegistryKey:
				case ResourceType.RegistryWow6432Key:
				case ResourceType.DSObjectAll:
					break;
					
				default:
					return new InheritArray[0];
			}

			// Make sure sdPath is supported, too
			string sdPath;
			if (this.Path is SecurityDescriptorStringPath) {
				sdPath = ((SecurityDescriptorStringPath) this.Path).Path;
			}
			else if (this.ObjectType == ResourceType.FileObject) {
				// BypassAclCheck must have been passed
				sdPath = this.Path.ToString();
//Console.WriteLine("GetInheritanceSource: FileObject with SafeHandle passed; using {0}", sdPath);
			}
			else {
//				sdPath = sdPath.Replace("HKEY_", "");
				return new InheritArray[0];
			}
			
			byte[] aclBytes = new byte[acl.BinaryLength];
			acl.GetBinaryForm(aclBytes, 0);
			Guid[] guidArray = this.GetInheritanceGuidArray();
			
			InheritArray[] inheritArray = new InheritArray[acl.Count];

			// Buffer to store the results
			int entrySize = Marshal.SizeOf(typeof(InheritArray));
			IntPtr inheritArrayPtr = Marshal.AllocHGlobal(acl.Count * entrySize);

			try {
				SecurityInformation aclType;
				if (acl.GetType().Name == "DiscretionaryAcl") {
					aclType = SecurityInformation.Dacl;
				}
				else {
					aclType = SecurityInformation.Sacl;
				}

				uint exitCode = advapi32.GetInheritanceSource(
					sdPath,
					this.ObjectType,
					aclType,
					this._securityDescriptor.IsContainer,
					ref guidArray,
					(uint) guidArray.Length,
					aclBytes,
					IntPtr.Zero,
					ref genericMapping,
					inheritArrayPtr
				);

				if (exitCode != 0) {
//Console.WriteLine(String.Format("Error getting inheritance source: {0} ({1})", exitCode, this.Path));
					return new InheritArray[0];
				}
				
				try {
					IntPtr currentPtr = (IntPtr) inheritArrayPtr.ToInt64();
					
					for (int i = 0; i < acl.Count; i++) {
						inheritArray[i] = (InheritArray) Marshal.PtrToStructure(currentPtr, typeof(InheritArray));
						currentPtr += entrySize;
					}
				}
				catch { //(Exception e) {
//Console.WriteLine(String.Format("An error occurred while going through inheritArrayPtr: {0}", e.Message));
					return new InheritArray[0];
				}
				finally {
                    // Make sure InheritArray is freed:
                    exitCode = advapi32.FreeInheritedFromArray(
                        inheritArrayPtr, 
                        (ushort) acl.Count, 
                        IntPtr.Zero
                    );

					if (exitCode != 0) {
//Console.WriteLine("Error calling FreeInheritedFromArray: {0}", exitCode);
					}
				}
			}
			catch { //(Exception e) {
//Console.WriteLine("Exception: {0}", e.Message);
//Console.WriteLine("Error allocating memory for inheritArrayPtr or during call to GetInheritanceSource");
				return new InheritArray[0];
			}
			finally {
				Marshal.FreeHGlobal(inheritArrayPtr);
			}

			return inheritArray;
		}
		#endregion

		public ResourceType ObjectType { 
			get { return _pathInfo.ObjectType; }
		}
		
		public virtual Type AccessRuleType {
			get { return typeof(PacAccessRule); }
		}
		
		public virtual Type AuditRuleType {
			get { return typeof(PacAuditRule); }
		}
		
		public Type AccessRightType { 
			get {
				return _pathInfo.AccessRightType ??
					typeof(int);
			}

			set {
				if (value.IsDefined(typeof(FlagsAttribute), false)) {
					_pathInfo.AccessRightType = value;
				}
			} 
		}

		internal virtual PacPrincipal GetPrincipal(SecurityIdentifier sid) {
			/*
				ACEs store SIDs. Those SIDs may be able to be translated with a simple SecurityIdentifier.Translate()
				call to convert them to an NTAccount, but sometimes that doesn't work, i.e., when the account is a local
				account on another computer. There are also a few well known SIDs that this won't work for. For that
				reason, the module uses Win32 API calls to do SID <--> name translations, and those support remote
				machines. 
				
				The purpose of this method is to convert a SID into a PacPrincipal, even if the account requires remote
				translation. It can be overridden for sub classes (the AD security descriptor class overrides it so that
				it can perform the lookup on a domain controller for a few BUILTIN accounts that can't be translated
				on client computers)
			*/

			if (sid == null) {
				return null;
			}
			
			return PacPrincipal.FromSid(this.ComputerName, sid);  // null computer names are OK (will do local translation)
		}	


		#region Get ACE methods
		public List<AdaptedCommonAce> MergeRules(List<AdaptedCommonAce> unmergedRules, bool groupByAccessMask) {
		/*
		Function takes a list of AdaptedCommonAce objects and groups them. groupByAccessMask, when true, means
		that the AccessMaskDisplay (whatever options were passed to it) is used along with the common grouping
		key items. If groupByAccessMask is false, the inheritance/propagation flags are used instead of the
		access mask.

		Method should be called twice, once to group by access mask, and those results should be used to group
		by inheritance flags.
		*/
			OrderedDictionary groupedAces = new OrderedDictionary();
			List<AdaptedCommonAce> mergedRules = new List<AdaptedCommonAce>();
			
			string key;
			
			foreach (AdaptedCommonAce currentRule in unmergedRules) {
				key = currentRule.GetGroupingKey(groupByAccessMask);
				if (!groupedAces.Contains(key)) {
					groupedAces.Add(key, new List<AdaptedCommonAce>());
				}

				((List<AdaptedCommonAce>) groupedAces[key]).Add(currentRule);
			}

			foreach (DictionaryEntry mergedRuleList in groupedAces) {
				List<AdaptedCommonAce> group = (List<AdaptedCommonAce>) mergedRuleList.Value;
						
				if (group.Count == 1) {
					// Single ACE; just add it to list
					mergedRules.Add(group[0]);
				}
				else {
					// Multiple ACEs. If they were grouped, assume they are combinable and OR the access mask and appliesto
					// together
					int newAccessMask = 0;
					AppliesTo newAppliesTo = 0;
					foreach (AdaptedCommonAce ace in group) {
						newAccessMask |= ace.AccessMask.AccessMask;
						newAppliesTo |= ace.AppliesTo.AppliesToEnum;
					}
					
					mergedRules.Add(group[0].CreateNewMergedAce(newAccessMask, newAppliesTo));
				}
			}
			
			return mergedRules;
		}

		public AdaptedCommonAce[] GetAccessRules(bool includeExplicit, bool includeInherited, Type targetType) {
			return GetAccessRules(includeExplicit, includeInherited, targetType, 0, null);
		}
		
		public AdaptedCommonAce[] GetAccessRules(bool includeExplicit, bool includeInherited, Type targetType, GetAceDisplayOptions displayOptions, AdaptedAceFilter[] aceFilters) {
			return GetRules(true, includeExplicit, includeInherited, targetType, displayOptions, aceFilters, null);
		}

		public AdaptedCommonAce[] GetAccessRules(bool includeExplicit, bool includeInherited, Type targetType, GetAceDisplayOptions displayOptions, AdaptedAceFilter[] aceFilters, bool? specificFilter) {
			return GetRules(true, includeExplicit, includeInherited, targetType, displayOptions, aceFilters, specificFilter);
		}

		public AdaptedCommonAce[] GetAuditRules(bool includeExplicit, bool includeInherited, Type targetType) {
			return GetAuditRules(includeExplicit, includeInherited, targetType, 0, null);
		}
		
		public AdaptedCommonAce[] GetAuditRules(bool includeExplicit, bool includeInherited, Type targetType, GetAceDisplayOptions displayOptions, AdaptedAceFilter[] aceFilters) {
			return GetRules(false, includeExplicit, includeInherited, targetType, displayOptions, aceFilters, null);
		}

		public AdaptedCommonAce[] GetAuditRules(bool includeExplicit, bool includeInherited, Type targetType, GetAceDisplayOptions displayOptions, AdaptedAceFilter[] aceFilters, bool? specificFilter) {
			return GetRules(false, includeExplicit, includeInherited, targetType, displayOptions, aceFilters, specificFilter);
		}

		private AdaptedCommonAce[] GetRules(bool isDacl, bool includeExplicit, bool includeInherited, Type targetType, GetAceDisplayOptions displayOptions, AdaptedAceFilter[] aceFilters, bool? specificFilter) {
			
			List<AdaptedCommonAce> ruleCollection = new List<AdaptedCommonAce>();
			
			CommonAcl acl = null;
			string inheritedFrom;

			InheritArray[] inheritanceArray = null;
			if (isDacl) {
				if (this._securityDescriptor.GetSddlForm(AccessControlSections.Access) != String.Empty) {
					// CommonSD is trying to show that a null DACL gives everyone full control; this module
					// doesn't do that
					acl = this._securityDescriptor.DiscretionaryAcl;
					inheritanceArray = this.DaclInheritanceArray;
				}
			}
			else {
				acl = this._securityDescriptor.SystemAcl;
				inheritanceArray = this.SaclInheritanceArray;
			}
			
			if (acl == null) {
				return ruleCollection.ToArray();
			}

			for (int i = 0; i < acl.Count; i++) {
				QualifiedAce ace = acl[i] as QualifiedAce;
				
				if (( !includeExplicit  && ( ace.AceFlags & AceFlags.Inherited ) == 0) ||
					( !includeInherited && ( ace.AceFlags & AceFlags.Inherited ) != 0)) {
					
					// This ace doesn't match inheritance filtering, so skip it
					continue;
				}
				
				if (inheritanceArray == null || inheritanceArray.Length == 0) {
					inheritedFrom = null;
				}
				else {
					inheritedFrom = inheritanceArray[i].AncestorName;
				}
				
				if (!string.IsNullOrEmpty(inheritedFrom)) {
					inheritedFrom = ROE.ThirdParty.Microsoft.Experimental.IO.LongPathCommon.RemoveLongPathPrefix(inheritedFrom);
				}

				if (ace is CommonAce) {
					ruleCollection.Add(new AdaptedCommonAce((CommonAce) ace, this, inheritedFrom, displayOptions));
				}
				else if (ace is ObjectAce) {
					ruleCollection.Add(new AdaptedActiveDirectoryAce((ObjectAce) ace, this, inheritedFrom, displayOptions));
				}
				else {
					// This shouldn't happen
					throw new Exception("GetRules(): Unknown ACE type??");
				}
			}

			if ((displayOptions & GetAceDisplayOptions.DontMergeAces) == 0) {
				ruleCollection = MergeRules(ruleCollection, true);    // Merge; group by access mask
				ruleCollection = MergeRules(ruleCollection, false);   // Merge; group by AppliesTo
			}

			ruleCollection = FilterRules(ruleCollection, aceFilters, specificFilter);
			
			return ruleCollection.ToArray();
		}
		
		private List<AdaptedCommonAce> FilterRules(List<AdaptedCommonAce> ruleCollection, AdaptedAceFilter[] aceFilters, bool? specificFilter) {
			// Unfortunately this does the filtering after AdaptedCommonAces have been created. There are some checks that
			// could be done to the QualifiedAce in the GetRules() method, e.g., AppliesTo, AccessMask, SID (if name resolution
			// were to be moved there and the resolution was cached when CommonAce is created).
			//
			// Moving there would mean filtering on unmerged ACEs only (which will happen if the user requests it). Also, generic
			// rights would need to be translated (and I'm sure there's more).
			//
			// For now, filtering happens after ruleCollection has been created. Will need to so some performance tests to see
			// if this adds too much overhead (it should still be faster than where-object from the shell).
			List<AdaptedCommonAce> filteredCollection = new List<AdaptedCommonAce>();

			foreach (AdaptedCommonAce ace in ruleCollection) {
				if (TestAceFilters(aceFilters, ace, specificFilter)) {
					filteredCollection.Add(ace);
				}
			}
			
			return filteredCollection;
		}
		
		private bool TestAceFilters(AdaptedAceFilter[] aceFilters, AdaptedCommonAce ace, bool? specificFilter) {
			if (aceFilters == null) { return true; }

			foreach (AdaptedAceFilter currentFilter in aceFilters) {
				if (!currentFilter.Match(ace, specificFilter)) {
					return false;
				}
			}
			
			return true;
		}

		#endregion
		
		#region Properties
		private bool _computerNameCheckComplete = false;
		private string _computerName;

		public string ComputerName {
			get {
				if (_computerNameCheckComplete == false) {
					_computerName = GetComputerNameFromSdPath();
				}
				
				return _computerName;
			}
		}
		
		private string GetComputerNameFromSdPath() {
			/*
				Over time, the types of checks performed here will probably be increased.
				
				For now, WSMan paths and paths of the form \\<computername>\<rest of path> will cause a non-null
				_computerName field.
			*/

			if (this.Path == null) { return null; }

			string path = null, returnString = null;
			
			switch (this.ObjectType) {
				case ResourceType.ProviderDefined:
					// WMI namespace or WSMAN object. In this case, we want the true Path, not the ToString() friendly path
					if (this.Path is SecurityDescriptorStringPath) {
						path = ((SecurityDescriptorStringPath) this.Path).Path;
					}

					break;
					
				default:
					// Most of the time the friendly ToString() version is fine (and it's easy b/c there's no type checking
					// necessary
					path = this.Path.ToString();
					break;
			}

			
			Match regexMatch = Regex.Match(path, @"^(\\\\|Microsoft\.WSMan\.Management\\WSMan::)(?<ComputerName>[^\\]+)\\");
			if (regexMatch.Success == true) {
				returnString = regexMatch.Groups["ComputerName"].Value;
			}
			else {
				returnString = null;
			}
			
			_computerNameCheckComplete = true;
			
			return returnString;
		}

		public PacPrincipal Owner {
			get { return GetPrincipal(this._securityDescriptor.Owner); }
		}

		public PacPrincipal Group {
			get { return GetPrincipal(this._securityDescriptor.Group); }
		}

		public SecurityDescriptorPath Path { 
			get {
				return _pathInfo.SdPath ?? 
					new SecurityDescriptorStringPath("<UNKNOWN>");
			}
			set { 
				if (_pathInfo != null) {
					_pathInfo.SdPath = value; 
				}
			}
		}
		
		public bool IsDS {
			get { return this._securityDescriptor.IsDS; }
		}

		public bool IsContainer {
			get { return this._securityDescriptor.IsContainer; }
		}

		private MandatoryIntegrityLabelAce _mandatoryIntegrityLabel;
		public MandatoryIntegrityLabelAce MandatoryIntegrityLabel {
			get {
				return _mandatoryIntegrityLabel;
			}
			set {
				_mandatoryIntegrityLabel = value;
				_labelModified = true;
			}
		}

		public bool? AreAccessRulesProtected {
			get {
				// Return null if DACL isn't present
				if (this._securityDescriptor.DiscretionaryAcl == null && ((this._requestedSecurityInformation & SecurityInformation.Dacl) == 0))
					return null;
				else
					return (this._securityDescriptor.ControlFlags & ControlFlags.DiscretionaryAclProtected) == ControlFlags.DiscretionaryAclProtected;
			}
		}

		public bool? AreAccessRulesCanonical {
			get { 
				// Return null if DACL isn't present
				if (this._securityDescriptor.DiscretionaryAcl == null && ((this._requestedSecurityInformation & SecurityInformation.Dacl) == 0))
					return null;
				else
					return this._securityDescriptor.IsDiscretionaryAclCanonical; 
			}
		}

		public bool? AreAuditRulesProtected {
			get {
				// Return null if SACL isn't present
				if (this._securityDescriptor.SystemAcl == null && ((this._requestedSecurityInformation & SecurityInformation.Sacl) == 0))
					return null;
				else
					return (this._securityDescriptor.ControlFlags & ControlFlags.SystemAclProtected) != ControlFlags.None;
			}
		}

		public bool? AreAuditRulesCanonical {
			get {
				// Return null if SACL isn't present
				if (this._securityDescriptor.SystemAcl == null && ((this._requestedSecurityInformation & SecurityInformation.Sacl) == 0))
					return null;
				else
					return this._securityDescriptor.IsSystemAclCanonical;
			}
		}
		#endregion

		public IdentityReference GetOwner(Type targetType) {
			if (this._securityDescriptor.Owner == (SecurityIdentifier) null) {
				return (IdentityReference) null;
			}
			else {
				return this._securityDescriptor.Owner.Translate(targetType);
			}            
		}

		public IdentityReference GetGroup(Type targetType) {
			if (this._securityDescriptor.Group == (SecurityIdentifier) null) {
				return (IdentityReference) null;
			}
			else {
				return _securityDescriptor.Group.Translate(targetType);
			}            
		}

		public void SetOwner(PacPrincipal principal) {
			if (principal == null) {
                throw new ArgumentNullException("principal");
            }

			SetOwner(principal.SecurityIdentifier);
		}

		public void SetOwner(IdentityReference identity) {
			if (identity == null) {
                throw new ArgumentNullException("identity");
            }

			this._securityDescriptor.Owner = (SecurityIdentifier) identity.Translate(typeof(SecurityIdentifier));
			this._ownerModified = true;
		}

		public void SetGroup(PacPrincipal principal) {
			if (principal == null) {
                throw new ArgumentNullException("principal");
            }
			
			SetGroup(principal.SecurityIdentifier);
		}

		public void SetGroup(IdentityReference identity) {
			if (identity == null) {
                throw new ArgumentNullException("identity");
            }
			
			this._securityDescriptor.Group = (SecurityIdentifier) identity.Translate(typeof(SecurityIdentifier));
			this._groupModified = true;
		}

		public void SetAccessRuleProtection(bool isProtected, bool preserveInheritance) {
			if (this.AreAccessRulesProtected == null) { return; }
		
			if (this.AreAccessRulesProtected != isProtected) {
				this._securityDescriptor.SetDiscretionaryAclProtection(isProtected, preserveInheritance);
//				this._daclModified = true;
			}
		}

		public void SetAuditRuleProtection(bool isProtected, bool preserveInheritance) {
			if (this.AreAuditRulesProtected == null) { return; }

			if (this.AreAuditRulesProtected != isProtected) {
				this._securityDescriptor.SetSystemAclProtection(isProtected, preserveInheritance);
//				this._saclModified = true;
			}
		}

		internal int GetAdjustedAccessMask(PacAccessRule rule, AccessControlType type) {
			/*
				Some objects have certain rights that are required that the ACL editor handles behind the scenes for you. The most obvious example
				is doing anything with a file or folder requires the Synchronize right, yet you never see it in the ACL editor. Behind the scenes,
				that right is always added to an AccessAllowed ACE, and always removed from an AccessDenied ACE.
				
				This method looks at the current rights enumeration and makes any object-specific modifications to the access mask. 
			*/
			
			int returnMask = rule.Rights.AccessMask;
			if (this.AccessRightType == typeof(FileSystemRights)) {
				if (type == AccessControlType.Allow) {
					returnMask |= (int) FileSystemRights.Synchronize;
				}
				else if (type == AccessControlType.Deny) {
					if (rule.Rights.AccessMask != (int) FileSystemRights.FullControl &&
                        rule.Rights.AccessMask != (int) (FileSystemRights.FullControl & ~FileSystemRights.DeleteSubdirectoriesAndFiles)) {
						returnMask &= (int) ~FileSystemRights.Synchronize;
					}
				}
			}
			
			return returnMask;
		}

		internal bool DoesExplicitAccessExist(PacAccessRule rule, int accessMask, AdaptedCommonAce[] acl) {
			/*
				This method is used in conjunction with GetAdjustedAccessMask() during an access removal operation. Why is this needed? Let's look at
				the file/folder example:
				
				Synchronize access is required to do anything, so it is being added behind the scenes on any Allow ACEs (GetAdjustedAccessMask()) does
				that. So, let's say someone adds 'Read' access. 'Synchronize' gets added, too. What happens when they try to remove 'Read' access? You
				can't automatically remove 'Synchronize' because maybe 'Modify' access is currently granted. If you remove 'Synchronize', you'll make
				whatever permissions are left worthless.
				
				This method provides a way to check to see if specific access is granted, so in the previous scenario it would check to see if 'Read, Synchronize'
				explicit access exists, and if it does, the remove operation will know to remove 'Synchronize' as well. If that exact access isn't granted
				in an Access collection, then the remove operation won't add 'Synchronize'. See the ModifyAccessRule() method for more information.
			*/
			foreach (AdaptedCommonAce ace in acl) {
				if (ace.IsInherited == false &&
					ace.AceType == rule.AccessControlType.ToString() &&
					ace.AccessMask.AccessMask == accessMask && 
				    ace.Principal.SecurityIdentifier == rule.Principal.SecurityIdentifier
				) { return true; }
			}
			
			return false;
		}

		internal static int AccessControlModificationValidRemoveOperations = (int) ( AccessControlModification.Remove | 
																			  AccessControlModification.RemoveAll | 
																			  AccessControlModification.RemoveSpecific );
	    internal static int AdObjectAceRights = (int) ( Enums.ActiveDirectoryRights.ExtendedRight |
														Enums.ActiveDirectoryRights.ValidatedWrite |
														Enums.ActiveDirectoryRights.ReadProperty |
														Enums.ActiveDirectoryRights.WriteProperty |
														Enums.ActiveDirectoryRights.CreateChild |
														Enums.ActiveDirectoryRights.DeleteChild );
																				
        public bool ModifyRule(AccessControlModification modification, PacAuthorizationRule rule, out bool modified, bool force) {

            if (rule == null) {
                throw new ArgumentNullException("rule");
            }

			if (this._securityDescriptor.IsDS && 
				((int) modification & AccessControlModificationValidRemoveOperations) != 0 &&
				(rule.Rights.AccessMask & AdObjectAceRights) != 0 &&
				rule.Rights.AccessMask != (int) Enums.ActiveDirectoryRights.FullControl &&
				force != true ) {

				// This check makes sure you can't remove extended right, validated write, create/delete child, or read/write property
				// access with a common ACE (unless you're removing full control). Why? Because removing access this way may remove
				// more than the user wants, e.g., removing ReadProperty rights w/ CommonAce would remove the ability to read ALL properties
				// for the principal. If the user want's that, they'll have to create an object ACE w/ empty GUID for ObjectAceType
				throw new Exception("Can't remove Extended Right, Validated Write, Create/Delete Child Object, Read/Write Property or PropertySet without usuing force parameter");
			}

			bool result = true;
			bool emptyAclCreated = false;

			// Figure out if this is a DACL or SACL ACE:
			bool isDaclAce = false, isObjectAce = false;
			if (rule is PacAccessRule) {
				isDaclAce = true;
				if (rule is PacObjectAccessRule) {
					isObjectAce = true;
				}
			}
			else if (rule is PacAuditRule) {
				if (rule is PacObjectAuditRule) {
					isObjectAce = true;
				}
			}
			else {
				throw new Exception(string.Format("Unknown ACE type: {0}", rule.GetType().Name));
			}

			bool aclIsPresent, aclWasRequested;
			if (isDaclAce) {
				aclIsPresent = this._securityDescriptor.DiscretionaryAcl != null;

				if (aclIsPresent && this._securityDescriptor.DiscretionaryAcl.Count == 1 && 
						 this._securityDescriptor.GetSddlForm(AccessControlSections.Access) == String.Empty
				) {
					// CommonSD is trying to show that a null DACL gives everyone full control; this module
					// doesn't do that
					aclIsPresent = false;
				}

				aclWasRequested = (this.GetRequestedSecurityInformation() & SecurityInformation.Dacl) != 0;
			}
			else {
				aclIsPresent = this._securityDescriptor.SystemAcl != null;
				aclWasRequested = (this.GetRequestedSecurityInformation() & SecurityInformation.Sacl) != 0;
			}
			if ( !aclIsPresent ) {
				if ( ((int) modification & AccessControlModificationValidRemoveOperations) != 0) {
					// ACL is null, but we were going to remove access, so no issue
					modified = false;
					return result;
				}

				if (force == false && !aclWasRequested) {
					StringBuilder errorMessage = new StringBuilder();
					errorMessage.Append("Security descriptor does not contain a ");
					if (isDaclAce) {
						errorMessage.Append("DACL");
					}
					else {
						errorMessage.Append("SACL");
					}
					errorMessage.Append(" (use the force parameter to continue anyway)");
					
					throw new Exception(errorMessage.ToString());
				}

				emptyAclCreated = true;
				OverwriteAcl(isDaclAce, new RawAcl(this._securityDescriptor.IsDS ? CommonAcl.AclRevisionDS : CommonAcl.AclRevision, 0));
Console.WriteLine("Creating ACL...");
			}

			dynamic dynRule = rule;
			InheritanceFlags inheritanceFlags = rule.InheritanceFlags;
			PropagationFlags propagationFlags = rule.PropagationFlags;
			
			if (!this._securityDescriptor.IsContainer) {
				// If SD isn't a container, remove any flags (otherwise you'd get an error
				// if you were modifying a file's SD with ACEs created by using -FolderRights
				// parameter.
				//
				// NOTE: These variables are only used during add/set operations since remove operations
				//       can take flags just fine. This will be cleaned up next time the code is refactored
				inheritanceFlags = InheritanceFlags.None;
				propagationFlags = PropagationFlags.None;
			}
			
			try {
				switch (modification) {
					case AccessControlModification.Add:
						if (isDaclAce) {
							if (!isObjectAce) {
								this._securityDescriptor.DiscretionaryAcl.AddAccess(dynRule.AccessControlType, rule.Principal.SecurityIdentifier, GetAdjustedAccessMask((PacAccessRule) rule, dynRule.AccessControlType), inheritanceFlags, propagationFlags);
							}
							else {
								this._securityDescriptor.DiscretionaryAcl.AddAccess(dynRule.AccessControlType, rule.Principal.SecurityIdentifier,  GetAdjustedAccessMask((PacAccessRule) rule, dynRule.AccessControlType), rule.InheritanceFlags, rule.PropagationFlags, dynRule.ObjectFlags, dynRule.ObjectType, dynRule.InheritedObjectType);
							}
						}
						else {
							if (!isObjectAce) {
								this._securityDescriptor.SystemAcl.AddAudit(dynRule.AuditFlags, rule.Principal.SecurityIdentifier,  rule.Rights.AccessMask, inheritanceFlags, propagationFlags);
							}
							else {
								this._securityDescriptor.SystemAcl.AddAudit(dynRule.AuditFlags, rule.Principal.SecurityIdentifier,  rule.Rights.AccessMask, rule.InheritanceFlags, rule.PropagationFlags, dynRule.ObjectFlags, dynRule.ObjectType, dynRule.InheritedObjectType);
							}
						}
						break;

					case AccessControlModification.Set:
						if (isDaclAce) {
							if (!isObjectAce) {
								this._securityDescriptor.DiscretionaryAcl.SetAccess(dynRule.AccessControlType, rule.Principal.SecurityIdentifier, GetAdjustedAccessMask((PacAccessRule) rule, dynRule.AccessControlType), inheritanceFlags, propagationFlags);
							}
							else {
								this._securityDescriptor.DiscretionaryAcl.SetAccess(dynRule.AccessControlType, rule.Principal.SecurityIdentifier,  GetAdjustedAccessMask((PacAccessRule) rule, dynRule.AccessControlType), rule.InheritanceFlags, rule.PropagationFlags, dynRule.ObjectFlags, dynRule.ObjectType, dynRule.InheritedObjectType);
							}
						}
						else {
							if (!isObjectAce) {
								this._securityDescriptor.SystemAcl.SetAudit(dynRule.AuditFlags, rule.Principal.SecurityIdentifier,  rule.Rights.AccessMask, inheritanceFlags, propagationFlags);
							}
							else {
								this._securityDescriptor.SystemAcl.SetAudit(dynRule.AuditFlags, rule.Principal.SecurityIdentifier,  rule.Rights.AccessMask, rule.InheritanceFlags, rule.PropagationFlags, dynRule.ObjectFlags, dynRule.ObjectType, dynRule.InheritedObjectType);
							}
						}
						break;

					case AccessControlModification.Reset:
						if (isDaclAce) {
							AccessControlType oppositeType;
							if (dynRule.AccessControlType == AccessControlType.Allow) {
								oppositeType = AccessControlType.Deny;
							}
							else {
								oppositeType = AccessControlType.Allow;
							}

							if (!isObjectAce) {
								this._securityDescriptor.DiscretionaryAcl.RemoveAccess(oppositeType, rule.Principal.SecurityIdentifier, -1, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None);
								this._securityDescriptor.DiscretionaryAcl.SetAccess(dynRule.AccessControlType, rule.Principal.SecurityIdentifier, GetAdjustedAccessMask((PacAccessRule) rule, dynRule.AccessControlType), inheritanceFlags, propagationFlags);
							}
							else {
								this._securityDescriptor.DiscretionaryAcl.RemoveAccess(oppositeType, rule.Principal.SecurityIdentifier,  -1, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, dynRule.ObjectFlags, dynRule.ObjectType, dynRule.InheritedObjectType);
								this._securityDescriptor.DiscretionaryAcl.SetAccess(dynRule.AccessControlType, rule.Principal.SecurityIdentifier,  rule.Rights.AccessMask, rule.InheritanceFlags, rule.PropagationFlags, dynRule.ObjectFlags, dynRule.ObjectType, dynRule.InheritedObjectType);
							}
						}
						else {
							if (!isObjectAce) {
								this._securityDescriptor.SystemAcl.SetAudit(dynRule.AuditFlags, rule.Principal.SecurityIdentifier,  rule.Rights.AccessMask, inheritanceFlags, propagationFlags);
							}
							else {
								this._securityDescriptor.SystemAcl.SetAudit(dynRule.AuditFlags, rule.Principal.SecurityIdentifier,  rule.Rights.AccessMask, rule.InheritanceFlags, rule.PropagationFlags, dynRule.ObjectFlags, dynRule.ObjectType, dynRule.InheritedObjectType);
							}
						}
						break;

					case AccessControlModification.Remove:
						if (isDaclAce) {
							int finalAccessMask = rule.Rights.AccessMask;
							if (rule.Rights.AccessMask != GetAdjustedAccessMask((PacAccessRule) rule, dynRule.AccessControlType)) {
								// GetAdjustedAccessMask can modify this, so one more check required to figure out what access we really want to remove
								if (DoesExplicitAccessExist((PacAccessRule) rule, GetAdjustedAccessMask((PacAccessRule) rule, dynRule.AccessControlType), this.GetAccessRules(true, true, typeof(IdentityReference)))) {
									finalAccessMask = GetAdjustedAccessMask((PacAccessRule) rule, dynRule.AccessControlType);
								}
							}
						
							if (!isObjectAce) {
								result = this._securityDescriptor.DiscretionaryAcl.RemoveAccess(dynRule.AccessControlType, rule.Principal.SecurityIdentifier,  finalAccessMask, rule.InheritanceFlags, rule.PropagationFlags);
							}
							else {
								result = this._securityDescriptor.DiscretionaryAcl.RemoveAccess(dynRule.AccessControlType, rule.Principal.SecurityIdentifier,  finalAccessMask, rule.InheritanceFlags, rule.PropagationFlags, dynRule.ObjectFlags, dynRule.ObjectType, dynRule.InheritedObjectType);
							}
						}
						else {
							if (!isObjectAce) {
								result = this._securityDescriptor.SystemAcl.RemoveAudit(dynRule.AuditFlags, rule.Principal.SecurityIdentifier,  rule.Rights.AccessMask, rule.InheritanceFlags, rule.PropagationFlags);
							}
							else {
								result = this._securityDescriptor.SystemAcl.RemoveAudit(dynRule.AuditFlags, rule.Principal.SecurityIdentifier,  rule.Rights.AccessMask, rule.InheritanceFlags, rule.PropagationFlags, dynRule.ObjectFlags, dynRule.ObjectType, dynRule.InheritedObjectType);
							}
						}

						break;

					case AccessControlModification.RemoveAll:
						if (isDaclAce) {
							if (!isObjectAce) {
								result = this._securityDescriptor.DiscretionaryAcl.RemoveAccess(dynRule.AccessControlType, rule.Principal.SecurityIdentifier,  -1, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None);
							}
							else {
								result = this._securityDescriptor.DiscretionaryAcl.RemoveAccess(dynRule.AccessControlType, rule.Principal.SecurityIdentifier,  -1, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, dynRule.ObjectFlags, dynRule.ObjectType, dynRule.InheritedObjectType);
							}
						}
						else {
							if (!isObjectAce) {
								result = this._securityDescriptor.SystemAcl.RemoveAudit(AuditFlags.Failure | AuditFlags.Success, rule.Principal.SecurityIdentifier,  -1, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None);
							}
							else {
								result = this._securityDescriptor.SystemAcl.RemoveAudit(AuditFlags.Failure | AuditFlags.Success, rule.Principal.SecurityIdentifier,  -1, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, dynRule.ObjectFlags, dynRule.ObjectType, dynRule.InheritedObjectType);
							}
						}
						
						if (result == false) {
							throw new SystemException();
						}

						break;

					case AccessControlModification.RemoveSpecific:
						if (isDaclAce) {
							int finalAccessMask = rule.Rights.AccessMask;
							if (rule.Rights.AccessMask != GetAdjustedAccessMask((PacAccessRule) rule, dynRule.AccessControlType)) {
								// GetAdjustedAccessMask can modify this, so one more check required to figure out what access we really want to remove
								if (DoesExplicitAccessExist((PacAccessRule) rule, GetAdjustedAccessMask((PacAccessRule) rule, dynRule.AccessControlType), this.GetAccessRules(true, true, typeof(IdentityReference)))) {
									finalAccessMask = GetAdjustedAccessMask((PacAccessRule) rule, dynRule.AccessControlType);
								}
							}

							if (!isObjectAce) {
								this._securityDescriptor.DiscretionaryAcl.RemoveAccessSpecific(dynRule.AccessControlType, rule.Principal.SecurityIdentifier,  finalAccessMask, rule.InheritanceFlags, rule.PropagationFlags);
							}
							else {
								this._securityDescriptor.DiscretionaryAcl.RemoveAccessSpecific(dynRule.AccessControlType, rule.Principal.SecurityIdentifier,  finalAccessMask, rule.InheritanceFlags, rule.PropagationFlags, dynRule.ObjectFlags, dynRule.ObjectType, dynRule.InheritedObjectType);
							}
						}
						else {
							if (!isObjectAce) {
								this._securityDescriptor.SystemAcl.RemoveAuditSpecific(dynRule.AuditFlags, rule.Principal.SecurityIdentifier,  rule.Rights.AccessMask, rule.InheritanceFlags, rule.PropagationFlags);
							}
							else {
								this._securityDescriptor.SystemAcl.RemoveAuditSpecific(dynRule.AuditFlags, rule.Principal.SecurityIdentifier,  rule.Rights.AccessMask, rule.InheritanceFlags, rule.PropagationFlags, dynRule.ObjectFlags, dynRule.ObjectType, dynRule.InheritedObjectType);
							}
						}

						break;

					default :
						throw new ArgumentOutOfRangeException("modification");
				}
			}
			catch (Exception e) {
//Console.WriteLine("Error in ModifyAccess: {0}", e.Message);
				if (emptyAclCreated) {
					if (isDaclAce) {
						this._securityDescriptor.DiscretionaryAcl = null;
					}
					else {
						this._securityDescriptor.SystemAcl = null;
					}
				}
			}

			modified = result;
			if (isDaclAce) {
				this._daclModified |= modified;
				this._daclInheritanceArray = null;

				if (emptyAclCreated) {
					_requestedSecurityInformation |= SecurityInformation.Dacl;
				}
			}
			else {
				this._saclModified |= modified;
				this._saclInheritanceArray = null;

				if (emptyAclCreated) {
					_requestedSecurityInformation |= SecurityInformation.Sacl;
				}
			}
			return result;
        }



		#region DACL Modification
		public bool ModifyAccessRule(AccessControlModification modification, PacAccessRule rule, out bool modified) {
			return ModifyRule(modification, rule, out modified, false);
		}

		public bool ModifyAccessRule(AccessControlModification modification, PacAccessRule rule, out bool modified, bool force) {
			return ModifyRule(modification, rule, out modified, force);
		}

        public void AddAccessRule(PacAccessRule rule) {
            if (rule == null) {
                throw new ArgumentNullException("rule");
            }

			bool modified;
			this.ModifyAccessRule(AccessControlModification.Add, rule, out modified);
        }

        public void AddAccessRule(PacObjectAccessRule rule) {
            if (rule == null) {
                throw new ArgumentNullException("rule");
            }

			bool modified;
			this.ModifyAccessRule(AccessControlModification.Add, rule, out modified);
        }
 
        public void SetAccessRule(PacAccessRule rule) {
            if (rule == null) {
                throw new ArgumentNullException("rule");
            }

			bool modified;
			ModifyAccessRule(AccessControlModification.Set, rule, out modified);
        }

        public void SetAccessRule(PacObjectAccessRule rule) {
            if (rule == null) {
                throw new ArgumentNullException("rule");
            }

			bool modified;
			ModifyAccessRule(AccessControlModification.Set, rule, out modified);
        }
 
        public void ResetAccessRule(PacAccessRule rule) {
            if (rule == null) {
                throw new ArgumentNullException("rule");
            }

			bool modified;
			ModifyAccessRule(AccessControlModification.Reset, rule, out modified);
        }

        public void ResetAccessRule(PacObjectAccessRule rule) {
            if (rule == null) {
                throw new ArgumentNullException("rule");
            }

			bool modified;
			ModifyAccessRule(AccessControlModification.Reset, rule, out modified);
        }
 
        public bool RemoveAccessRule(PacAccessRule rule) {
            if (rule == null) {
                throw new ArgumentNullException("rule");
            }

			bool modified;
			return ModifyAccessRule(AccessControlModification.Remove, rule, out modified);
        }
 
        public bool RemoveAccessRule(PacObjectAccessRule rule) {
            if (rule == null) {
                throw new ArgumentNullException("rule");
            }

			bool modified;
			return ModifyAccessRule(AccessControlModification.Remove, rule, out modified);
        }

        public void RemoveAccessRuleAll(PacAccessRule rule) {
            if ( rule == null ) {
                throw new ArgumentNullException("rule");
            }

			bool modified;
			ModifyAccessRule( AccessControlModification.RemoveAll, rule, out modified );
        }
 
        public void RemoveAccessRuleAll(PacObjectAccessRule rule) {
            if ( rule == null ) {
                throw new ArgumentNullException("rule");
            }

			bool modified;
			ModifyAccessRule( AccessControlModification.RemoveAll, rule, out modified );
        }

        public void RemoveAccessRuleSpecific(PacAccessRule rule) {
            if (rule == null) {
                throw new ArgumentNullException("rule");
            }

			bool modified;
			ModifyAccessRule(AccessControlModification.RemoveSpecific, rule, out modified);
        }

        public void RemoveAccessRuleSpecific(PacObjectAccessRule rule) {
            if (rule == null) {
                throw new ArgumentNullException("rule");
            }

			bool modified;
			ModifyAccessRule(AccessControlModification.RemoveSpecific, rule, out modified);
        }

		public void PurgeAccessRules(PacPrincipal principal) {
			this._securityDescriptor.PurgeAccessControl(principal.SecurityIdentifier);
			this._daclModified = true;
		}
 		#endregion

		#region SACL Modification
        public bool ModifyAuditRule(AccessControlModification modification, PacAuditRule rule, out bool modified) {
			return ModifyRule(modification, rule, out modified, false);
		}
 
        public bool ModifyAuditRule(AccessControlModification modification, PacAuditRule rule, out bool modified, bool force) {
			return ModifyRule(modification, rule, out modified, force);
		}

        public void AddAuditRule(PacAuditRule rule) {
            if (rule == null) {
                throw new ArgumentNullException("rule");
            }

			bool modified;
			ModifyAuditRule(AccessControlModification.Add, rule, out modified);
        }

        public void AddAuditRule(PacObjectAuditRule rule) {
            if (rule == null) {
                throw new ArgumentNullException("rule");
            }

			bool modified;
			ModifyAuditRule(AccessControlModification.Add, rule, out modified);
        }
 
        public void SetAuditRule(PacAuditRule rule) {
            if (rule == null) {
                throw new ArgumentNullException("rule");
            }

			bool modified;
			ModifyAuditRule(AccessControlModification.Set, rule, out modified);
        }
 
        public void SetAuditRule(PacObjectAuditRule rule) {
            if (rule == null) {
                throw new ArgumentNullException("rule");
            }

			bool modified;
			ModifyAuditRule(AccessControlModification.Set, rule, out modified);
        }

        public bool RemoveAuditRule(PacAuditRule rule) {
            if (rule == null) {
                throw new ArgumentNullException("rule");
            }

			bool modified;
			return ModifyAuditRule(AccessControlModification.Remove, rule, out modified);
        }
 
        public bool RemoveAuditRule(PacObjectAuditRule rule) {
            if (rule == null) {
                throw new ArgumentNullException("rule");
            }

			bool modified;
			return ModifyAuditRule(AccessControlModification.Remove, rule, out modified);
        }

        public void RemoveAuditRuleAll(PacAuditRule rule) {
            if (rule == null) {
                throw new ArgumentNullException("rule");
            }

			bool modified;
			ModifyAuditRule(AccessControlModification.RemoveAll, rule, out modified);
        }
 
        public void RemoveAuditRuleAll(PacObjectAuditRule rule) {
            if (rule == null) {
                throw new ArgumentNullException("rule");
            }

			bool modified;
			ModifyAuditRule(AccessControlModification.RemoveAll, rule, out modified);
        }

        public void RemoveAuditRuleSpecific(PacAuditRule rule) {
            if (rule == null) {
                throw new ArgumentNullException("rule");
            }

			bool modified;
			ModifyAuditRule(AccessControlModification.RemoveSpecific, rule, out modified);
        }

        public void RemoveAuditRuleSpecific(PacObjectAuditRule rule) {
            if (rule == null) {
                throw new ArgumentNullException("rule");
            }

			bool modified;
			ModifyAuditRule(AccessControlModification.RemoveSpecific, rule, out modified);
        }

		public void PurgeAuditRules(PacPrincipal principal) {
			this._securityDescriptor.PurgeAudit(principal.SecurityIdentifier);
			this._saclModified = true;
		}
		#endregion

		#region Effective access
/*
		public static string[] GetEffectiveAccess(byte[] binarySd, PacPrincipal principal, string limitingName) {
            uint desiredAccess = 0x02000000;  // MAX ALLOWED

			SecurityIdentifier sid = principal.SecurityIdentifier;
			byte[] sidBytes = new byte[sid.BinaryLength];
			sid.GetBinaryForm(sidBytes, 0);

            authz.AUTHZ_ACCESS_REQUEST request = new authz.AUTHZ_ACCESS_REQUEST();
            request.DesiredAccess = desiredAccess;

			authz.AUTHZ_ACCESS_REPLY reply = new authz.AUTHZ_ACCESS_REPLY();
            reply.ResultListLength = 1;
            reply.Error = Marshal.AllocHGlobal((int) (reply.ResultListLength * Marshal.SizeOf(typeof(UInt32))));
            reply.GrantedAccessMask = Marshal.AllocHGlobal((int) (reply.ResultListLength * Marshal.SizeOf(typeof(UInt32))));
            reply.SaclEvaluationResults = IntPtr.Zero;

            IntPtr hResourceManager = IntPtr.Zero;
			if (!authz.AuthzInitializeResourceManager(
				AuthzResourceManagerFlags.NoAudit, // Flags
				IntPtr.Zero,  // Access check callback function (Not used here)
				IntPtr.Zero,  // Dynamic groups callback function (Not used here)
				IntPtr.Zero,  // Callback function to free memory from previous callback (Not used here)
				"",           // Resource manager name
				out hResourceManager
			)) {
				throw new Exception(Marshal.GetLastWin32Error());
			}



		}
*/
		#endregion

		private void OverwriteAcl(bool isDacl) {
			// Empty ACL
			OverwriteAcl(isDacl, new RawAcl(_securityDescriptor.IsDS ? CommonAcl.AclRevisionDS : CommonAcl.AclRevision, 0));
		}
		
		private void OverwriteAcl(bool isDacl, RawAcl rawAcl) {
			if (isDacl) {
				// DiscretionaryAcl
				_daclInheritanceArray = null;
				_daclModified = true;
				
				if (rawAcl != null) {
					_securityDescriptor.DiscretionaryAcl = new DiscretionaryAcl(_securityDescriptor.IsContainer, _securityDescriptor.IsDS, rawAcl);
				}
				else {
					_securityDescriptor.DiscretionaryAcl = null;
				}
			}
			else {
				// SystemAcl

// Need a check here to see if any label, scope, or attribute information is contained
// so that _labelModified, _scopeModified, and _attributeModified can be set

				_saclInheritanceArray = null;
				_saclModified = true;

				if (rawAcl != null) {
					_securityDescriptor.SystemAcl = new SystemAcl(_securityDescriptor.IsContainer, _securityDescriptor.IsDS, rawAcl);
				}
				else {
					_securityDescriptor.SystemAcl = null;
				}
			}
		}
		
		private void UpdateWithNewSecurityDescriptor(RawSecurityDescriptor newOne, AccessControlSections includeSections) {
			if ((includeSections & AccessControlSections.Owner) != 0) {
				_ownerModified = true;
				_securityDescriptor.Owner = newOne.Owner;
			}
			
			if ((includeSections & AccessControlSections.Group) != 0) {
				_groupModified = true;
				_securityDescriptor.Group = newOne.Group;
			}

			if ((includeSections & AccessControlSections.Access) != 0) {
				OverwriteAcl(true, newOne.DiscretionaryAcl);
			}

			if ((includeSections & AccessControlSections.Audit) != 0) {
				OverwriteAcl(false, newOne.SystemAcl);
			}
		}
		
		public void SetSecurityDescriptorSddlForm(string sddlForm) {
			SetSecurityDescriptorSddlForm(sddlForm, AccessControlSections.All);
		}
		
		public void SetSecurityDescriptorSddlForm(string sddlForm, AccessControlSections includeSections) {
			if (sddlForm == null) {
				throw new ArgumentNullException("sddlForm");
			}
			
			UpdateWithNewSecurityDescriptor(new RawSecurityDescriptor(sddlForm), includeSections);
		}

		public byte[] GetSecurityDescriptorBinaryForm() {
			byte[] binaryForm = new byte[this.RawSD.BinaryLength];
			this.RawSD.GetBinaryForm(binaryForm, 0);
			return binaryForm;
		}
	
		public string GetSecurityDescriptorSddlForm() {
			return this.RawSD.GetSddlForm(AccessControlSections.All);
		}

		public string GetSecurityDescriptorSddlForm(AccessControlSections includeSections) {
			return this.RawSD.GetSddlForm(includeSections);
		}

		public string Sddl {
			get { return GetSecurityDescriptorSddlForm(); }
		}
		
		public override string ToString() {
			return ToString(this.GetRequestedSecurityInformation(), 50, false, true, true);
		}
		
		internal static string SECTION_NOT_REQUESTED_TEXT = "<NOT REQUESTED>";
		internal static string SECTION_EMPTY_TEXT = "<EMPTY>";

		public string ToString(SecurityInformation infoToShow, int width, bool wrapAces, bool includeInherited, bool includeLabel) {
			StringBuilder returnSb = new StringBuilder();

			if (includeLabel) {
				returnSb.AppendFormat("{0} ({1})", this.Path.ToString(), this.ObjectType);
				if (!string.IsNullOrEmpty(this.ComputerName)) {
					returnSb.AppendFormat(" [On {0}]", this.ComputerName);
				}
			}
			
			if ((infoToShow & SecurityInformation.Owner) != 0) {
				returnSb.Append("\n");
				if (includeLabel) { returnSb.Append("Owner: "); }
				
				if ((GetRequestedSecurityInformation() & SecurityInformation.Owner) != 0) {
					returnSb.Append(this.Owner);
				}
				else {
					returnSb.Append(SECTION_NOT_REQUESTED_TEXT);
				}
				returnSb.Append("\n");
			}

			if ((infoToShow & SecurityInformation.Group) != 0) {
				returnSb.Append("\n");
				if (includeLabel) { returnSb.Append("Group: "); }
				if ((GetRequestedSecurityInformation() & SecurityInformation.Group) != 0) {
					returnSb.Append(this.Group);
				}
				else {
					returnSb.Append(SECTION_NOT_REQUESTED_TEXT);
				}
				returnSb.Append("\n");
			}


			if ((infoToShow & SecurityInformation.ProtectedDacl) != 0) {
				returnSb.AppendFormat("\nDisable DACL Inheritance\n");
			}
			
			if ((infoToShow & SecurityInformation.UnprotectedDacl) != 0) {
				returnSb.AppendFormat("\nEnable DACL Inheritance\n");
			}

			int acesCount;
			if ((infoToShow & SecurityInformation.Dacl) != 0) {
				returnSb.Append("\n");
				if (includeLabel) { returnSb.Append("DACL:\n"); }
				if (includeLabel) { returnSb.Append("-----\n"); }

				if ((GetRequestedSecurityInformation() & SecurityInformation.Dacl) != 0) {
					acesCount = 0;
					foreach (AdaptedCommonAce ace in this.GetAccessRules(true, includeInherited, typeof(PacPrincipal))) {
						returnSb.AppendFormat("{0}\n", ace.ToString(width, wrapAces));
						acesCount++;
					}
					
					if (!includeInherited && !(this.AreAccessRulesProtected == true)) {
						returnSb.AppendFormat("<ANY ACES FROM PARENT HERE>\n");
					}
					else if (acesCount == 0) {
						returnSb.Append(SECTION_EMPTY_TEXT);
					}
				}
				else {
					returnSb.Append(SECTION_NOT_REQUESTED_TEXT);
				}
			}

			if ((infoToShow & SecurityInformation.ProtectedSacl) != 0) {
				returnSb.AppendFormat("\nDisable SACL Inheritance\n");
			}
			
			if ((infoToShow & SecurityInformation.UnprotectedSacl) != 0) {
				returnSb.AppendFormat("\nEnable SACL Inheritance\n");
			}
			
			if ((infoToShow & SecurityInformation.Sacl) != 0) {
				returnSb.Append("\n");
				if (includeLabel) { returnSb.Append("SACL:\n"); }
				if (includeLabel) { returnSb.Append("-----\n"); }

				if ((GetRequestedSecurityInformation() & SecurityInformation.Sacl) != 0) {
					acesCount = 0;
					foreach (AdaptedCommonAce ace in this.GetAuditRules(true, includeInherited, typeof(PacPrincipal))) {
						returnSb.AppendFormat("{0}\n", ace.ToString(width, wrapAces));
						acesCount++;
					}
					if (!includeInherited && !(this.AreAuditRulesProtected == true)) {
						returnSb.AppendFormat("<ANY ACES FROM PARENT HERE>\n");
					}
					else if (acesCount == 0) {
						returnSb.Append(SECTION_EMPTY_TEXT);
					}
				}
				else {
					returnSb.Append(SECTION_NOT_REQUESTED_TEXT);
				}
			}
		
			return returnSb.ToString();
		}
		
		public string FormatLabelAndDataString(string formatter, string label, int labelWidth, string data, int dataWidth, bool wrap) {
			
			StringBuilder returnSb = new StringBuilder(label + data + 20); // 20 is just padding...
			StringBuilder labelSb = new StringBuilder(label);
			StringBuilder dataSb = new StringBuilder(data);
			
			while (dataSb.Length > 0 && labelSb.Length > 0) {
				returnSb.AppendFormat(
					formatter,
					NibbleAtString(labelSb, labelWidth, wrap),
					NibbleAtString(dataSb, dataWidth, wrap)
				);
			}
			
			return returnSb.ToString();
		}

		private string NibbleAtString(StringBuilder sb, int length, bool wrap) {
			string returnString;
			if (sb.Length == 0) {
				return "";
			}
			else if (sb.Length <= length) {
				returnString = sb.ToString();
				sb.Clear();
			}
			else if (wrap == false) {
				return sb.ToString(0, length - 3) + "...";
			}
			else {
				returnString = sb.ToString(0, length);
				sb.Remove(0, length);
			}
			return returnString;
		}

	}
}
