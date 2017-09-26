
namespace ROE.PowerShellAccessControl {

	public abstract class AdaptedAceFilter {
		
		public AdaptedAceFilter(bool specific, bool negate) {
			this.Specific = specific;
			this.Negate = negate;
			
			this.AdditionalFilterList = new List<AdaptedAceFilter>();
		}

		public bool Specific { 
			get {
				return _specific;
			}
			set {
				bool originalValue = _specific;
				_specific = value;

				if (_specific != originalValue) {
					if (SpecificChanged != null) {
						SpecificChanged();
					}
				}
			}
		}
		private bool _specific;
		
		public bool Negate { get; set; }

		/*
			ACE filters are essentially ANDed together, so all must return true. The
			AdditionalFilterList was a last minute way to provide a method of ORing
			ACE filters together.
			
			Take this command for example> Get-Ace -Principal user1, user2
			If two PrincpalAceFilters were created and added to the main ACE filters
			list that GetAccessRules() will take, nothing would be returned b/c the
			principal would have to match 'user1' and 'user2'. Instead, the Get-Ace
			cmdlet takes the first filter (the one for 'user1'), and just adds any
			other principal filters to the first one. That effectively makes it so
			the principal only has to match one. Additional parameters create ACE
			filters that are still ANDed...
		*/
		public List<AdaptedAceFilter> AdditionalFilterList { get; private set; }
		public void AddAdditionalFilter(AdaptedAceFilter aceFilter) {
			this.AdditionalFilterList.Add(aceFilter);
		}

		public bool Match(AdaptedCommonAce ace) {
			return Match(ace, this.Specific);
		}

		public bool Match(AdaptedCommonAce ace, bool? specific) {
			if (specific != null) {
				return Match(ace, specific.Value);
			}
			else {
				return Match(ace);
			}
		}

		public bool Match(AdaptedCommonAce ace, bool specific) {

			// First check the main filter:
			if (this.MatchSingle(ace, specific)) {
				return true;
			}
			
			// Now check any additional filters:
			foreach (AdaptedAceFilter currentFilter in this.AdditionalFilterList) {
				if (currentFilter.MatchSingle(ace, specific)) { return true; }
			}

			// Didn't match on any filters
			return false;
		}
		
		public abstract bool MatchSingle(AdaptedCommonAce ace, bool specific);

		public event Action SpecificChanged;
	}

	public class AceTypeAceFilter : AdaptedAceFilter {
		
		private Enums.AceType[] _aceTypes;

		public AceTypeAceFilter(Enums.AceType[] aceTypes) : this(aceTypes, false, false) {}
		public AceTypeAceFilter(Enums.AceType[] aceTypes, bool specific) : this(aceTypes, specific, false) {}
		
		public AceTypeAceFilter(Enums.AceType[] aceTypes, bool specific, bool negate) : base(specific, negate) {
			_aceTypes = aceTypes;
		}

		public override bool MatchSingle(AdaptedCommonAce ace, bool specific) {
			bool result = false;
			
			foreach (Enums.AceType currentAceType in _aceTypes) {
				if (ace.AceType.StartsWith(currentAceType.ToString())) {
					result = true; 
					break;
				}
			}
			
			if (this.Negate) {
				return !result;
			}
			else {
				return result;
			}
		}

	}

	public class AppliesToAceFilter : AdaptedAceFilter {
		
		private static AceFlagsConverter AceFlagsConverter = new AceFlagsConverter();
		private AppliesTo _appliesTo;
		
		public AppliesToAceFilter(AppliesTo appliesTo) : this(appliesTo, false, false) {}
		public AppliesToAceFilter(AppliesTo appliesTo, bool specific) : this(appliesTo, specific, false) {}
		public AppliesToAceFilter(AppliesTo appliesTo, bool specific, bool negate) : base(specific, negate) {
			_appliesTo = appliesTo;
		}
/*		
		public override bool MatchSingle(QualifiedAce ace) {
			AppliesTo aceAppliesTo = (AppliesTo) AceFlagsConverter.ConvertTo(ace.AceFlags, typeof(AppliesTo));
			
			if (this.Specific) {
				return ((_appliesTo & aceAppliesTo) == aceAppliesTo);
			}
			else {
				return ((_appliesTo & aceAppliesTo) == _appliesTo);
			}
		}
*/		
		public override bool MatchSingle(AdaptedCommonAce ace, bool specific) {
			bool result;
			if (specific) {
				result = _appliesTo == ace.AppliesTo.AppliesToEnum;
			}
			else {
				result = (_appliesTo & ace.AppliesTo.AppliesToEnum) == _appliesTo;
			}
			
			if (this.Negate) {
				return !result;
			}
			else {
				return result;
			}
		}
	}

	public class AuditFlagsAceFilter : AdaptedAceFilter {
		
		private AuditFlags _auditFlags;
		
		public AuditFlagsAceFilter(AuditFlags auditFlags) : this(auditFlags, false, false) {}
		public AuditFlagsAceFilter(AuditFlags auditFlags, bool specific) : this(auditFlags, specific, false) {}
		public AuditFlagsAceFilter(AuditFlags auditFlags, bool specific, bool negate) : base(specific, negate) {
			_auditFlags = auditFlags;
		}

		public override bool MatchSingle(AdaptedCommonAce ace, bool specific) {
			bool result;
			if (specific) {
				result = _auditFlags == ace.AuditFlags;
			}
			else {
				result = (_auditFlags & ace.AuditFlags) == _auditFlags;
			}
			
			if (this.Negate) {
				return !result;
			}
			else {
				return result;
			}
		}
	}

	public class InheritedObjectAceTypeFilter : AdaptedAceFilter {
		
		Regex _nameRegex;
		
		public InheritedObjectAceTypeFilter(string displayName) : this(displayName, false, false) {}
		public InheritedObjectAceTypeFilter(string displayName, bool specific) : this(displayName, specific, false) {}
		public InheritedObjectAceTypeFilter(string displayName, bool specific, bool negate) : base(specific, negate) {
			_nameRegex = ObjectAceTypeGuidConverter.StringToRegex(displayName);
		}

		public override bool MatchSingle(AdaptedCommonAce ace, bool specific) {
			bool result;
			
			result = false;
			Guid inheritedObjectAceTypeGuid = Guid.Empty;
			if (ace is AdaptedActiveDirectoryAce) {
				inheritedObjectAceTypeGuid = ((AdaptedActiveDirectoryAce) ace).InheritedObjectAceType;
			}
			
			if (inheritedObjectAceTypeGuid == Guid.Empty && !specific) {
				result = true;
			}
			else if (inheritedObjectAceTypeGuid != Guid.Empty) {
				ActiveDirectoryAceTypeInstance typeInstance = ObjectAceTypeGuidConverter.LookupFirstByGuid(
					inheritedObjectAceTypeGuid.ToString(), 
					new ActiveDirectoryObjectAceTypeGuidType[] { ActiveDirectoryObjectAceTypeGuidType.ClassObject }
				);
				
				if (typeInstance != null && _nameRegex.IsMatch(typeInstance.DisplayName)) {
					result = true;
				}
			}
			
			if (this.Negate) {
				return !result;
			}
			else {
				return result;
			}
		}
	}

	public class ObjectAceTypeFilter : AdaptedAceFilter {
		internal Regex _nameRegex;
		
		public ObjectAceTypeFilter(string displayName) : this(displayName, false, false) {}
		public ObjectAceTypeFilter(string displayName, bool specific) : this(displayName, specific, false) {}
		internal ObjectAceTypeFilter(string displayName, bool specific, bool negate) : base(specific, negate) {
			_nameRegex = ObjectAceTypeGuidConverter.StringToRegex(displayName);

			this.ValidAccessMask = 0;

			// This looks up the display name and makes sure the ValidAccessMask is updated (makes it so the non-specific
			// check will work against ACEs with empty GUID for the ObjectAceType
			ActiveDirectoryAceTypeInstance typeInstance;
			if (ObjectAceTypeGuidConverter.TryLookupFirstByDisplayName(displayName, new ActiveDirectoryObjectAceTypeGuidType[] { ActiveDirectoryObjectAceTypeGuidType.Property, ActiveDirectoryObjectAceTypeGuidType.PropertySet }, out typeInstance)) {
				this.ValidAccessMask |= Enums.ActiveDirectoryRights.ReadAndWriteProperty;
			}

			if (ObjectAceTypeGuidConverter.TryLookupFirstByDisplayName(displayName, new ActiveDirectoryObjectAceTypeGuidType[] { ActiveDirectoryObjectAceTypeGuidType.ClassObject }, out typeInstance)) {
				this.ValidAccessMask |= Enums.ActiveDirectoryRights.CreateAndDeleteChild;
			}

			if (ObjectAceTypeGuidConverter.TryLookupFirstByDisplayName(displayName, new ActiveDirectoryObjectAceTypeGuidType[] { ActiveDirectoryObjectAceTypeGuidType.ValidatedWrite }, out typeInstance)) {
				this.ValidAccessMask |= Enums.ActiveDirectoryRights.ValidatedWrite;
			}

			if (ObjectAceTypeGuidConverter.TryLookupFirstByDisplayName(displayName, new ActiveDirectoryObjectAceTypeGuidType[] { ActiveDirectoryObjectAceTypeGuidType.ExtendedRight }, out typeInstance)) {
				this.ValidAccessMask |= Enums.ActiveDirectoryRights.ExtendedRight;
			}

			this.TypesToSearch = new ActiveDirectoryObjectAceTypeGuidType[] {
				ActiveDirectoryObjectAceTypeGuidType.PropertySet,
				ActiveDirectoryObjectAceTypeGuidType.Property,
				ActiveDirectoryObjectAceTypeGuidType.ClassObject,
				ActiveDirectoryObjectAceTypeGuidType.ExtendedRight,
				ActiveDirectoryObjectAceTypeGuidType.ValidatedWrite
			};
		}

		public Enums.ActiveDirectoryRights ValidAccessMask { get; private set; }
		public ActiveDirectoryObjectAceTypeGuidType[] TypesToSearch { get; set; }

		public List<ActiveDirectoryAceTypeInstance> GetEffectiveAccessList() {
			// First, combine all regexes into one:
			
			List<string> regexStrings = new List<string>();
			regexStrings.Add(this._nameRegex.ToString());
			
			for (int i = 1; i < this.AdditionalFilterList.Count; i++) {
				ObjectAceTypeFilter currentFilter = this.AdditionalFilterList[i] as ObjectAceTypeFilter;
				
				if (currentFilter != null) {
					regexStrings.Add(currentFilter._nameRegex.ToString());
				}
			}

			string combinedRegexString = string.Join("|", regexStrings);
			
			if (this.Negate) { combinedRegexString = string.Format(@"^(?!({0})).*$", combinedRegexString); }
			
			return ObjectAceTypeGuidConverter.PrepareAceTypeListForAuthZ(
				ObjectAceTypeGuidConverter.LookupAceType(
					ObjectAceTypeGuidConverterLookupType.ByDisplayName, 
					new Regex(combinedRegexString, RegexOptions.IgnoreCase), 
					this.TypesToSearch, 
					-1, 
					null, 
					true
				)
			);
		}

		public override bool MatchSingle(AdaptedCommonAce ace, bool specific) {
			bool result;
			
			result = false;
			Guid objectAceTypeGuid = Guid.Empty;
			if (ace is AdaptedActiveDirectoryAce) {
				objectAceTypeGuid = ((AdaptedActiveDirectoryAce) ace).ObjectAceType;
			}
			
			if (objectAceTypeGuid == Guid.Empty && !specific) {
				result = true;
			}
			else if (objectAceTypeGuid != Guid.Empty) {
				ActiveDirectoryAceTypeInstance typeInstance = ObjectAceTypeGuidConverter.LookupFirstByGuid(
					objectAceTypeGuid.ToString(),
					this.TypesToSearch
				);
				
				if (typeInstance != null) {
					if (_nameRegex.IsMatch(typeInstance.DisplayName)) {
						result = true;
					}
					else if (typeInstance.ObjectType == ActiveDirectoryObjectAceTypeGuidType.PropertySet) { // !specific check would exclude PropertySet matches
						// The current ACE's GUID is a property set; check to see if any contained properties
						// have display names that match...

						List<ActiveDirectoryAceTypeInstance> properties = ObjectAceTypeGuidConverter.LookupPropertiesByPropertySetGuid(typeInstance.AceTypeGuid);
						
						if (properties != null) {
							foreach (ActiveDirectoryAceTypeInstance currentProperty in properties) {

								if (_nameRegex.IsMatch(currentProperty.DisplayName)) {
									result = true;
									break;
								}
							}
						}
					}
				}
			}

			
			// One more thing to check: is the access mask valid for the display name passed?
			if ( (ace.AccessMask.AccessMask & (int) this.ValidAccessMask) == 0) {
				result = false;
			}
			
			
			if (this.Negate) {
				return !result;
			}
			else {
				return result;
			}
		}
	}
	
	public class AccessMaskAceFilter : AdaptedAceFilter {
		public int AccessMask { get; set; }
		
		public AccessMaskAceFilter(object accessMask) : this(accessMask, false, false) {}
		public AccessMaskAceFilter(object accessMask, bool specific) : this(accessMask, specific, false) {}
		
		public AccessMaskAceFilter(object accessMask, bool specific, bool negate) : base(specific, negate) {
			if (accessMask == null) {
				throw new ArgumentNullException("accessMask");
			}

			Type valueType = accessMask.GetType();
			switch (valueType.FullName) {
				
				case "System.Int32":
				case "System.Int16":
				case "System.UInt32":
				case "System.UInt16":
					this.AccessMask = (int) accessMask;
					break;
				
				case "ROE.PowerShellAccessControl.AccessMaskDisplay":
					this.AccessMask = ((AccessMaskDisplay) accessMask).AccessMask;
					break;
					
				default:
					if (valueType.IsEnum && valueType.IsDefined(typeof(FlagsAttribute), false)) {
						goto case "System.Int32";
					}
					else {
						throw new Exception(string.Format("Unsupported type for AccessMask: {0}", valueType.FullName));
					}
					break;
			}
		}
		
		public override bool MatchSingle(AdaptedCommonAce ace, bool specific) {
			bool result;
			if (specific) {
				result = ace.AccessMask.AccessMask == this.AccessMask;
			}
			else {
				result = (ace.AccessMask.AccessMask & this.AccessMask) == this.AccessMask;
			}
			
			if (this.Negate) {
				return !result;
			}
			else {
				return result;
			}
		}
	}

	public class PrincipalAceFilter : AdaptedAceFilter {
		public Regex FullUserNameRegex { get; private set; }
		public string UserName { get; private set; }
// More things can be added, e.g., DomainName, AccountName, SidUse, etc
		
		public PrincipalAceFilter() : this(null, false, false) {}
		public PrincipalAceFilter(string likeString) : this(likeString, false, false) {}
		public PrincipalAceFilter(string likeString, bool specific) : this(likeString, specific, false) {}
		public PrincipalAceFilter(string likeString, bool specific, bool negate) : base(specific, negate) {
			this.UserName = Regex.Escape(likeString);
			UpdateFullUserNameRegex();

			this.SpecificChanged += UpdateFullUserNameRegex;
		}
		
		private void UpdateFullUserNameRegex() {
			string likeString = this.UserName;
			
			if (!this.Specific) { 
				likeString = string.Format(@"(.*\\)?{0}", likeString); 
			}
			likeString = string.Format("^{0}$", likeString);
			// Fix potential ** nested quantifier:
			likeString = likeString.Replace(@"**", "*");

			// Regex.Escape has changed ? and * to \? and \*
			this.FullUserNameRegex = new Regex(likeString.Replace(@"\?", ".").Replace(@"\*", ".*"), RegexOptions.IgnoreCase);
		}
		
		public override bool MatchSingle(AdaptedCommonAce ace, bool specific) {
			// Specific has no bearing on Match() method
			bool result;
			result = FullUserNameRegex.IsMatch(ace.Principal.ToString());
			
			if (this.Negate) {
				return !result;
			}
			else {
				return result;
			}
		}
	}
}