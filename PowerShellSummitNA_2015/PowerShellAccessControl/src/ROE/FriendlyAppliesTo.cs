namespace ROE.PowerShellAccessControl {
	
	public class FriendlyAppliesTo {
		/*
			AppliesTo enumeration uses generic Object, ChildContainers, ChildObjects, DirectChildrenOnly to describe
			what to apply an ACE to. This class allows for friendlier, object-specific displaying of what an ACE
			applies to. A type converter allows this class to be converted directly into the AppliesTo enumeration
			so that an AdaptedAce can be fed directly into New-Ace/Add-Ace/Remove-Ace
		*/

		private AppliesTo _realAppliesTo;
		private Type _accessRightType;
		private Guid _inheritedObjectAceType;
		private bool _isContainer;
		
		#region Constructors
		public FriendlyAppliesTo(InheritanceFlags inheritanceFlags, PropagationFlags propagationFlags) {
			_realAppliesTo = (AppliesTo) 0;

			if ((inheritanceFlags & InheritanceFlags.ContainerInherit) == InheritanceFlags.ContainerInherit) {
				_realAppliesTo |= AppliesTo.ChildContainers;
			}

			if ((inheritanceFlags & InheritanceFlags.ObjectInherit) == InheritanceFlags.ObjectInherit) {
				_realAppliesTo |= AppliesTo.ChildObjects;
			}

			if ((propagationFlags & PropagationFlags.InheritOnly) != PropagationFlags.InheritOnly) {
				_realAppliesTo |= AppliesTo.Object;
			}

			if ((propagationFlags & PropagationFlags.NoPropagateInherit) == PropagationFlags.NoPropagateInherit) {
				_realAppliesTo |= AppliesTo.DirectChildrenOnly;
			}

		}
		
		public FriendlyAppliesTo(InheritanceFlags inheritanceFlags, PropagationFlags propagationFlags, Type accessRightType, bool isContainer) : this(inheritanceFlags, propagationFlags) {
			_accessRightType = accessRightType;
			_isContainer = isContainer;
		}
		
		public FriendlyAppliesTo(InheritanceFlags inheritanceFlags, PropagationFlags propagationFlags, Type accessRightType, Guid inheritedObjectAceType) : this(inheritanceFlags, propagationFlags) {
			_accessRightType = accessRightType;
			_inheritedObjectAceType = inheritedObjectAceType;
			_isContainer = true;
		}
		#endregion

		#region Static Mapper fields and methods
		private static IDictionary<string, IDictionary<AppliesTo, string>> ShortDictionary = new Dictionary<string, IDictionary<AppliesTo, string>>() {
//			{ "FileSystemRights", new Dictionary<string, string>() { {"Object", "F"}, {"ChildContainers", "SF"}, {"ChildObjects", "Fi" } } },
//			{ "RegistryRights", new Dictionary<string, string>() { {"Object", "K"}, {"ChildContainers", "SK"} } },
			{ "RegistryRights|True", new Dictionary<AppliesTo, string>() { {AppliesTo.Object, "O"}, {AppliesTo.ChildContainers, "CC"}, {AppliesTo.DirectChildrenOnly,"(DCO)"} } },
			{ "ActiveDirectoryRights|True", new Dictionary<AppliesTo, string>() { {AppliesTo.Object, "O"}, {AppliesTo.ChildContainers, "CC"}, {AppliesTo.DirectChildrenOnly,"(DCO)"} } }

		};
		
		private static IDictionary<string, IDictionary<AppliesTo, string>> LongDictionary = new Dictionary<string, IDictionary<AppliesTo, string>>() {
			{ "FileSystemRights|True", new Dictionary<AppliesTo, string>() { {AppliesTo.Object, "ThisFolder"}, {AppliesTo.ChildContainers, "SubFolders"}, {AppliesTo.ChildObjects, "Files" }, {AppliesTo.DirectChildrenOnly, "(DirectChildrenOnly)" } } },
			{ "FileSystemRights|False", new Dictionary<AppliesTo, string>() { {AppliesTo.Object, "ThisFile"} } },
			{ "RegistryRights|True", new Dictionary<AppliesTo, string>() { {AppliesTo.Object, "ThisKey"}, {AppliesTo.ChildContainers, "SubKeys"}, {AppliesTo.DirectChildrenOnly, "(DirectChildrenOnly)" } } },
			{ "ActiveDirectoryRights|True", new Dictionary<AppliesTo, string>() { {AppliesTo.Object, "Object"}, {AppliesTo.ChildContainers, "ChildContainers"}, {AppliesTo.DirectChildrenOnly, "(DirectChildrenOnly)" } } }
		};

		// If a type isn't defined in one of the two dictionaries above, one of these "generic" ones will be used:
		private static IDictionary<AppliesTo, string> GenericShortMapper = new Dictionary<AppliesTo, string>() {
			{AppliesTo.Object, "O"}, {AppliesTo.ChildContainers, "CC"}, {AppliesTo.ChildObjects, "CO"}, {AppliesTo.DirectChildrenOnly, "(DCO)"}
		};
		private static IDictionary<AppliesTo, string> GenericLongMapper = new Dictionary<AppliesTo, string>() {
			{AppliesTo.Object, "Object"}, {AppliesTo.ChildContainers, "ChildContainers"}, {AppliesTo.ChildObjects, "ChildObjects"}, {AppliesTo.DirectChildrenOnly, "(DirectChildrenOnly)"}
		};

		private static IDictionary<AppliesTo, string> GetShortMapper(string type) {
			return GetShortMapper(type, true);
		}
		
		private static IDictionary<AppliesTo, string> GetShortMapper(string type, bool isContainer) {
			string key = string.Format("{0}|{1}", type, isContainer);
			if (type != null && ShortDictionary.ContainsKey(key)) {
				return ShortDictionary[key];
			}
			else {
				return GenericShortMapper;
			}
		}

		private static IDictionary<AppliesTo, string> GetLongMapper(string type) {
			return GetLongMapper(type, true);
		}
		
		private static IDictionary<AppliesTo, string> GetLongMapper(string type, bool isContainer) {
			string key = string.Format("{0}|{1}", type, isContainer);
			if (type != null && LongDictionary.ContainsKey(key)) {
				return LongDictionary[key];
			}
			else {
				return GenericLongMapper;
			}
		}
		
		private Dictionary<AppliesTo, string> GetMapper(bool shortMode) {
			string accessRightType = _accessRightType != null ? _accessRightType.Name : null;
			
			if (shortMode) {
				return (Dictionary<AppliesTo, string>) GetShortMapper(accessRightType, this._isContainer);
			}
			else {
				return (Dictionary<AppliesTo, string>) GetLongMapper(accessRightType, this._isContainer);
			}
		}

		private string[] GetAppliesToStringArrayWithoutDco(Dictionary<AppliesTo, string> mapper, bool shortMode) {
			// This doesn't check the PropagationFlags.NoPropagateInherit. That's handled outside of this
			// helper function so that this function's output can be joined with either spaces or commas

			List<string> appliesToList = new List<string>();

			foreach (AppliesTo currentAppliesToValue in Enum.GetValues(typeof(AppliesTo))) {
				if (currentAppliesToValue == AppliesTo.DirectChildrenOnly) { 
					continue; 
				}
				
				if (mapper.ContainsKey(currentAppliesToValue)) {
					// Checking like this gives the ability to ignore some of the enum values, e.g., 
					// registry keys have no concept of 'ChildObjects', so if the mapper doesn't define
					// 'ChildObjects', an ACE with that defined won't have it shown in the friendly string
					
					if ((_realAppliesTo & currentAppliesToValue) == currentAppliesToValue) {
						appliesToList.Add(mapper[currentAppliesToValue]);
					}
					else if (shortMode == true) {
						// Leave space for any flags that aren't set
						appliesToList.Add(new string(' ', mapper[currentAppliesToValue].Length));
					}
				}
			}

			return appliesToList.ToArray();
		}

		#endregion

		private string InheritedObjectAceTypeDisplay {
			get {
				if (_inheritedObjectAceType == null || _inheritedObjectAceType == Guid.Empty) {
					return string.Empty;
				}
				
				return AdaptedActiveDirectoryAce.GetObjectAceTypeString(
					_inheritedObjectAceType, 
					new ActiveDirectoryObjectAceTypeGuidType[] { ActiveDirectoryObjectAceTypeGuidType.ClassObject }, 
					false
				);
			}
		}

		
		public AppliesTo AppliesToEnum {
			get {
				return _realAppliesTo;
			}
		}
		
		public string AppliesToString {
			get {
				return ToString();
			}
		}

		public bool TestIsDefaultForObject() {
			/*
				Tests whether or not the applies to is default or "special". This is used by PS to give
				simple display of the ACLs without AppliesTo column. If the AppliesTo isn't default for
				the object type, 'Special' is displayed to the user.
			*/
		
			// We're going to build up what a normal AppliesTo value should look like using the info
			// this class keeps up with: access mask enum and whether or not it is a container
		
			// Non container objects will apply just to object, e.g., files, printers, services, so
			// start with that:
			AppliesTo normalAppliesTo = AppliesTo.Object;
			AppliesTo effectiveAppliesTo = this.AppliesToEnum;
			
			// Check to see if the parent SD is for a container
			if (this._isContainer) {
				// AppliesTo should also apply to any child containers. This takes care of AD objects
				// and registry keys
				normalAppliesTo |= AppliesTo.ChildContainers;
				
				if (this._accessRightType == typeof(FileSystemRights)) { // Must be a folder
					normalAppliesTo |= AppliesTo.ChildObjects;
				}
			
				if (this._accessRightType == typeof(RegistryRights)) {
					// Remove ChildObjects from appliesto test for registry keys
					effectiveAppliesTo &= ~AppliesTo.ChildObjects;
				}
			}
			
			return normalAppliesTo == effectiveAppliesTo;
		}
		
		public override string ToString() {
			return ToString(false);
		}
		
		public string ToString(bool shortMode) {
			Dictionary<AppliesTo, string> mapper = GetMapper(shortMode);
			StringBuilder appliesToString;
			string separator;
			int sbCapacity;
		
			if (shortMode) {
				sbCapacity = 20;
				separator = " ";
			}
			else {
				sbCapacity = 50;
				separator = ", ";
			}

			if ( !(string.IsNullOrEmpty(this.InheritedObjectAceTypeDisplay)) ) {
				sbCapacity += this.InheritedObjectAceTypeDisplay.Length;
			}

			appliesToString = new StringBuilder(sbCapacity);
			appliesToString.Append(string.Join(separator, GetAppliesToStringArrayWithoutDco(mapper, shortMode)));
			
			if ((_realAppliesTo & AppliesTo.DirectChildrenOnly) != 0 && mapper.ContainsKey(AppliesTo.DirectChildrenOnly)) {
				appliesToString.Append(" ");
				appliesToString.Append(mapper[AppliesTo.DirectChildrenOnly]);
			}

			if ( !(string.IsNullOrEmpty(this.InheritedObjectAceTypeDisplay)) ) {
				appliesToString.Append(" (");
				appliesToString.Append(this.InheritedObjectAceTypeDisplay);
				appliesToString.Append(")");
			}
			
			return appliesToString.ToString();
		}
		
		public string GetShortString() {
			return ToString(true);
		}
	}
}