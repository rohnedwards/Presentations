namespace ROE.PowerShellAccessControl {

	[Cmdlet(VerbsCommon.Get, "PacAdObjectAceType", DefaultParameterSetName="SearchByDisplayName")]
	public class GetPacAdObjectAceType : PSCmdlet {
		
		[Parameter(ParameterSetName="SearchByDisplayName", Position=0)]
		public string[] DisplayName { get; set; }

		[Parameter(ParameterSetName="SearchByName")]
		public string[] Name { get; set; }

		[Parameter(ParameterSetName="SearchByGuid")]
		public string[] Guid { get; set; }
		
		[Parameter()]
		public ActiveDirectoryObjectAceTypeGuidType[] TypesToSearch { 
			get { 
				return _typesToSearch ??
					(_typesToSearch = new ActiveDirectoryObjectAceTypeGuidType[] { 
						ActiveDirectoryObjectAceTypeGuidType.Property,
						ActiveDirectoryObjectAceTypeGuidType.PropertySet,
						ActiveDirectoryObjectAceTypeGuidType.ValidatedWrite,
						ActiveDirectoryObjectAceTypeGuidType.ExtendedRight,
						ActiveDirectoryObjectAceTypeGuidType.ClassObject
					});
			}
			
			set { _typesToSearch = value; }
		}
		private ActiveDirectoryObjectAceTypeGuidType[] _typesToSearch;

		[Parameter()]
		public int MaxResults {
			get { return _maxResults; }
			set { _maxResults = value; }
		}
		private int _maxResults = -1;

		public string DomainName {
			get { return _domainName; }
			set { _domainName = value; }
		}
		private string _domainName = string.Empty; 

		protected override void ProcessRecord() {
		
			ObjectAceTypeGuidConverterLookupType lookupType;
			List<string> searchStrings = new List<string>();
		
			switch (this.ParameterSetName) {
				case "SearchByDisplayName":
					lookupType = ObjectAceTypeGuidConverterLookupType.ByDisplayName;
					foreach (string currentDisplayName in this.DisplayName) {
						searchStrings.Add(ObjectAceTypeGuidConverter.StringToRegex(currentDisplayName).ToString());
					}
					break;
					
				case "SearchByName":
					lookupType = ObjectAceTypeGuidConverterLookupType.ByName;
					foreach (string currentName in this.Name) {
						searchStrings.Add(ObjectAceTypeGuidConverter.StringToRegex(currentName).ToString());
					}
					break;

				case "SearchByGuid":
					lookupType = ObjectAceTypeGuidConverterLookupType.ByGuid;
					foreach (string currentGuidString in this.Guid) {
						searchStrings.Add(ObjectAceTypeGuidConverter.StringToRegex(currentGuidString).ToString());
					}
					break;
			
				default:
					WriteError(new ErrorRecord(
						new Exception(string.Format("Unkown ParameterSetName: {0}", this.ParameterSetName)),
						"",
						ErrorCategory.InvalidData,
						this.ParameterSetName
					));
					return;
			}
			
			WriteObject(
				ObjectAceTypeGuidConverter.LookupAceType(
					lookupType, 
					new Regex(string.Join("|", searchStrings), RegexOptions.IgnoreCase), 
					this.TypesToSearch, 
					this.MaxResults, 
					this.DomainName, 
					false
				),
				true
			);
		}
	}

	public class ActiveDirectoryInheritedAceTypeInstance : ActiveDirectoryAceTypeInstance {
		public ActiveDirectoryInheritedAceTypeInstance(string displayName) : base(displayName, new ActiveDirectoryObjectAceTypeGuidType[] { ActiveDirectoryObjectAceTypeGuidType.ClassObject }) {}
		public ActiveDirectoryInheritedAceTypeInstance(Guid guid) : base(guid, new ActiveDirectoryObjectAceTypeGuidType[] { ActiveDirectoryObjectAceTypeGuidType.ClassObject }) {}
	}

	public class ActiveDirectoryAceTypeInstance : IComparable<ActiveDirectoryAceTypeInstance> {
	
		public ActiveDirectoryAceTypeInstance(string guidString, string name, string displayName, ActiveDirectoryObjectAceTypeGuidType objectType) : this (guidString, name, displayName, objectType, 1, Guid.Empty) {}
		
		public ActiveDirectoryAceTypeInstance(string guidString, string name, string displayName, ActiveDirectoryObjectAceTypeGuidType objectType, ushort objectTypeListLevel, Guid propertySetGuid) {
			this.AceTypeGuid = guidString;
			this.Name = name;
			this.DisplayName = displayName;
			this.ObjectType = objectType;
			this.ObjectTypeListLevel = objectTypeListLevel;
			this.PropertySetGuid = propertySetGuid.ToString();
		}

#region Are any methods using these constructors? If not, get rid of them
		public ActiveDirectoryAceTypeInstance(string displayName) : this(displayName, new ActiveDirectoryObjectAceTypeGuidType[] { 
			ActiveDirectoryObjectAceTypeGuidType.Property,
			ActiveDirectoryObjectAceTypeGuidType.PropertySet,
			ActiveDirectoryObjectAceTypeGuidType.ValidatedWrite,
			ActiveDirectoryObjectAceTypeGuidType.ExtendedRight,
			ActiveDirectoryObjectAceTypeGuidType.ClassObject
		}) { }

		public ActiveDirectoryAceTypeInstance(string displayName, ActiveDirectoryObjectAceTypeGuidType[] types) {
			try {
				copyAceInstance(GetSingleAceTypeInstance(displayName, types, ObjectAceTypeGuidConverterLookupType.ByDisplayName));
			}
			catch {
				copyAceInstance(GetSingleAceTypeInstance(displayName, types, ObjectAceTypeGuidConverterLookupType.ByGuid));
			}
		}

		public ActiveDirectoryAceTypeInstance(Guid guid) : this(guid, new ActiveDirectoryObjectAceTypeGuidType[] { 
			ActiveDirectoryObjectAceTypeGuidType.Property,
			ActiveDirectoryObjectAceTypeGuidType.PropertySet,
			ActiveDirectoryObjectAceTypeGuidType.ValidatedWrite,
			ActiveDirectoryObjectAceTypeGuidType.ExtendedRight,
			ActiveDirectoryObjectAceTypeGuidType.ClassObject
		}) { }

		public ActiveDirectoryAceTypeInstance(Guid guid, ActiveDirectoryObjectAceTypeGuidType[] types) {
			copyAceInstance(GetSingleAceTypeInstance(guid.ToString(), types, ObjectAceTypeGuidConverterLookupType.ByGuid));
		}

		private void copyAceInstance(ActiveDirectoryAceTypeInstance aceInstance) {
			this.AceTypeGuid = aceInstance.AceTypeGuid;
			this.Name = aceInstance.Name;
			this.DisplayName = aceInstance.DisplayName;
			this.ObjectType = aceInstance.ObjectType;
			this.ObjectTypeListLevel = aceInstance.ObjectTypeListLevel;
			this.PropertySetGuid = aceInstance.PropertySetGuid;
		}
#endregion
		
		private static ActiveDirectoryAceTypeInstance GetSingleAceTypeInstance(string lookupArgument, ActiveDirectoryObjectAceTypeGuidType[] types, ObjectAceTypeGuidConverterLookupType lookupType) {

			ActiveDirectoryAceTypeInstance aceInstance = null;
			using (PowerShell ps = PowerShell.Create()) {
				ps.AddCommand("Write-Output").AddArgument(ObjectAceTypeGuidConverter.LookupAceType(
					lookupType,
					ObjectAceTypeGuidConverter.StringToRegex(lookupArgument),
					types,
					-1,
					null,
					false
				)).AddCommand("Out-GridView").AddParameter("OutputMode", "Single").AddParameter("Title", "Make a selection");

				foreach (ActiveDirectoryAceTypeInstance output in ps.Invoke<ActiveDirectoryAceTypeInstance>()) {
					aceInstance = output;
					break;
				}

/*
				foreach (PSObject output in ps.Invoke()) {
					aceInstance = (ActiveDirectoryAceTypeInstance) output.BaseObject;
					break;
				}
*/
			}
			
			if (aceInstance == null) {
				throw new Exception(string.Format("Unable to determine GUID from '{0}'", lookupArgument));
			}
			return aceInstance;
		}

		public string AceTypeGuid { get; private set; }
		public string Name { get; private set; }
		public string DisplayName { get; private set; }
		public ActiveDirectoryObjectAceTypeGuidType ObjectType { get; private set; }
		internal string PropertySetGuid { get; set; }
		internal ushort ObjectTypeListLevel { get; set; }
		internal string DomainName { get; set; }
		
		public ActiveDirectoryAceTypeInstance GetParentAceTypeInstance() {
			// Properties are the only objects that can have parents, but not
			// all properties are children. Easiest way to check is to see if
			// PropertySetGuid is empty GUID
			if (this.PropertySetGuid == Guid.Empty.ToString()) {
				return null;
			}
			
			return ObjectAceTypeGuidConverter.LookupFirstByGuid(
				this.PropertySetGuid, 
				new ActiveDirectoryObjectAceTypeGuidType[] { 
					ActiveDirectoryObjectAceTypeGuidType.PropertySet
				}
			);
		}

		public List<ActiveDirectoryAceTypeInstance> GetChildAceTypeInstances() {
			// PropertSets are the only objects that can have children
			if (this.ObjectType != ActiveDirectoryObjectAceTypeGuidType.PropertySet) {
				return null;
			}
			
			return ObjectAceTypeGuidConverter.LookupPropertiesByPropertySetGuid(this.AceTypeGuid, this.DomainName);
		}

		
		public override string ToString() {
			return this.DisplayName;
		}
		
		public int CompareTo(ActiveDirectoryAceTypeInstance that) {

			// For AD effective access to work properly, it makes it easier
			// if the AceTypeInstances are in order by PropertySetGuid and then ObjectTypeListLevel

			int guidResult = this.PropertySetGuid.CompareTo(that.PropertySetGuid);
			
			if (guidResult == 0) {
				// GUIDs match, so check out the ObjectTypeListLevel
				return this.ObjectTypeListLevel.CompareTo(that.ObjectTypeListLevel);
			}
			else {
				return guidResult;
			}
		}
	}

	internal class ObjectAceTypeGuidConverter {

        // Stores the full path to the Schema container
        private string _schemaContainerPath, _extendedRightsContainerPath, _domain;
	
        internal ObjectAceTypeGuidConverter(string domain) {
            if (string.IsNullOrEmpty(domain)) {
				domain = System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties().DomainName;
			}	
				
			_domain = domain;

            using (DirectoryEntry rootDse = new DirectoryEntry(String.Format("LDAP://{0}/RootDSE", domain))) {
				// Get Schema container path
				_schemaContainerPath = String.Format("LDAP://{0}", rootDse.Properties["schemaNamingContext"].Value);
				_extendedRightsContainerPath = String.Format("LDAP://CN=Extended-Rights,{0}", rootDse.Properties["ConfigurationNamingContext"].Value);
			}

			LoadAdControlAccessRights();
			LoadAdSchemaObjects();

			_adAceTypeList.Sort();
        }

		// Each domain gets its own ObjectAceTypeGuidConverter
		private static Dictionary<string, ObjectAceTypeGuidConverter> _objectAceTypeGuidConverters = new Dictionary<string, ObjectAceTypeGuidConverter>();
		private static ObjectAceTypeGuidConverter GetObjectAceTypeGuidConverter(string domainName) {
			
			if (domainName == null) { domainName = string.Empty; }
			
			try {
				if (!(_objectAceTypeGuidConverters.ContainsKey(domainName))) {
					_objectAceTypeGuidConverters.Add(domainName, new ObjectAceTypeGuidConverter(domainName));
				}
			}
			catch {
				return null;
			}
			
			return _objectAceTypeGuidConverters[domainName];
		}

		public List<ActiveDirectoryAceTypeInstance> _adAceTypeList = new List<ActiveDirectoryAceTypeInstance>();

		private void LoadAdSchemaObjects() {
			
			/*
				Looks up properties and class objects
			*/
			
			using (DirectoryEntry searchRootObject = new DirectoryEntry(_schemaContainerPath)) {
				using (DirectorySearcher searcher = new DirectorySearcher(searchRootObject, "(|(ObjectClass=attributeschema)(ObjectClass=classschema))", new string[] { "schemaidguid", "ldapdisplayname", "name", "attributesecurityguid", "classSchema", "ObjectClass" })) {
					searcher.PageSize = 1000;

					using (SearchResultCollection results = searcher.FindAll()) {
						string guidString, propSetGuidString, name, displayName, objectClass;
						ActiveDirectoryObjectAceTypeGuidType type;
						ActiveDirectoryAceTypeInstance aceTypeInstance;
						
						foreach (SearchResult searchResult in results) {
							guidString = (new Guid((byte[]) searchResult.Properties["schemaidguid"][0])).ToString();
							name = searchResult.Properties["name"][0].ToString();
							displayName = searchResult.Properties["ldapdisplayname"][0].ToString();
							objectClass = searchResult.Properties["objectclass"][1].ToString();
							switch (objectClass) {
							
								case "attributeSchema":
									type = ActiveDirectoryObjectAceTypeGuidType.Property;
									break;
									
								case "classSchema":
									type = ActiveDirectoryObjectAceTypeGuidType.ClassObject;
									break;
							
								default:
									goto EndOfForEach;
							}

							aceTypeInstance = new ActiveDirectoryAceTypeInstance(guidString, name, displayName, type);
							aceTypeInstance.DomainName = _domain;

							if (searchResult.Properties.Contains("attributesecurityguid")) {
								// This property belongs to a property set, so record the property set's GUID, and
								// set the ObjectTypeListLevel to 2 (used for effective access)

								propSetGuidString = (new Guid((byte[]) searchResult.Properties["attributesecurityguid"][0])).ToString();
								aceTypeInstance.PropertySetGuid = propSetGuidString;
								aceTypeInstance.ObjectTypeListLevel = 2;
							}
							
							_adAceTypeList.Add(aceTypeInstance);
							
							EndOfForEach:
							continue;
						}
					}
				}
			}
		}
		
		private void LoadAdControlAccessRights() {
			
			using (DirectoryEntry searchRootObject = new DirectoryEntry(_extendedRightsContainerPath)) {
				using (DirectorySearcher searcher = new DirectorySearcher(searchRootObject, "validAccesses=*", new string[] { "rightsguid", "displayname", "name", "validAccesses" })) {
					searcher.PageSize = 1000;
					
					using (SearchResultCollection results = searcher.FindAll()) {
						string guidString, name, displayName, validAccesses;
						ActiveDirectoryObjectAceTypeGuidType type;
						ActiveDirectoryAceTypeInstance aceTypeInstance;

						foreach (SearchResult searchResult in results) {
							guidString = (new Guid(searchResult.Properties["rightsguid"][0].ToString())).ToString();
							name = searchResult.Properties["name"][0].ToString();
							displayName = searchResult.Properties["displayname"][0].ToString();
							validAccesses = searchResult.Properties["validAccesses"][0].ToString();

							switch (validAccesses) {
								case "8":
									type = ActiveDirectoryObjectAceTypeGuidType.ValidatedWrite;
									break;
									
								case "48":
									type = ActiveDirectoryObjectAceTypeGuidType.PropertySet;
									break;
								
								case "256":
									type = ActiveDirectoryObjectAceTypeGuidType.ExtendedRight;
									break;
									
								default:
									goto EndOfForEach;
							}

							aceTypeInstance = new ActiveDirectoryAceTypeInstance(guidString, name, displayName, type);
							aceTypeInstance.DomainName = _domain;

							if (type == ActiveDirectoryObjectAceTypeGuidType.PropertySet) {
								aceTypeInstance.PropertySetGuid = guidString;
							}
							
							_adAceTypeList.Add(aceTypeInstance);

							EndOfForEach:
							continue;
						}
					}
				}
			}
		}



		internal static List<ActiveDirectoryAceTypeInstance> LookupPropertiesByPropertySetGuid(string propertySetGuid) {
			return LookupPropertiesByPropertySetGuid(propertySetGuid, null);
		}
		
		internal static List<ActiveDirectoryAceTypeInstance> LookupPropertiesByPropertySetGuid(string propertySetGuid, string domainName) {

			return LookupAceType(
				ObjectAceTypeGuidConverterLookupType.ByPropertySetGuid,
				StringToRegex(propertySetGuid),
				new ActiveDirectoryObjectAceTypeGuidType[] { ActiveDirectoryObjectAceTypeGuidType.Property },
				-1,
				domainName
			);
		}

		internal static List<ActiveDirectoryAceTypeInstance> LookupByGuid(string guid) {
			return LookupByGuid(
				guid, 
				new ActiveDirectoryObjectAceTypeGuidType[] { 
					ActiveDirectoryObjectAceTypeGuidType.Property,
					ActiveDirectoryObjectAceTypeGuidType.PropertySet,
					ActiveDirectoryObjectAceTypeGuidType.ValidatedWrite,
					ActiveDirectoryObjectAceTypeGuidType.ExtendedRight,
					ActiveDirectoryObjectAceTypeGuidType.ClassObject
				}
			);
		}

		internal static List<ActiveDirectoryAceTypeInstance> LookupByGuid(string guid, ActiveDirectoryObjectAceTypeGuidType[] types) {
			return LookupAceType(
				ObjectAceTypeGuidConverterLookupType.ByGuid, 
				StringToRegex(guid), 
				types,
				-1,
				null
			);
		}

		internal static List<ActiveDirectoryAceTypeInstance> LookupByName(string name) {
			return LookupByName(
				name, 
				new ActiveDirectoryObjectAceTypeGuidType[] { 
					ActiveDirectoryObjectAceTypeGuidType.Property,
					ActiveDirectoryObjectAceTypeGuidType.PropertySet,
					ActiveDirectoryObjectAceTypeGuidType.ValidatedWrite,
					ActiveDirectoryObjectAceTypeGuidType.ExtendedRight,
					ActiveDirectoryObjectAceTypeGuidType.ClassObject
				}
			);
		}

		internal static List<ActiveDirectoryAceTypeInstance> LookupByName(string name, ActiveDirectoryObjectAceTypeGuidType[] types) {
			return LookupAceType(
				ObjectAceTypeGuidConverterLookupType.ByName, 
				StringToRegex(name), 
				types, 
				-1,
				null
			);
		}

		internal static List<ActiveDirectoryAceTypeInstance> LookupByDisplayName(string displayName) {
			return LookupByDisplayName(
				displayName, 
				new ActiveDirectoryObjectAceTypeGuidType[] { 
					ActiveDirectoryObjectAceTypeGuidType.Property,
					ActiveDirectoryObjectAceTypeGuidType.PropertySet,
					ActiveDirectoryObjectAceTypeGuidType.ValidatedWrite,
					ActiveDirectoryObjectAceTypeGuidType.ExtendedRight,
					ActiveDirectoryObjectAceTypeGuidType.ClassObject
				}
			);
		}

		internal static List<ActiveDirectoryAceTypeInstance> LookupByDisplayName(string displayName, ActiveDirectoryObjectAceTypeGuidType[] types) {
			return LookupAceType(
				ObjectAceTypeGuidConverterLookupType.ByDisplayName, 
				StringToRegex(displayName), 
				types, 
				-1,
				null
			);
		}

		internal static ActiveDirectoryAceTypeInstance LookupFirstByGuid(string guid) {
			return LookupFirstByGuid(
				guid, 
				new ActiveDirectoryObjectAceTypeGuidType[] { 
					ActiveDirectoryObjectAceTypeGuidType.Property,
					ActiveDirectoryObjectAceTypeGuidType.PropertySet,
					ActiveDirectoryObjectAceTypeGuidType.ValidatedWrite,
					ActiveDirectoryObjectAceTypeGuidType.ExtendedRight,
					ActiveDirectoryObjectAceTypeGuidType.ClassObject
				}
			);
		}

		internal static ActiveDirectoryAceTypeInstance LookupFirstByGuid(string guid, ActiveDirectoryObjectAceTypeGuidType[] types) {
			List<ActiveDirectoryAceTypeInstance> list = LookupAceType(
				ObjectAceTypeGuidConverterLookupType.ByGuid, 
				StringToRegex(guid), 
				types,
				1,
				null
			);

			if (list.Count < 1) {
				return null;
			}
			else {
				return list[0];
			}
		}

		internal static ActiveDirectoryAceTypeInstance LookupFirstByName(string name) {
			return LookupFirstByName(
				name, 
				new ActiveDirectoryObjectAceTypeGuidType[] { 
					ActiveDirectoryObjectAceTypeGuidType.Property,
					ActiveDirectoryObjectAceTypeGuidType.PropertySet,
					ActiveDirectoryObjectAceTypeGuidType.ValidatedWrite,
					ActiveDirectoryObjectAceTypeGuidType.ExtendedRight,
					ActiveDirectoryObjectAceTypeGuidType.ClassObject
				}
			);
		}

		internal static ActiveDirectoryAceTypeInstance LookupFirstByName(string name, ActiveDirectoryObjectAceTypeGuidType[] types) {
			List<ActiveDirectoryAceTypeInstance> list = LookupAceType(
				ObjectAceTypeGuidConverterLookupType.ByName, 
				StringToRegex(name), 
				types, 
				1,
				null
			);

			if (list.Count < 1) {
				return null;
			}
			else {
				return list[0];
			}
		}

		internal static ActiveDirectoryAceTypeInstance LookupFirstByDisplayName(string displayName) {
			return LookupFirstByDisplayName(
				displayName, 
				new ActiveDirectoryObjectAceTypeGuidType[] { 
					ActiveDirectoryObjectAceTypeGuidType.Property,
					ActiveDirectoryObjectAceTypeGuidType.PropertySet,
					ActiveDirectoryObjectAceTypeGuidType.ValidatedWrite,
					ActiveDirectoryObjectAceTypeGuidType.ExtendedRight,
					ActiveDirectoryObjectAceTypeGuidType.ClassObject
				}
			);
		}
		
		internal static bool TryLookupFirstByDisplayName(string displayName, ActiveDirectoryObjectAceTypeGuidType[] types, out ActiveDirectoryAceTypeInstance typeInstance) {
			typeInstance = LookupFirstByDisplayName(displayName, types);
			
			if (typeInstance != null) { return true; }
			else { return false; }
		}
		
		internal static ActiveDirectoryAceTypeInstance LookupFirstByDisplayName(string displayName, ActiveDirectoryObjectAceTypeGuidType[] types) {
			List<ActiveDirectoryAceTypeInstance> list = LookupAceType(
				ObjectAceTypeGuidConverterLookupType.ByDisplayName, 
				StringToRegex(displayName), 
				types, 
				1,
				null
			);
			
			if (list.Count < 1) {
				return null;
			}
			else {
				return list[0];
			}
		}


		internal static Regex StringToRegex(string searchString) {
			return new Regex(String.Format("^{0}$", searchString.Replace("*", ".*").Replace("?", ".")), RegexOptions.IgnoreCase);
		}
		
		internal static List<ActiveDirectoryAceTypeInstance> LookupAceType(ObjectAceTypeGuidConverterLookupType lookupType, Regex searchRegex, ActiveDirectoryObjectAceTypeGuidType[] typesToInclude, int maxResults, string domainName) {
			return LookupAceType(lookupType, searchRegex, typesToInclude, maxResults, domainName, false);
		}
		
		internal static List<ActiveDirectoryAceTypeInstance> PrepareAceTypeListForAuthZ(List<ActiveDirectoryAceTypeInstance> originalList) {

			List<ActiveDirectoryAceTypeInstance> newList = new List<ActiveDirectoryAceTypeInstance>();
			string lastParentPropertySetGuid = Guid.Empty.ToString();

			foreach (ActiveDirectoryAceTypeInstance currentInstance in originalList) {

				if (currentInstance.ObjectType == ActiveDirectoryObjectAceTypeGuidType.PropertySet) {
					// This is a PropertySet, so track its GUID (this works because the list is already
					// sorted by PropertySet, ObjectTypeListLevel):
					lastParentPropertySetGuid = currentInstance.AceTypeGuid;
				}
				else if (currentInstance.ObjectType == ActiveDirectoryObjectAceTypeGuidType.Property && currentInstance.ObjectTypeListLevel > 1 && currentInstance.PropertySetGuid != lastParentPropertySetGuid) {

					ActiveDirectoryAceTypeInstance propertySetInstance = LookupFirstByGuid(currentInstance.PropertySetGuid, new ActiveDirectoryObjectAceTypeGuidType[] { ActiveDirectoryObjectAceTypeGuidType.PropertySet });
					if (propertySetInstance != null) { 
						newList.Add(propertySetInstance); 
					}
					else {
						// This means the property has a property set, but the property set couldn't be looked up. The AuthZ call doesn't
						// care about friendly names, though, so we'll create a new instance that has the GUID and ObjectTypeListLevel set
						
						// Now that I think about it, the LookupFirstByGuid() isn't necessary above, and this can be done instead:
						newList.Add(new ActiveDirectoryAceTypeInstance(
							currentInstance.PropertySetGuid,
							"", // Name doesn't matter; users won't see this
							"", // DisplayName doesn't matter
							ActiveDirectoryObjectAceTypeGuidType.PropertySet, // Doesn't matter, either
							1,  // This matters; it's the object level, which is always 1 for PropertySets
							Guid.Empty
						));
					}

					// Set this so another property in this propertyset won't cause another entry to be added to newList:
					lastParentPropertySetGuid = currentInstance.PropertySetGuid;
				}
				newList.Add(currentInstance);
			}
			
			return newList;
		}

		internal static List<ActiveDirectoryAceTypeInstance> LookupAceType(ObjectAceTypeGuidConverterLookupType lookupType, Regex searchRegex, ActiveDirectoryObjectAceTypeGuidType[] typesToInclude, int maxResults, string domainName, bool includeParentPropertySet) {

			// includeParentPropertySet is used for building OBJECT_TYPE_LIST for AuthZ checks. It means when you
			// come across a matching Property, make sure it's parent PropertySet (if it has one) is also included,
			// even if whatever property being checked doesn't pass the test

			List<ActiveDirectoryAceTypeInstance> matchingInstances = new List<ActiveDirectoryAceTypeInstance>();
			bool lookupTypePassed;
			
			var objectAceTypeGuidConverter = GetObjectAceTypeGuidConverter(domainName);
			if (objectAceTypeGuidConverter == null) { return null; }
			foreach (ActiveDirectoryAceTypeInstance currentInstance in objectAceTypeGuidConverter._adAceTypeList) {

				lookupTypePassed = false;

				switch (lookupType) {
					case ObjectAceTypeGuidConverterLookupType.ByGuid:
						if (searchRegex.Match(currentInstance.AceTypeGuid).Success) { lookupTypePassed = true; }
						break;
					
					case ObjectAceTypeGuidConverterLookupType.ByName:
						if (searchRegex.Match(currentInstance.Name).Success) { lookupTypePassed = true; }
						break;
						
					case ObjectAceTypeGuidConverterLookupType.ByDisplayName:
						if (searchRegex.Match(currentInstance.DisplayName).Success) { lookupTypePassed = true; }
						break;

					case ObjectAceTypeGuidConverterLookupType.ByPropertySetGuid:
						if (searchRegex.Match(currentInstance.PropertySetGuid).Success) { lookupTypePassed = true; }
						break;

					default:
						throw new Exception("Unknown lookup type");
				}


				if (lookupTypePassed) {
					// Get the instances from that key and see if they are of an acceptable type
					foreach (ActiveDirectoryObjectAceTypeGuidType currentType in typesToInclude) {
						if (currentType == currentInstance.ObjectType) {
							matchingInstances.Add(currentInstance);
							break;
						}
					}

					if (maxResults > 0 && matchingInstances.Count >= maxResults) { break; }
				}
			}
			
			return matchingInstances;
		}
	}
	
	internal enum ObjectAceTypeGuidConverterLookupType {
		ByGuid,
		ByName,
		ByDisplayName,
		ByPropertySetGuid
	}

	public enum ActiveDirectoryObjectAceTypeGuidType {
		PropertySet,
		Property,
		ClassObject,
		ExtendedRight,
		ValidatedWrite
	}

}