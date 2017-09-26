
namespace ROE.PowerShellAccessControl {
	public class AccessMaskDisplay {
		#region Constructors
		public AccessMaskDisplay(int accessMask, Type accessRightType) : this(accessMask, accessRightType, Guid.Empty, GetAceDisplayOptions.None) { }
		public AccessMaskDisplay(int accessMask, Type accessRightType, Guid objectAceType) : this(accessMask, accessRightType, objectAceType, GetAceDisplayOptions.None) { }
		public AccessMaskDisplay(int accessMask, Type accessRightType, GetAceDisplayOptions displayOptions) : this(accessMask, accessRightType, Guid.Empty, displayOptions) { }
		public AccessMaskDisplay(int accessMask, Type accessRightType, Guid objectAceType, GetAceDisplayOptions displayOptions) {
			this.AccessMask = accessMask;
			this.AccessRightType = accessRightType;
			this.ObjectAceType = objectAceType;
			this.DisplayOptions = displayOptions;
		}
		#endregion

		public const string NoAccessString = "None";

		public Int32 AccessMask { get; set; }
		public Type AccessRightType { get; set; }
		public Guid ObjectAceType { get; set; }
		public GetAceDisplayOptions DisplayOptions { get; set; }

		public int GetGenericRights() {
			return GetGenericRights(this.AccessMask);
		}
		
		public int RemoveGenericRights() {
			return RemoveGenericRights(this.AccessMask);
		}
		
		public int RemoveUndefinedRights() {
			return RemoveUndefinedRights(this.AccessMask, this.AccessRightType);
		}
		
		public int RemoveUndefinedRights(int accessMask) {
			return RemoveUndefinedRights(accessMask, this.AccessRightType);
		}
		
		public int GetUndefinedRights() {
			return GetUndefinedRights(this.AccessMask, this.AccessRightType);
		}
		
		public int GetUndefinedRights(int accessMask) {
			return GetUndefinedRights(accessMask, this.AccessRightType);
		}
		
		public int GetKnownSpecificAccessMask() {
			return GetKnownSpecificAccessMask(this.AccessMask, this.AccessRightType);
		}
		
		public int GetKnownSpecificAccessMask(int accessMask) {
			return GetKnownSpecificAccessMask(accessMask, this.AccessRightType);
		}
		
		public int MapGenericRightsToSpecificRights(int accessMask) {
			return MapGenericRightsToSpecificRights(accessMask, this.AccessRightType);
		}
		
		public int MapGenericRightsToSpecificRights() {
			return MapGenericRightsToSpecificRights(this.AccessMask, this.AccessRightType);
		}

		public string GetAccessRightString(int accessMask) {
			
			if (this.AccessRightType == null || !(this.AccessRightType.IsDefined(typeof(FlagsAttribute), false))) {
				// Without a flags enumeration, this function has no work to do. Just return the access mask:
				return accessMask.ToString();
			}
			
			RightsDictionaryViewType viewType;
			if ((this.DisplayOptions & GetAceDisplayOptions.ShowDetailedRights) != 0) {
				viewType = RightsDictionaryViewType.NoCombinedRights;
			}
			else {
				viewType = RightsDictionaryViewType.Default;
			}
			
			SortedList<int, string> rightsDictionary = GetRightsDictionary(this.AccessRightType, viewType);

			int workingAccessMask = accessMask;
			int adObjectTypeAccessMask = 0;
			
			if (this.AccessRightType == typeof(Enums.ActiveDirectoryRights) && (this.DisplayOptions & GetAceDisplayOptions.DontLookupAdRights) == 0) {
				// Take out ObjectAce specific rights from the rights dictionary translations step.
				// Translating that (even if ObjectAceType is Guid.Empty) happens later
				if (this.ObjectAceType != Guid.Empty) {
					workingAccessMask = 0;
				}
				else {
					workingAccessMask &= ~(AdaptedActiveDirectoryAce.AccessMaskWithObjectType);
				}
				
				adObjectTypeAccessMask = accessMask & AdaptedActiveDirectoryAce.AccessMaskWithObjectType;
			}

			// We got a sorted list of rights; now we need to work through each one and see if
			// their numeric access masks are contained in the accessMask parameter. Work backwards
			// so we can start with the larger access masks in the list. If a matching mask is found,
			// xor the working access mask with the matching one so permission strings won't be duplicated.
			List<string> rightsList = new List<string>();
			for (int i = rightsDictionary.Count - 1; i >= 0; --i) {
				if ((rightsDictionary.Keys[i] & workingAccessMask) == rightsDictionary.Keys[i]) {
					workingAccessMask ^= rightsDictionary.Keys[i];
					rightsList.Add(rightsDictionary.Values[i]);
				}
				
				if (workingAccessMask == 0) { break; }
			}

			rightsList.Reverse();
			
			if (workingAccessMask != 0) {
				// Permissions left over...
				rightsList.Add(string.Format("Special ({0})", workingAccessMask));
			}
			
			// That took care of simple rights. If this is an AD object access mask, though, we need to
			// check to see if there were any ObjectType rights, and if so, translate them to a readable
			// form:
			if (adObjectTypeAccessMask > 0) {
				List<ActiveDirectoryObjectAceTypeGuidType[]> types = new List<ActiveDirectoryObjectAceTypeGuidType[]>();
				List<string> actionStrings = new List<string>();
				
				// Check to see if access mask includes Create and/or Delete child rights
				switch ((Enums.ActiveDirectoryRights) adObjectTypeAccessMask & Enums.ActiveDirectoryRights.CreateAndDeleteChild) {
					case Enums.ActiveDirectoryRights.CreateChild:
						actionStrings.Add("Create");
						break;
					case Enums.ActiveDirectoryRights.DeleteChild:
						actionStrings.Add("Delete");
						break;
					case Enums.ActiveDirectoryRights.CreateAndDeleteChild:
						actionStrings.Add("Create and Delete");
						break;
				}
				if (actionStrings.Count != types.Count) {
					types.Add(new ActiveDirectoryObjectAceTypeGuidType[] { ActiveDirectoryObjectAceTypeGuidType.ClassObject});
				}
				
				// Check to see if access mask includes Read and/or Write properties
				switch ((Enums.ActiveDirectoryRights) adObjectTypeAccessMask & Enums.ActiveDirectoryRights.ReadAndWriteProperty) {
					case Enums.ActiveDirectoryRights.ReadProperty:
						actionStrings.Add("Read");
						break;
					case Enums.ActiveDirectoryRights.WriteProperty:
						actionStrings.Add("Write");
						break;
					case Enums.ActiveDirectoryRights.ReadAndWriteProperty:
						actionStrings.Add("Read and Write");
						break;
				}
				if (actionStrings.Count != types.Count) {
					types.Add(new ActiveDirectoryObjectAceTypeGuidType[] { ActiveDirectoryObjectAceTypeGuidType.Property, ActiveDirectoryObjectAceTypeGuidType.PropertySet });
				}
			
				// Check to see if access mask includes extended right
				if ((adObjectTypeAccessMask & (int) Enums.ActiveDirectoryRights.ExtendedRight) != 0) {
					actionStrings.Add("Perform");
					types.Add(new ActiveDirectoryObjectAceTypeGuidType[] { ActiveDirectoryObjectAceTypeGuidType.ExtendedRight });
				}

				// Check to see if access mask includes validated write
				if ((adObjectTypeAccessMask & (int) Enums.ActiveDirectoryRights.ValidatedWrite) != 0) {
					actionStrings.Add("Perform");
					types.Add(new ActiveDirectoryObjectAceTypeGuidType[] { ActiveDirectoryObjectAceTypeGuidType.ValidatedWrite });
				}
				
				if (types.Count != actionStrings.Count) {
					throw new Exception ("types count doesn't match actionStrings count");			
				}

				List<ActiveDirectoryAceTypeInstance> lookupResults;
				StringBuilder currentDisplaySb = new StringBuilder(60);
				for (int i = 0; i < types.Count; i++) {
					if (this.ObjectAceType == Guid.Empty) {
						// No limited GUID, so applies to all of types[i]
						foreach (ActiveDirectoryObjectAceTypeGuidType currentType in types[i]) {
							currentDisplaySb.AppendFormat("{0} All ", actionStrings[i]);
							
							if (currentType == ActiveDirectoryObjectAceTypeGuidType.Property) { currentDisplaySb.Append("Properties"); }
							else { currentDisplaySb.AppendFormat("{0}s", currentType.ToString()); }
							
							rightsList.Add(currentDisplaySb.ToString());
							currentDisplaySb.Clear();
						}
					}
					else {
						lookupResults = ObjectAceTypeGuidConverter.LookupByGuid(this.ObjectAceType.ToString(), types[i]);
						if (lookupResults.Count > 0) {
							foreach (ActiveDirectoryAceTypeInstance aceTypeInstance in lookupResults) {
								currentDisplaySb.AppendFormat("{0} {1} {2}", actionStrings[i], aceTypeInstance.DisplayName, aceTypeInstance.ObjectType);

								rightsList.Add(currentDisplaySb.ToString());
								currentDisplaySb.Clear();
							}
						}
						else if ( (this.DisplayOptions & GetAceDisplayOptions.ShowDetailedRights) != 0) {
							// LookupByGuid() wasn't able to translate the guid into a friendly name and user want's detailed rights
							foreach (ActiveDirectoryObjectAceTypeGuidType currentType in types[i]) {
								currentDisplaySb.AppendFormat("{0} Unknown {1} ({2})", actionStrings[i], currentType, this.ObjectAceType);

								rightsList.Add(currentDisplaySb.ToString());
								currentDisplaySb.Clear();
							}
						}
					}
				}

			}
			
			if ((this.DisplayOptions & GetAceDisplayOptions.DontLookupAdRights) != 0 && this.AccessRightType == typeof(Enums.ActiveDirectoryRights) && this.ObjectAceType != Guid.Empty) {
				// AD rights weren't looked up, so make sure to show GUID in display
				return string.Format("{0} ({1})", string.Join(", ", rightsList.ToArray()), this.ObjectAceType.ToString());
			}
			else {
				return string.Join(", ", rightsList.ToArray());
			}
		}

		public string ToString(GetAceDisplayOptions displayOptions) {

			int workingAccessMask = this.AccessMask;
			
			StringBuilder sb = new StringBuilder(50);

			if ((displayOptions & GetAceDisplayOptions.DontMapGenericRights) == 0) {
				workingAccessMask = this.MapGenericRightsToSpecificRights(workingAccessMask);
			}
			
			// If generic rights were mapped, this should be 0 
			int genericRights = GetGenericRights(workingAccessMask);
			if (genericRights != 0) {
				workingAccessMask = RemoveGenericRights(workingAccessMask);
			}
			
			int undefinedRights = GetUndefinedRights(workingAccessMask);
			if (undefinedRights != 0) {
				workingAccessMask = RemoveUndefinedRights(workingAccessMask);
			}
			
			if (workingAccessMask != 0) {
				sb.Append(GetAccessRightString(workingAccessMask));
			}
			
			if (genericRights != 0) {
				if (sb.Length > 0) {
					sb.Append(", ");
				}
				sb.Append(Enum.Format(typeof(GenericAceRights), genericRights, "G"));
			}
			
			if (undefinedRights != 0 && (displayOptions & GetAceDisplayOptions.HideUndefinedRights) == 0) {
				if (sb.Length > 0) {
					sb.Append(", ");
				}
				sb.Append("Unknown (");
				sb.Append(undefinedRights);
				sb.Append(")");
			}
			
			if (sb.Length == 0) { sb.Append(AccessMaskDisplay.NoAccessString); }

			if ((displayOptions & GetAceDisplayOptions.IncludeNumericAccessMask) != 0) {
				sb.AppendFormat(" [{0}]", this.AccessMask);
			}

			return sb.ToString();
		}
		
		public override string ToString() {
			return ToString(this.DisplayOptions);
		}
		
		#region Static helpers
		private static Dictionary<Type, int> AllKnownRightsDictionary = new Dictionary<Type, int>();
		public static int GetAllKnownRightsForAccessMaskEnumeration(Type accessMaskEnum) {
			if (accessMaskEnum == null || !(accessMaskEnum.IsDefined(typeof(FlagsAttribute), false))) {
				return 0;
			}
			
			if (!AllKnownRightsDictionary.ContainsKey(accessMaskEnum)) {
				string[] validNames = Enum.GetNames(accessMaskEnum);
				
				object fullControl = Enum.Parse(accessMaskEnum, String.Join(", ", validNames));
				int fullControlNumeric = Convert.ToInt32(fullControl);

				AllKnownRightsDictionary[accessMaskEnum] = fullControlNumeric;
			}
			
			return AllKnownRightsDictionary[accessMaskEnum];
		}

		private static int GetGenericRights(int accessMask) {
			return accessMask & -268435456;
		}
		private static int RemoveGenericRights(int accessMask) {
			return accessMask & ~(-268435456);
		}

		private static int RemoveUndefinedRights(int accessMask, Type accessRightType) {
			return accessMask & GetAllKnownRightsForAccessMaskEnumeration(accessRightType);
		}
		
		private static int GetUndefinedRights(int accessMask, Type accessRightType) {
			return RemoveGenericRights(accessMask) & ~GetAllKnownRightsForAccessMaskEnumeration(accessRightType);
		}

		private static int GetKnownSpecificAccessMask(int accessMask, Type accessRightType) {
			return RemoveUndefinedRights(accessMask, accessRightType) & RemoveGenericRights(accessMask);
		}

		private static int MapGenericRightsToSpecificRights(int accessMask, Type accessRightType) {
			
			if (GetGenericRights(accessMask) == 0) { 
				// No generic rights, so no mapping needed
				return accessMask; 
			}
			
			GenericAceRights genericRights = (GenericAceRights) (GetGenericRights(accessMask));
			accessMask = RemoveGenericRights(accessMask);

			var PropertyInfo = typeof(GenericRightsMapper).GetProperty(accessRightType.Name);
			if (PropertyInfo != null) {
				GenericMapping GenericMapping = (GenericMapping) PropertyInfo.GetValue(null, null);

				if ((genericRights & GenericAceRights.GenericAll) != 0)
					accessMask |= GenericMapping.GenericAll;
				if ((genericRights & GenericAceRights.GenericExecute) != 0)
					accessMask |= GenericMapping.GenericExecute;
				if ((genericRights & GenericAceRights.GenericRead) != 0)
					accessMask |= GenericMapping.GenericRead;
				if ((genericRights & GenericAceRights.GenericWrite) != 0)
					accessMask |= GenericMapping.GenericWrite;
			}
			else {
				// Can't map rights, so add generic rights back to the mask that's had undefined rights removed
				accessMask |= (int) genericRights;
			}
			
			return accessMask;
		}

 		private static Dictionary<Type, SortedList<int, string>> NoCombinedRightsDictionaries = new Dictionary<Type, SortedList<int, string>>();
 		private static Dictionary<Type, SortedList<int, string>> CombinedRightsDictionaries = new Dictionary<Type, SortedList<int, string>>();

		internal static SortedList<int, string> GetRightsDictionary(Type type, RightsDictionaryViewType viewType) {

			if (type == null | !(type.IsDefined(typeof(FlagsAttribute), false))) {
				// Not a flags enumeration, so return empty dictionary
				throw new Exception("Can't create rights dictionary: type must be flags enumeration");
			}
			
			Dictionary<Type, SortedList<int, string>> workingDictionary;
			
			switch (viewType) {
				case RightsDictionaryViewType.NoCombinedRights:
					workingDictionary = NoCombinedRightsDictionaries;
					break;
					
				default:
					workingDictionary = CombinedRightsDictionaries;
					break;
			}

			if (!(workingDictionary.ContainsKey(type))) {

				SortedList<int, string> dict = new SortedList<int, string>();
				
				// Go through each enum value (use GetNames instead of GetValues b/c it will return unique strings
				// when values are shared--see FileSytemRights enum for an example)
				foreach (string enumName in Enum.GetNames(type)) {
					int intValue = Convert.ToInt32(Enum.Parse(type, enumName));
					
					if (viewType == RightsDictionaryViewType.NoCombinedRights && ((intValue & (intValue - 1)) != 0)) {
						// Not a power of 2, so continue to next iteration
						continue;
					}
					
					if (dict.ContainsKey(intValue)) {
						dict[intValue] += @"/" + enumName;
					}
					else {
						dict.Add(intValue, enumName);
					}	
				}
				
				workingDictionary.Add(type, dict);
			}
			
			return workingDictionary[type];
		}

		#endregion
	}

}