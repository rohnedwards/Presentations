namespace ROE.PowerShellAccessControl {
	public class AdaptedActiveDirectoryAce : AdaptedCommonAce {
		internal static readonly int AccessMaskWithObjectType = 0x1 | 0x2 | 0x8 | 0x10 | 0x20 | 0x100;
		GetAceDisplayOptions _accessMaskDisplayOptions;
		internal AdaptedActiveDirectoryAce(ObjectAce aceObject, AdaptedSecurityDescriptor sdObject, string inheritedFrom) : this(aceObject, sdObject, inheritedFrom, 0) {
		}

		internal AdaptedActiveDirectoryAce(ObjectAce aceObject, AdaptedSecurityDescriptor sdObject, string inheritedFrom, GetAceDisplayOptions displayOptions) : base(aceObject, sdObject, inheritedFrom, displayOptions) {
			this._accessMaskDisplayOptions = displayOptions;
		}

		internal override AdaptedCommonAce CreateNewMergedAce(int accessMask, AppliesTo appliesTo) {
			AceFlags newAceFlags = this._aceObject.AceFlags & (AceFlags.Inherited | AceFlags.AuditFlags);
			
			if ((appliesTo & Enums.AppliesTo.Object) != Enums.AppliesTo.Object) {
				newAceFlags |= AceFlags.InheritOnly;
			}
			if ((appliesTo & Enums.AppliesTo.ChildContainers) == Enums.AppliesTo.ChildContainers) {
				newAceFlags |= AceFlags.ContainerInherit;
			}
			if ((appliesTo & Enums.AppliesTo.ChildObjects) == Enums.AppliesTo.ChildObjects) {
				newAceFlags |= AceFlags.ObjectInherit;
			}
			
			ObjectAce ace = new ObjectAce(
				newAceFlags, 
				this._aceObject.AceQualifier, 
				accessMask, 
				this._aceObject.SecurityIdentifier, 
				this.ObjectAceFlags,
				this.ObjectAceType,
				this.InheritedObjectAceType,
				this._aceObject.IsCallback, 
				this._aceObject.GetOpaque()
			);

			return new AdaptedActiveDirectoryAce(ace, this._parentSdObject, this.InheritedFrom, this._accessMaskDisplayOptions);
		}

		public override AccessMaskDisplay AccessMask {
			get { 
				return new AccessMaskDisplay(
					this._aceObject.AccessMask, 
					(base._parentSdObject != null ? base._parentSdObject.AccessRightType : typeof(int)),
					((ObjectAce) base._aceObject).ObjectAceType,
					this._accessMaskDisplayOptions
				);
			}
		}

public static string GetObjectAceTypeString(Guid objectAceType, ActiveDirectoryObjectAceTypeGuidType[] types, bool includeTypeName) {
/*
  Takes a guid and performs a lookup. If includeTypeName is true, type name will be included in string, e.g.,
  'PropertyName Property' instead of just 'PropertyName'. If more than one result is returned, the strings will
  be joined with a coma to produce a single string.
*/

	List<string> stringList = new List<string>();

	StringBuilder sb = new StringBuilder();
	List<ActiveDirectoryAceTypeInstance> instances = ObjectAceTypeGuidConverter.LookupByGuid(objectAceType.ToString(), types);
	
	if (instances.Count == 0) {
		sb.Append(objectAceType.ToString());
		
		if (includeTypeName) {

			List<string> typesList = new List<string>();
			foreach (ActiveDirectoryObjectAceTypeGuidType currentType in types) {
				typesList.Add(currentType.ToString());
			}
			sb.Append(" ");
			sb.Append(String.Join("/", typesList.ToArray()));
		}

		stringList.Add(sb.ToString());
	}
	else {
		foreach (ActiveDirectoryAceTypeInstance aceTypeInstance in instances) {
			sb.Append(aceTypeInstance.DisplayName);
			
			if (includeTypeName) {
				sb.Append(String.Format(" {0}", aceTypeInstance.ObjectType.ToString()));
			}

			stringList.Add(sb.ToString());
			sb.Clear();
		}
	}

	return String.Join(", ", stringList.ToArray());
}

		public override string GetGroupingKey() {
			return String.Format("{0},{1},{2}", base.GetGroupingKey(), this.InheritedObjectAceType, this.ObjectAceType);
		}

/*
		public override string[] GetAccessMaskDisplayArray(RightsDictionaryViewType displayMode) {
			return AdaptedCommonAce.GetAccessMaskDisplayArray(displayMode, this._aceObject.AccessMask, typeof(ROE.PowerShellAccessControl.Enums.ActiveDirectoryRights), this.ObjectAceType).ToArray();
		}
*/
		public Guid ObjectAceType {
			get { return ((ObjectAce) base._aceObject).ObjectAceType; }
		}
	
		public Guid InheritedObjectAceType {
			get { return ((ObjectAce) base._aceObject).InheritedObjectAceType; }
		}

		public ObjectAceFlags ObjectAceFlags {
			get { return ((ObjectAce) base._aceObject).ObjectAceFlags; }
		}

	}
}



