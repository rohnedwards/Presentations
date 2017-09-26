namespace ROE.PowerShellAccessControl {
	public class AdaptedCommonAce : AdaptedAce {
		
		new internal readonly QualifiedAce _aceObject;
		GetAceDisplayOptions _accessMaskDisplayOptions;
		
		internal AdaptedCommonAce(QualifiedAce aceObject, AdaptedSecurityDescriptor sdObject, string inheritedFrom) : this(aceObject, sdObject, inheritedFrom, 0) {
		}
		
		internal AdaptedCommonAce(QualifiedAce aceObject, AdaptedSecurityDescriptor sdObject, string inheritedFrom, GetAceDisplayOptions displayOptions) : base(aceObject, sdObject, inheritedFrom) {
			// Masks the base _aceObject
			this._aceObject = aceObject;
			this._accessMaskDisplayOptions = displayOptions;
		}
		
/*
		public bool? AreAclRulesProtected {
			get {
				if (base._parentSdObject == null) { return null; }
			
				switch (this.AceType) {
					case "Allow":
					case "Deny":
						return base._parentSdObject.AreAccessRulesProtected;
						
					case "Audit":
						return base._parentSdObject.AreAuditRulesProtected;
						
					default:
						return null;
				}
			}
		}
*/

		internal virtual AdaptedCommonAce CreateNewMergedAce(int accessMask, AppliesTo appliesTo) {
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
			
			CommonAce ace = new CommonAce(newAceFlags, this._aceObject.AceQualifier, accessMask, this._aceObject.SecurityIdentifier, this._aceObject.IsCallback, this._aceObject.GetOpaque());

			return new AdaptedCommonAce(ace, this._parentSdObject, this.InheritedFrom, this._accessMaskDisplayOptions);
		}

		public virtual string GetGroupingKey() {
			return String.Format("{0},{1},{2},{3},{4}", this.AceType, this.Principal, this.InheritedFrom, this.AuditFlags, (this._aceObject.PropagationFlags & PropagationFlags.NoPropagateInherit));
		}
		
		public string GetGroupingKey(bool groupByAccessMask) {
			// If true, add access mask to grouping key
			// If false, add Inheritance and Propagation flags to key
			
			if (groupByAccessMask) {
				return string.Format("{0},{1}", GetGroupingKey(), this.AccessMask.ToString());
			}
			else {
				return string.Format("{0},{1}", GetGroupingKey(), (this._aceObject.AceFlags & AceFlags.InheritanceFlags));
			}	
		}

			
		public PacPrincipal Principal {
			get {
				return this._parentSdObject != null ?
					this._parentSdObject.GetPrincipal(this._aceObject.SecurityIdentifier) : PacPrincipal.FromSid(this._aceObject.SecurityIdentifier);
			}
		}

		public virtual AccessMaskDisplay AccessMask {
			get { 
				return new AccessMaskDisplay(
					this._aceObject.AccessMask, 
					(this._parentSdObject != null ? this._parentSdObject.AccessRightType : typeof(int)),
					_accessMaskDisplayOptions
				);
			}
		}

		public override string ToString() {
			return ToString(50, false);
		}
		public string ToString(int width, bool wrap) {
			// 50 is minimum
			int typeLength = 8;
			int userLength = 19;
			int accessLength = 19;
			
			int extraWidth = width - (typeLength + userLength + accessLength + 4);  // 4 is for spaces b/w
			if (extraWidth > 0) {
				userLength += (int) Math.Round(extraWidth * .6);
				accessLength += (int) Math.Round(extraWidth * .4);
			}
			
			string formatter = string.Format("{{0, -{0}}}  {{1, -{1}}}  {{2, -{2}}}", typeLength, userLength, accessLength);
		
			StringBuilder typeSb = new StringBuilder(this.AceType);
			StringBuilder userSb = new StringBuilder(this.Principal.ToString());
			StringBuilder accessSb;
			if (this.AppliesTo.TestIsDefaultForObject()) {
				accessSb = new StringBuilder(this.AccessMask.ToString(GetAceDisplayOptions.None));
			}
			else {
				accessSb = new StringBuilder("Special");
			}
			
			StringBuilder finalString = new StringBuilder();
			while (true) {
				
				finalString.Append(string.Format(
					formatter, 
					NibbleAtString(typeSb, typeLength, wrap), 
					NibbleAtString(userSb, userLength, wrap), 
					NibbleAtString(accessSb, accessLength, wrap)
				));
				
				if (wrap == false || accessSb.Length == 0 && userSb.Length == 0 && typeSb.Length == 0) {
					break;
				}
				else {
					finalString.Append("\n");
				}
			}
			return finalString.ToString();
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