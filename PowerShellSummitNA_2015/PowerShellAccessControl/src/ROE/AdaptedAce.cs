namespace ROE.PowerShellAccessControl {

	public class AdaptedAce {
	
		internal readonly GenericAce _aceObject;
		internal AdaptedSecurityDescriptor _parentSdObject;
		private readonly string _inheritedFrom;

		internal AdaptedAce(GenericAce aceObject, AdaptedSecurityDescriptor sdObject, string inheritedFrom) {
			this._aceObject = aceObject;
			this._parentSdObject = sdObject;
			this._inheritedFrom = inheritedFrom;
			
			if (aceObject is ObjectAce) {
				this._friendlyAppliesTo = new FriendlyAppliesTo(aceObject.InheritanceFlags, aceObject.PropagationFlags, sdObject.AccessRightType, ((ObjectAce) aceObject).InheritedObjectAceType);
			}
			else {
				this._friendlyAppliesTo = new FriendlyAppliesTo(aceObject.InheritanceFlags, aceObject.PropagationFlags, sdObject.AccessRightType, sdObject.IsContainer);
			}
		}

		private static GenericAceConverter _aceConverter;
		public static GenericAceConverter AceConverter {	
			get {
				return _aceConverter??
					 (_aceConverter = new GenericAceConverter());
			}
		}

		// The thinking here is that PS formatting system will show the display name from the PathInfo object.
		// If this object is sent to New-Ace/Add-Ace/Remove-Ace/etc, this PathInfo will be converted to a string,
		// and the ToString() method can be overloaded to return SdPath.
		public AdaptedSecurityDescriptorPathInformation Path {
			get {
				return this._parentSdObject != null ? this._parentSdObject._pathInfo : null;
			}
		}

		public object Owner {
			get { 
				return this._parentSdObject != null ? this._parentSdObject.Owner : null; 
			}
		}

		public object Group {
			get { 
				return this._parentSdObject != null ? this._parentSdObject.Group : null; 
			}
		}

		public string AceType {
			// A type converter will convert this string into an AceType
			get {
				
				if (this._aceObject is QualifiedAce) {
					QualifiedAce qualifiedAce = (QualifiedAce) this._aceObject;
						
					// Longest string is this: Audit SF (CB)
					// which is 13 characters. Let's make SB 16 to
					// give it a little extra room:
					StringBuilder aceType = new StringBuilder(16);
					switch (qualifiedAce.AceQualifier.ToString()) {
						case "AccessAllowed":
							aceType.Append("Allow");
							break;
							
						case "AccessDenied":
							aceType.Append("Deny");
							break;
							
						case "SystemAudit":
							aceType.Append("Audit ");
							if ((qualifiedAce.AuditFlags & AuditFlags.Success) != 0) { aceType.Append("S"); }
							else { aceType.Append(" "); }

							if ((qualifiedAce.AuditFlags & AuditFlags.Failure) != 0) { aceType.Append("F"); }
							else { aceType.Append(" "); }
							
							break;
					}
				
					if (qualifiedAce.IsCallback) {
						aceType.Append(" (CB)");
					}
				
					return aceType.ToString();
				}
				
				else {
					// Need work here
					return String.Format("Unknown ({0})", this._aceObject.AceType);
				}
			}
		}
	
		public bool IsInherited {
			get {
				return this._aceObject.IsInherited;
			}
		}
		
		public string InheritedFrom {
			get {
				if (this.IsInherited == false) {
					return "<not inherited>";
				}
			
				return this._inheritedFrom != null ? this._inheritedFrom : "Parent Object";
			}
		}
		
		private FriendlyAppliesTo _friendlyAppliesTo;
		public FriendlyAppliesTo AppliesTo { 
			get { return _friendlyAppliesTo; }
		}
/*	
		public AppliesTo AppliesTo {
			get {
				AppliesTo appliesTo = (AppliesTo) 0;

				if ((this._aceObject.InheritanceFlags & InheritanceFlags.ContainerInherit) == InheritanceFlags.ContainerInherit) {
					appliesTo |= AppliesTo.ChildContainers;
				}

				if ((this._aceObject.InheritanceFlags & InheritanceFlags.ObjectInherit) == InheritanceFlags.ObjectInherit) {
					appliesTo |= AppliesTo.ChildObjects;
				}

				if ((this._aceObject.PropagationFlags & PropagationFlags.InheritOnly) != PropagationFlags.InheritOnly) {
					appliesTo |= AppliesTo.Object;
				}

				if ((this._aceObject.PropagationFlags & PropagationFlags.NoPropagateInherit) == PropagationFlags.NoPropagateInherit) {
					appliesTo |= AppliesTo.DirectChildrenOnly;
				}

				return appliesTo;

			}
		}
*/		
		public AuditFlags AuditFlags {
			get { return this._aceObject.AuditFlags; }
		}

		public GenericAce GetBaseAceObject() {
			return this._aceObject;
		}

		public string GetInheritanceString() {
			if (_parentSdObject == null) { return null; }
			
			StringBuilder inheritanceString = new StringBuilder();
			
			if ((_parentSdObject.GetRequestedSecurityInformation() & SecurityInformation.Dacl) != 0) {
				inheritanceString.Append("DACL Inheritance ");
				
				if (_parentSdObject.AreAccessRulesProtected == true) {
					inheritanceString.Append("Disabled");
				}
				else {
					inheritanceString.Append("Enabled");
				}
			}
			

			if ((_parentSdObject.GetRequestedSecurityInformation() & SecurityInformation.Sacl) != 0) {
				if (inheritanceString.Length != 0) { inheritanceString.Append(", "); }

				inheritanceString.Append("SACL Inheritance ");
				
				if (_parentSdObject.AreAuditRulesProtected == true) {
					inheritanceString.Append("Disabled");
				}
				else {
					inheritanceString.Append("Enabled");
				}
				
			}
			return inheritanceString.ToString();
		}
		
	}
}