namespace ROE.PowerShellAccessControl {

	public class PacAuthorizationRule : AuthorizationRule {

		protected PacAuthorizationRule(
			PacPrincipal principal, 
			int accessMask, 
			bool isInherited, 
			AppliesTo appliesTo, 
			Type accessRightType
		) : base (principal.SecurityIdentifier, accessMask, isInherited, AppliesToToInheritanceFlags(appliesTo), AppliesToToPropagationFlags(appliesTo)) {
		
			_accessRightType = accessRightType;
			this.Principal = principal;
		}

		protected PacAuthorizationRule(
			QualifiedAce qualifiedAce,
			Type accessRightType
		) : base (qualifiedAce.SecurityIdentifier, qualifiedAce.AccessMask, qualifiedAce.IsInherited, qualifiedAce.InheritanceFlags, qualifiedAce.PropagationFlags) {
			_accessRightType = accessRightType;
			this.Principal = new PacPrincipal(qualifiedAce.SecurityIdentifier);
		}

		public PacPrincipal Principal { get; private set; }

		private int _accessMask;
		public void SetAccessRightType(Type accessRightType) {
			_accessRightType = accessRightType;
			_accessMaskDisplay = null;
		}
		public Type GetAccessRightType() {
			return _accessRightType;
		}
		private Type _accessRightType;
		
		public AccessMaskDisplay Rights {
			get {
				return _accessMaskDisplay ??
					(_accessMaskDisplay = new AccessMaskDisplay(base.AccessMask, _accessRightType));
			}
		}
		protected AccessMaskDisplay _accessMaskDisplay;
	
		public AppliesTo AppliesTo { 
			get {
				AppliesTo appliesTo = 0;
				
				if ((this.InheritanceFlags & InheritanceFlags.ContainerInherit) != 0) {
					appliesTo |= AppliesTo.ChildContainers;
				}

				if ((this.InheritanceFlags & InheritanceFlags.ObjectInherit) != 0) {
					appliesTo |= AppliesTo.ChildObjects;
				}
				
				if ((this.PropagationFlags & PropagationFlags.InheritOnly) == 0) {
					appliesTo |= AppliesTo.Object;
				}
				
				if ((this.PropagationFlags & PropagationFlags.NoPropagateInherit) != 0) {
					appliesTo |= AppliesTo.DirectChildrenOnly;
				}
				
				return appliesTo;
			}
		}
			
	
		#region Hide base members
//		new internal IdentityReference IdentityReference { get { return base.IdentityReference; } }
//		new internal InheritanceFlags InheritanceFlags { get { return base.InheritanceFlags; } }
//		new internal PropagationFlags PropagationFlags { get { return base.PropagationFlags; } }
		#endregion
	
		private static AceFlagsConverter AceFlagsConverter = new AceFlagsConverter();
		private static InheritanceFlags AppliesToToInheritanceFlags(AppliesTo appliesTo) {
			InheritanceFlags returnFlags = InheritanceFlags.None;
			
			if ((appliesTo & AppliesTo.ChildContainers) != 0) {
				returnFlags |= InheritanceFlags.ContainerInherit;
			}

			if ((appliesTo & AppliesTo.ChildObjects) != 0) {
				returnFlags |= InheritanceFlags.ObjectInherit;
			}
			
			return returnFlags;
		}

		private static PropagationFlags AppliesToToPropagationFlags(AppliesTo appliesTo) {
			PropagationFlags returnFlags = PropagationFlags.None;
			
			if ((appliesTo & AppliesTo.Object) == 0) {
				returnFlags |= PropagationFlags.InheritOnly;
			}

			if ((appliesTo & AppliesTo.DirectChildrenOnly) != 0) {
				returnFlags |= PropagationFlags.NoPropagateInherit;
			}
			
			return returnFlags;
		}

		public override string ToString() {
			return string.Format("{0} {1} ({2})", this.Principal, this.Rights, this.AppliesTo);
		}
	}


    public class PacAccessRule : PacAuthorizationRule {

		public PacAccessRule( PacPrincipal principal, int accessMask, AppliesTo appliesTo, AccessControlType accessControlType, Type accessRightType ) :
			this( principal, accessMask, false, appliesTo, accessControlType, accessRightType ) { }
			
		public PacAccessRule( PacPrincipal principal, int accessMask, AppliesTo appliesTo, AccessControlType accessControlType ) :
			this( principal, accessMask, false, appliesTo, accessControlType, typeof(int) ) { }
		
		public PacAccessRule( QualifiedAce qualifiedAce, Type accessRightType ) :
			base( qualifiedAce, accessRightType ) { 
		
			switch (qualifiedAce.AceQualifier) {
				case AceQualifier.AccessAllowed:
					this.AccessControlType = AccessControlType.Allow;
					break;
					
				case AceQualifier.AccessDenied:
					this.AccessControlType = AccessControlType.Deny;
					break;
					
				default:
					throw new Exception("qualifiedAce is not an Allow or Deny ACE");
			}
		}

		public PacAccessRule( QualifiedAce qualifiedAce ) :
			this( qualifiedAce, typeof(int) ) { }

        internal PacAccessRule( PacPrincipal principal, int accessMask, bool isInherited, AppliesTo appliesTo, AccessControlType accessControlType, Type accessRightType ) : 
			base( principal, accessMask, isInherited, appliesTo, accessRightType ) {

            this.AccessControlType = accessControlType;
        }
 
        public AccessControlType AccessControlType { get; private set; }

		public override string ToString() {
			return string.Format("{0} {1}", this.AccessControlType, base.ToString());
		}
    }
 
 
    public class PacObjectAccessRule : PacAccessRule {
		public PacObjectAccessRule( PacPrincipal principal, int accessMask, AppliesTo appliesTo, Guid objectType, Guid inheritedObjectType, AccessControlType accessControlType, Type accessRightType ) :
			this( principal, accessMask, false, appliesTo, objectType, inheritedObjectType, accessControlType, accessRightType ) { }
			
		public PacObjectAccessRule( PacPrincipal principal, int accessMask, AppliesTo appliesTo, Guid objectType, Guid inheritedObjectType, AccessControlType accessControlType ) :
			this( principal, accessMask, false, appliesTo, objectType, inheritedObjectType, accessControlType, typeof(int) ) { }

		public PacObjectAccessRule( QualifiedAce qualifiedAce, Type accessRightType ) :
			base( qualifiedAce, accessRightType ) { 
		
			Guid objectType = Guid.Empty;
			Guid inheritedObjectType = Guid.Empty;
			if (qualifiedAce is ObjectAce) {
				objectType = ((ObjectAce) qualifiedAce).ObjectAceType;
				inheritedObjectType = ((ObjectAce) qualifiedAce).InheritedObjectAceType;
			}

            if (( !objectType.Equals( Guid.Empty )) && (( qualifiedAce.AccessMask & AdaptedActiveDirectoryAce.AccessMaskWithObjectType ) != 0 )) {
                this.ObjectType = objectType;
                this.ObjectFlags |= ObjectAceFlags.ObjectAceTypePresent;
            }
            else {
                this.ObjectType = Guid.Empty;
            }
 
            if (( !inheritedObjectType.Equals( Guid.Empty )) && ((qualifiedAce.InheritanceFlags & InheritanceFlags.ContainerInherit ) != 0 )) {
                this.InheritedObjectType = inheritedObjectType;
                this.ObjectFlags |= ObjectAceFlags.InheritedObjectAceTypePresent;
            }
            else {
                this.InheritedObjectType = Guid.Empty;
            }
		}

		public PacObjectAccessRule( QualifiedAce qualifiedAce ) :
			this( qualifiedAce, typeof(int) ) { }
			
        internal PacObjectAccessRule( PacPrincipal principal, int accessMask, bool isInherited, AppliesTo appliesTo, Guid objectType, Guid inheritedObjectType, AccessControlType accessControlType, Type accessRightType )
            : base( principal, accessMask, isInherited, appliesTo, accessControlType, accessRightType ) {

            if (( !objectType.Equals( Guid.Empty )) && (( accessMask & AdaptedActiveDirectoryAce.AccessMaskWithObjectType ) != 0 )) {
                this.ObjectType = objectType;
                this.ObjectFlags |= ObjectAceFlags.ObjectAceTypePresent;
            }
            else {
                this.ObjectType = Guid.Empty;
            }
 
            if (( !inheritedObjectType.Equals( Guid.Empty )) && ((appliesTo & AppliesTo.ChildContainers ) != 0 )) {
                this.InheritedObjectType = inheritedObjectType;
                this.ObjectFlags |= ObjectAceFlags.InheritedObjectAceTypePresent;
            }
            else {
                this.InheritedObjectType = Guid.Empty;
            }
        }
 
        public Guid ObjectType { get; private set; }
        public Guid InheritedObjectType { get; private set; }
        public ObjectAceFlags ObjectFlags { get; private set; }

		public override string ToString() {
			return string.Format("{0}; ObjectType {1}; InheritedObjectType: {2}", base.ToString(), this.ObjectType, this.InheritedObjectType);
		}
    }
 
    public class PacAuditRule : PacAuthorizationRule {
 
        public PacAuditRule( PacPrincipal principal, int accessMask, AppliesTo appliesTo, AuditFlags auditFlags, Type accessRightType ) :
			this( principal, accessMask, false, appliesTo, auditFlags, accessRightType ) { }

        public PacAuditRule( PacPrincipal principal, int accessMask, AppliesTo appliesTo, AuditFlags auditFlags ) :
			this( principal, accessMask, false, appliesTo, auditFlags, typeof(int) ) { }

		public PacAuditRule( QualifiedAce qualifiedAce, Type accessRightType ) :
			base( qualifiedAce, accessRightType ) { 
		
			if (qualifiedAce.AceQualifier != AceQualifier.SystemAudit) {
				throw new Exception("qualifiedAce is not an Allow or Deny ACE");
			}

			if (qualifiedAce.AuditFlags == AuditFlags.None) {
				throw new Exception("You must provide at least one audit flag");
			}
 
            this.AuditFlags = qualifiedAce.AuditFlags;
		}

		public PacAuditRule( QualifiedAce qualifiedAce ) :
			this( qualifiedAce, typeof(int) ) { }

        internal PacAuditRule( PacPrincipal principal, int accessMask, bool isInherited, AppliesTo appliesTo, AuditFlags auditFlags, Type accessRightType ) :
			base( principal, accessMask, isInherited, appliesTo, accessRightType ) {
			
			if (auditFlags == AuditFlags.None) {
				throw new Exception("You must provide at least one audit flag");
			}
 
            this.AuditFlags = auditFlags;
        }
 
        public AuditFlags AuditFlags { get; private set; }
 
		public override string ToString() {
			return string.Format("Audit {0} [{1}]", base.ToString(), this.AuditFlags);
		}
   }
 
 
    public class PacObjectAuditRule : PacAuditRule {

        public PacObjectAuditRule( PacPrincipal principal, int accessMask, AppliesTo appliesTo, Guid objectType, Guid inheritedObjectType, AuditFlags auditFlags, Type accessRightType ) :
            this( principal, accessMask, false, appliesTo, objectType, inheritedObjectType, auditFlags, accessRightType ) { }

        public PacObjectAuditRule( PacPrincipal principal, int accessMask, AppliesTo appliesTo, Guid objectType, Guid inheritedObjectType, AuditFlags auditFlags ) :
            this( principal, accessMask, false, appliesTo, objectType, inheritedObjectType, auditFlags, typeof(int) ) { }

		public PacObjectAuditRule( QualifiedAce qualifiedAce, Type accessRightType ) :
			base( qualifiedAce, accessRightType ) { 
		
			Guid objectType = Guid.Empty;
			Guid inheritedObjectType = Guid.Empty;
			if (qualifiedAce is ObjectAce) {
				objectType = ((ObjectAce) qualifiedAce).ObjectAceType;
				inheritedObjectType = ((ObjectAce) qualifiedAce).InheritedObjectAceType;
			}

            if (( !objectType.Equals( Guid.Empty )) && (( qualifiedAce.AccessMask & AdaptedActiveDirectoryAce.AccessMaskWithObjectType ) != 0 )) {
                this.ObjectType = objectType;
                this.ObjectFlags |= ObjectAceFlags.ObjectAceTypePresent;
            }
            else {
                this.ObjectType = Guid.Empty;
            }
 
            if (( !inheritedObjectType.Equals( Guid.Empty )) && ((qualifiedAce.InheritanceFlags & InheritanceFlags.ContainerInherit ) != 0 )) {
                this.InheritedObjectType = inheritedObjectType;
                this.ObjectFlags |= ObjectAceFlags.InheritedObjectAceTypePresent;
            }
            else {
                this.InheritedObjectType = Guid.Empty;
            }
		}

		public PacObjectAuditRule( QualifiedAce qualifiedAce ) :
			this( qualifiedAce, typeof(int) ) { }

        internal PacObjectAuditRule( PacPrincipal principal, int accessMask, bool isInherited, AppliesTo appliesTo, Guid objectType, Guid inheritedObjectType, AuditFlags auditFlags, Type accessRightType ) :
            base( principal, accessMask, isInherited, appliesTo, auditFlags, accessRightType ) {
            

            if (( !objectType.Equals( Guid.Empty )) && (( accessMask & AdaptedActiveDirectoryAce.AccessMaskWithObjectType ) != 0 )) {
                this.ObjectType = objectType;
                this.ObjectFlags |= ObjectAceFlags.ObjectAceTypePresent;
            }
            else {
                this.ObjectType = Guid.Empty;
            }
 
            if (( !inheritedObjectType.Equals( Guid.Empty )) && ((appliesTo & AppliesTo.ChildContainers ) != 0 )) {
                this.InheritedObjectType = inheritedObjectType;
                this.ObjectFlags |= ObjectAceFlags.InheritedObjectAceTypePresent;
            }
            else {
                this.InheritedObjectType = Guid.Empty;
            }
        }
 
        public Guid ObjectType { get; private set; }
        public Guid InheritedObjectType { get; private set; }
        public ObjectAceFlags ObjectFlags { get; private set; }

		public override string ToString() {
			return string.Format("{0}; ObjectType {1}; InheritedObjectType: {2}", base.ToString(), this.ObjectType, this.InheritedObjectType);
		}
    }
  
}
