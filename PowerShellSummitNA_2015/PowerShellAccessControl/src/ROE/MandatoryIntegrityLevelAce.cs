namespace ROE.PowerShellAccessControl {
	public class MandatoryIntegrityLabelAce : AdaptedAce {
	
		private int _policies;
		private SecurityIdentifier _securityIdentifier;
	
		internal MandatoryIntegrityLabelAce(CustomAce aceObject, AdaptedSecurityDescriptor sdObject, string inheritedFrom) : base(aceObject, sdObject, inheritedFrom) {
			if ((int) aceObject.AceType != 17) {
				throw new Exception("Wrong AceType");
			}

			byte[] opaqueData = aceObject.GetOpaque();
			
			this._policies = BitConverter.ToInt32(opaqueData, 0);
			this._securityIdentifier = new SecurityIdentifier(opaqueData, 4);
			
		}
		
		public SystemMandatoryLabelMask Policies {
			get {
				return (SystemMandatoryLabelMask) Enum.ToObject(typeof(SystemMandatoryLabelMask), this._policies);
			}
		}
		
		public PacPrincipal IntegrityLevelIdentityReference {
			get {
				return this._parentSdObject != null ?
					this._parentSdObject.GetPrincipal(_securityIdentifier) : PacPrincipal.FromSid(_securityIdentifier);
			}
		}
		
		public string IntegrityLevel {
			get {
				Match match = Regex.Match(this.IntegrityLevelIdentityReference.ToString(), @"(.*\\)?(?<label>.*) Mandatory Level");
				
				if (match.Success == true) {
					return match.Groups["label"].Value;
				}
				else {
					return this.IntegrityLevelIdentityReference.ToString();
				}
			}
		}
	
		public override string ToString() {
			return string.Format("{0} ({1})", this.IntegrityLevel, this.Policies);
		}
	}
}