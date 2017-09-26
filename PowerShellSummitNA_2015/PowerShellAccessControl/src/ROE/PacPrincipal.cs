namespace ROE.PowerShellAccessControl {

	public class PacPrincipal {
		
		#region Constructors
		public PacPrincipal(string computername, string username) : this(computername, TranslateAccountNameToSid(computername, username)) { }
		public PacPrincipal(string username) : this (null, username) { }
		public PacPrincipal(SecurityIdentifier sid) : this(null, sid) { }
		
		public PacPrincipal(string computername, SecurityIdentifier sid) {
			SidNameUse sidNameUse = new SidNameUse();
			
			byte[] sidBytes = new byte[sid.BinaryLength];
			sid.GetBinaryForm(sidBytes, 0);

			uint domainNameLength = 255;
			StringBuilder domainName = new StringBuilder((int) domainNameLength);

			uint accountNameLength = 255;
			StringBuilder accountName = new StringBuilder((int) accountNameLength);

			int returnValue;
			returnValue = advapi32.LookupAccountSid(
				computername,  // Computer 
				sidBytes,      // SID
				accountName,   // Account name
				ref accountNameLength,
				domainName,    // Domain name
				ref domainNameLength,
				out sidNameUse
			);


			this.ComputerName = computername;
			this.SecurityIdentifier = sid;
			if (returnValue != 0) {
				// Unable to translate from SID. May still be a valid account, though, so no
				// error needs to be thrown
			}
			else {
				this.DomainName = domainName.ToString();
				this.AccountName = accountName.ToString();
				this.SidNameUse = sidNameUse;
			}
		}
		
/*	
		internal PacPrincipal(string computerName, string domainName, string accountName, SecurityIdentifier sid, SidNameUse sidNameUse) {
			this.ComputerName = computerName;
			this.DomainName = domainName;
			this.AccountName = accountName;
			this.SidNameUse = sidNameUse;
			this.SecurityIdentifier = sid;
		}
		
*/
		#endregion
		
		#region Properties
		internal const string UnknownAccountFormat = "Unknown Account ({0})";
		public string ComputerName { get; private set; }

		public string DomainName { get; private set; }
		
		public string AccountName { get; private set; }
		
		public SidNameUse SidNameUse { 
			get {
				return _sidNameUse;
			}
			private set {
				_sidNameUse = value;
			}
		}
		private SidNameUse _sidNameUse = SidNameUse.Unknown;
		
		public SecurityIdentifier SecurityIdentifier { get; private set; }

		#endregion

		#region Methods
		public override string ToString() {
			StringBuilder returnString = new StringBuilder(50);
			
			if (!string.IsNullOrEmpty(this.ComputerName)) {
				returnString.AppendFormat(@"{0}\", this.ComputerName);
			}
			
			if (!string.IsNullOrEmpty(this.DomainName)) {
				returnString.AppendFormat(@"{0}\", this.DomainName);
			}
			
			if (!string.IsNullOrEmpty(this.AccountName)) {
				returnString.Append(this.AccountName);
			}
			else {
				returnString.AppendFormat(PacPrincipal.UnknownAccountFormat, this.SecurityIdentifier);
			}
			
			return returnString.ToString();
		}
		
		public object Translate(Type outputType) {
			return this.SecurityIdentifier.Translate(outputType);
		}
		#endregion


#region Temporary until I fix other source code
public static PacPrincipal FromSid(string computerName, SecurityIdentifier sid) {
	return new PacPrincipal(computerName, sid);
}
public static PacPrincipal FromSid(SecurityIdentifier sid) {
	return FromSid(null, sid);
}
#endregion
/*
		public static bool operator==(PacPrincipal left, PacPrincipal right) {
			return left.SecurityIdentifier == right.SecurityIdentifier;
		}
		 
		public static bool operator!=(PacPrincipal left, PacPrincipal right) {
				return !(left == right);
		}
*/
		public override bool Equals(object o) {
            if (o == null) {
                return false;
            }

			PacPrincipal pacPrincipal = o as PacPrincipal;

			if (pacPrincipal == null) { 
				return false;
			}

			return (this.SecurityIdentifier == pacPrincipal.SecurityIdentifier);
        }
		
		public override int GetHashCode() {
			return this.SecurityIdentifier.GetHashCode();
		}

		public static SecurityIdentifier TranslateAccountNameToSid(string computername, string principal) {

			SidNameUse sidNameUse = new SidNameUse();
			
			uint sidByteArraySize = 0;
			uint domainNameLength = 0;

			// Dirty hack. For some reason, using "APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES" fails,
			// but just "ALL APPLICATION PACKAGES" is fine. This needs further work, but for now just strip
			// "APPLICATION PACKAGE AUTHORITY"
			if (principal.StartsWith(@"APPLICATION PACKAGE AUTHORITY\", true, CultureInfo.InvariantCulture)) {
				try {
					principal = principal.Split(new char[] { '\\' }, 2)[1];
				}
				catch {
					throw new Exception(@"principal not in proper format: 'DOMAIN\USERNAME'");
				}
				
			}	

			int returnValue;
			returnValue = advapi32.LookupAccountName(
				computername,  // Computer 
				principal,   // Account
				null,          // SID
				ref sidByteArraySize,
				null,          // Domain name (return)
				ref domainNameLength,
				out sidNameUse
			);

			if (returnValue != 122) {
				// Throw exception with translated error
				throw new Win32Exception(returnValue);
			}

			byte[] sidBytes = new byte[sidByteArraySize];
			StringBuilder domainName = new StringBuilder((int) domainNameLength);
			returnValue = advapi32.LookupAccountName(
				computername,  // Computer 
				principal,   // Account
				sidBytes,      // SID
				ref sidByteArraySize,
				domainName,    // Domain name (return)
				ref domainNameLength,
				out sidNameUse
			);

			if (returnValue != 0) {
				throw new Win32Exception(returnValue);
			}
			
			return new SecurityIdentifier(sidBytes, 0);
		}
	}
}