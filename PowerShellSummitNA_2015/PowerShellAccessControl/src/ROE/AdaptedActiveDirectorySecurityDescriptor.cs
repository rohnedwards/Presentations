namespace ROE.PowerShellAccessControl {
	public class AdaptedActiveDirectorySecurityDescriptor : AdaptedSecurityDescriptor {
/*
There are a few different places where AD lookups are required. Maybe make a class that keeps track of all of the possible info that's needed,
and the first time any of the properties that require a lookup are needed are encountered, single call can look them all up and create a new
class instance...
*/

		#region Constructors
		internal AdaptedActiveDirectorySecurityDescriptor(AdaptedSecurityDescriptorPathInformation pathInfo, RawSecurityDescriptor rawSecurityDescriptor, GetSecurityInformation requestedSecurityInformation) : base(pathInfo, rawSecurityDescriptor, requestedSecurityInformation) {
			// SdPath must be a string
			
			if (pathInfo.IsDS == false) {
				throw new Exception ("IsDS property must be set");
			}
			
			if (!(pathInfo.SdPath is SecurityDescriptorStringPath)) {
				throw new Exception ("SdPath is in wrong format");
			}
			
			AdaptedActiveDirectorySecurityDescriptorPathInformation adPathInfo = pathInfo as AdaptedActiveDirectorySecurityDescriptorPathInformation;
			if (adPathInfo != null && adPathInfo.DsObjectClass != null) {
				this.ObjectAceType = new Guid(ObjectAceTypeGuidConverter.LookupFirstByDisplayName(adPathInfo.DsObjectClass).AceTypeGuid);
			}
		}

		public AdaptedActiveDirectorySecurityDescriptor(AdaptedSecurityDescriptorPathInformation pathInfo, RawSecurityDescriptor rawSecurityDescriptor) : this(pathInfo, rawSecurityDescriptor, 0) { }

		public AdaptedActiveDirectorySecurityDescriptor(AdaptedSecurityDescriptorPathInformation pathInfo, string sddlForm) : this(pathInfo, new RawSecurityDescriptor(sddlForm)) { }

		internal AdaptedActiveDirectorySecurityDescriptor(AdaptedSecurityDescriptorPathInformation pathInfo, byte[] binaryForm, int offset, GetSecurityInformation requestedSecurityInformation) : this(pathInfo, new RawSecurityDescriptor(binaryForm, offset), requestedSecurityInformation) { }
		public AdaptedActiveDirectorySecurityDescriptor(AdaptedSecurityDescriptorPathInformation pathInfo, byte[] binaryForm, int offset) : this(pathInfo, binaryForm, offset, 0) { }
		#endregion
		
		private Guid[] _inheritanceGuidArray;
		internal override Guid[] GetInheritanceGuidArray() {
			return _inheritanceGuidArray ??
				(_inheritanceGuidArray = new Guid[] { this.ObjectAceType });
		}
		
		private Guid GetObjectAceType() {
			using (DirectoryEntry adObject = new DirectoryEntry(String.Format("LDAP://{0}", this.Path.ToString()))) {
				object[] objectClassArray = (object[]) adObject.Properties["ObjectClass"].Value;
				string currentClass =  objectClassArray[objectClassArray.Length - 1].ToString();
				
				return new Guid(ObjectAceTypeGuidConverter.LookupFirstByDisplayName(currentClass).AceTypeGuid);
			}
		}
		public Guid ObjectAceType {
			get {
				if (_objectAceType == Guid.Empty) {
					_objectAceType = GetObjectAceType();
				}
				return _objectAceType;
			}
			private set {
				_objectAceType = value;
			}
		}
		Guid _objectAceType;

		internal override PacPrincipal GetPrincipal(SecurityIdentifier sid) {
			// Try base method first:
			
			PacPrincipal principal =  base.GetPrincipal(sid);

			if (principal.AccountName == null) {
				// Account name wasn't translated properly; attempt to send to DC to translate
				principal = PacPrincipal.FromSid(this.DomainShortName, sid);
			}
			
			return principal;
		}

		public string DomainShortName {
			get { return LookupDomainShortName(this.Path.ToString()); }
		}

		private static Dictionary<string, string> _domainShortNameDict = new Dictionary<string, string>();
		internal static string LookupDomainShortName(string distinguishedName) {
			
			string dcDn = GetDcFromDn(distinguishedName);
			
			// See if this DC has already been looked up:
			if (!_domainShortNameDict.ContainsKey(dcDn)) {
				try {
					_domainShortNameDict.Add(dcDn, GetDomainShortNameFromDn(dcDn));
				}
				catch {
					return null;
				}
			}
			
			return _domainShortNameDict[dcDn];
		}
		private static string GetDcFromDn(string distinguishedName) {

//			Match match = Regex.Match(distinguishedName, ",(DC=(.*))$", RegexOptions.IgnoreCase);
			Match match = Regex.Match(distinguishedName, ",(DC=(?!.*(CN=|OU=))(.*))$", RegexOptions.IgnoreCase);			
			
			if (match.Success) {
				return match.Groups[1].Value;
			}
			else {
				throw new Exception(String.Format("Unable to get DC from '{0}'", distinguishedName));
			}
		}
		
		private static string GetAdObjectCategory(string distinguishedName) {

			using (DirectoryEntry adObject = new DirectoryEntry(String.Format("LDAP://{0}", distinguishedName))) {
				return adObject.Properties["objectCategory"].Value.ToString();
			}
		}
		
		private static string GetDomainShortNameFromDn(string distinguishedName) {

			// Just use Regex to find the DC's DN of the DN passed. Lookup the objectCategory DN of that DN, and get its DC (for most AD objects,
			// the extra lookup is unnecessary, but DNS objects initial DC DN isn't the defaultNamingContext...
			
			// Right now, this is assuming that the Regex check against the objectCategory will always return the defaultNamingContext of the domain.
			// If that assumption turns out to be invalid, a loop can be set up to keep chasing down the next objectCategory's DC (you'd have to be
			// careful to avoid infinite loops)
			string defaultNamingContext;
			try {
				defaultNamingContext = GetDcFromDn(GetAdObjectCategory(distinguishedName));
			}
			catch {
				throw new Exception(String.Format("Error getting defaultNamingContext for DN: {0}", distinguishedName));
			}
			
			string ldapFilter = String.Format("(&(objectCategory=crossRef)(nCName={0}))", defaultNamingContext);

			using (DirectoryEntry partitionContainer = new DirectoryEntry(String.Format("LDAP://CN=Partitions,CN=Configuration,{0}", defaultNamingContext))) {
				using (DirectorySearcher searcher = new DirectorySearcher(partitionContainer, ldapFilter, new string[] { "name" })) {
					return searcher.FindOne().Properties["name"][0].ToString();
				}
			}
		}

		public override Type AccessRuleType {
			get {
				return typeof(PacObjectAccessRule);
			}
		}
		
		public override Type AuditRuleType {
			get {
				return typeof(PacObjectAuditRule);
			}
		}
	}
}



