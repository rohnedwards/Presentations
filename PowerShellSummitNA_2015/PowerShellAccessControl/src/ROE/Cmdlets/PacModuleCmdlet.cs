using Microsoft.WSMan.Management;

namespace ROE.PowerShellAccessControl {

	public class PacModuleCmdlet : PSCmdlet, IDisposable {
		/*
			Any cmdlet inheriting from this will be able to enable privileges
		*/

		[Parameter(
			Mandatory = true,
			ValueFromPipeline = true,
			Position = 0
		)]
		[Alias("Path")]
		public PSObject[] InputObject { get; set; }

		[Parameter()]
		public PacSdOption PacSDOption { 
			get {
				return _pacCommandOptions ??
					(_pacCommandOptions = new PacSdOption());
			}
			set {
				_pacCommandOptions = value;
			}
		}
		private PacSdOption _pacCommandOptions;
		internal int _bypassAclPermissions;
		internal bool _recurse, _includeFiles, _includeDirectories, _isLiteral;
		internal ResourceType _objectType;
		internal GetSecurityInformation _securityDescriptorSections;
		
		// Cmdlets that need a -Force switch will set this internal field
		internal bool _force = false;
		
		private Dictionary<string, ROE.ThirdParty.PrivilegeClass.Privilege> _enabledPrivilegesDict = new Dictionary<string, ROE.ThirdParty.PrivilegeClass.Privilege>();
		private List<string> _failedPrivilegesList = new List<string>();
		bool disposed = false;

		public void Dispose() {
			Dispose(true);
			GC.SuppressFinalize(this);           
		}
		
		protected virtual void Dispose(bool disposing) {
			if (this.disposed) { 
				return; 
			}
			
			if (disposing) {
				ROE.ThirdParty.PrivilegeClass.Privilege currentPrivilege;
				foreach (string privilegeName in _enabledPrivilegesDict.Keys) {
//Console.WriteLine("Cleanup: Reverting '{0}'", privilegeName);
					currentPrivilege = _enabledPrivilegesDict[privilegeName];
					try {
						currentPrivilege.Revert();
					}
					catch (Exception e) {
Console.WriteLine("  -> Error reverting: {0}", e.Message);
					}
				}

				// Assume they all reverted successfully
				_enabledPrivilegesDict.Clear();
			}
			this.disposed = true;
		}

		internal bool EnablePrivilege(string privilegeName) {

			WriteDebug(string.Format("EnablePrivilege(): Attempting enable {0}", privilegeName));

			if (_enabledPrivilegesDict.ContainsKey(privilegeName.ToLower())) {
				WriteDebug("EnablePrivilege():  -> Privilege already enabled");
				return true;
			}
			else if (_failedPrivilegesList.Contains(privilegeName.ToLower())) {
				WriteDebug("EnablePrivilege():  -> Privilege failed earlier");
				return false;
			}
			
			ROE.ThirdParty.PrivilegeClass.Privilege priv = new ROE.ThirdParty.PrivilegeClass.Privilege(privilegeName);
			try {
				priv.Enable();
				WriteDebug("EnablePrivilege():  -> Privilege successfully enabled");
				_enabledPrivilegesDict.Add(privilegeName.ToLower(), priv);
			}
			catch (Exception e){
				WriteWarning(string.Format("Error enabling '{0}': {1}", priv.PrivilegeName, e.Message));
				_failedPrivilegesList.Add(privilegeName.ToLower());
				return false;
			}
			return true;
		}

		internal AdaptedSecurityDescriptor ConvertSingleSecurityDescriptorToAdaptedSecurityDescriptor(object unknownSDObject) {
			// Cmdlets that can work on ObjectSecurity instances OR AdaptedSecurityInstances need to ensure that an
			// AdaptedSecurityDescriptor version is always an AdaptedSecurityDescriptor object if the -Apply switch
			// is provided
			
			if (unknownSDObject is AdaptedSecurityDescriptor) {
				return (AdaptedSecurityDescriptor) unknownSDObject;
			}
			else if ( unknownSDObject is ObjectSecurity ||
					  ( unknownSDObject is PSObject && ((PSObject) unknownSDObject).BaseObject is ObjectSecurity) ) {
					  
				foreach (AdaptedSecurityDescriptor adaptedSD in this.GetAdaptedSecurityDescriptor(new PSObject[] { new PSObject(unknownSDObject) })) {
					return adaptedSD;
				}
			}
			
			// This shouldn't happen if calls to this method are set up properly
			throw new Exception("Unable to convert security descriptor into AdaptedSecurityDescriptor instance");
		}
		
		protected override void BeginProcessing() {
			// Cmdlet keeps an internal copy of the PacSDOption settings so that if a user
			// creates an option instance the different cmdlets won't modify it
			_isLiteral = this.PacSDOption.LiteralPath;
			_recurse = this.PacSDOption.Recurse;
			_includeFiles = this.PacSDOption.File;
			_includeDirectories = this.PacSDOption.Directory;
			_objectType = this.PacSDOption.ObjectType;
WriteDebug(string.Format("PacModuleCmdlet Begin(): this.PacSDOption.SecurityDescriptorSections = {0}", this.PacSDOption.SecurityDescriptorSections));
			_securityDescriptorSections = this.PacSDOption.SecurityDescriptorSections;
			_bypassAclPermissions = 0;

			if (this.PacSDOption.BypassAclCheck) {
				// Always request read access if this is set (PacModuleModificationCmdlet can attempt
				// to open w/ write semantics if -Apply is also set)

				WriteDebug("BypassAclCheck option was passed; enabling 'SeBackupPrivilege'");
				if (EnablePrivilege("SeBackupPrivilege")) {
					_bypassAclPermissions |= (int) (FileSystemRights.ReadPermissions);
				}
			}

			if ((_securityDescriptorSections & GetSecurityInformation.Audit) != 0) {
				WriteDebug("Audit (SACL) was requested; enabling 'SeSecurityPrivilege'");
				if (this.EnablePrivilege("SeSecurityPrivilege")) {
					if (_bypassAclPermissions > 0) {
						_bypassAclPermissions |= 0x01000000; //AccessSystemSecurity
					}
				}
				else {
					_securityDescriptorSections ^= GetSecurityInformation.Audit;
				}
			}
		}


		#region Common methods
		internal void SplitPath(string path, out string root, out string remainingPath, out string pathOptions) {
			
			string[] pathComponents;
			string _root, _remainingPath, _pathOptions;

			pathComponents = Regex.Split(path, @"(?<=\(\?.*?\))\s?(?=.)");
			if (pathComponents.Length == 2) {
				// Options were present
				_pathOptions = pathComponents[0];
				path = pathComponents[1];
			}
			else {
				_pathOptions = "";
			}

			pathComponents = Regex.Split(path, @"(?<=^[^\\]+:?|^\\\\[^\\]*?\\[^\\]*?|^\.\.?)\\"); //@"(?<=^[^\\]*?:|^\\\\[^\\]*?\\[^\\]*?|^\.\.?)\\");
			
			if (pathComponents.Length == 2) {
				// Regex found a root component of the path
				_root = pathComponents[0];
				_remainingPath = pathComponents[1];
			}
			else { //(pathComponents.Length == 1) {
				// No root component (can happen with AD paths, etc) or only a root component, e.g., C:\ (or C:) was passed
				_root = pathComponents[0];
				_remainingPath = "";
			}

			WriteDebug(string.Format("SplitPath: Path '{0}' was split into {1} component(s):", path, pathComponents.Length));
			WriteDebug(string.Format("            -> Root     : {0}", _root));
			WriteDebug(string.Format("            -> Remaining: {0}", _remainingPath));

			// Extra check to see if . or .. were used as the root:
			if (_root == "." || _root == "..") {
				WriteDebug("            -> Relative path, getting current location");
				string currentLocation = this.SessionState.Path.CurrentLocation.Path;
				
				if (_root == "..") {
					currentLocation = this.SessionState.Path.ParseParent(currentLocation, null);
				}

				WriteDebug(string.Format(@"            -> Recalling SplitPath() with new path: {0}\{1}", currentLocation, _remainingPath));
				string __temp;
				SplitPath(string.Format(@"{0}\{1}", currentLocation, _remainingPath), out _root, out _remainingPath, out __temp);
			}
			
			root = _root;
			remainingPath = _remainingPath;
			pathOptions = _pathOptions;
		}

		internal IEnumerable<AdaptedSecurityDescriptorPathInformation> GetPathInfoFromString(string[] inputPaths) {

			string root, rootToLower, remainingPath, pathOptions;
			bool isContainer;

			// Keep track of effective options separate from what was passed to method
			bool effectiveIsLiteral, effectiveRecurse, effectiveIncludeDirectories, effectiveIncludeFiles, fileOrDirectoryOptionEncountered;

			foreach (string currentInputPath in inputPaths) {
				// Split the path
				SplitPath(currentInputPath, out root, out remainingPath, out pathOptions);
				rootToLower = root.ToLower(CultureInfo.InvariantCulture);

				// Reset all options (in case currentPath doesn't have inline options)
				effectiveIsLiteral = this._isLiteral;
				effectiveRecurse = this._recurse;
				effectiveIncludeDirectories = this._includeDirectories;
				effectiveIncludeFiles = this._includeFiles;
				fileOrDirectoryOptionEncountered = false;

				if (!string.IsNullOrEmpty(pathOptions)) {
					// There were options specified
					
					WriteDebug(string.Format("GetPathInfoFromString(): Inline options were present for path '{0}'", currentInputPath));
					foreach (char character in pathOptions.ToCharArray()) {
						switch (character) {
							case '?':
							case '(':
							case ')':
							case ' ':
								// Ignore any of these
								break;
							
							case 'l': // Literal path
								WriteDebug(string.Format("GetPathInfoFromString():  -> {0} = IsLiteral", character))	;
								effectiveIsLiteral = true;
								break;
								
							case 'r': // Recurse
								WriteDebug(string.Format("GetPathInfoFromString():  -> {0} = Recurse", character));
								effectiveRecurse = true;
								break;
							
							case 'f': // Include files
								WriteDebug(string.Format("GetPathInfoFromString():  -> {0} = IncludeFiles", character));
								effectiveIncludeFiles = true;

								if (!fileOrDirectoryOptionEncountered) {
									effectiveIncludeDirectories = false;
								}
								fileOrDirectoryOptionEncountered = true;
								break;
								
							case 'd': // Include directories
								WriteDebug(string.Format("GetPathInfoFromString():  -> {0} = IncludeDirectories", character));
								effectiveIncludeDirectories = true;
								if (!fileOrDirectoryOptionEncountered) {
									effectiveIncludeFiles = false;
								}
								fileOrDirectoryOptionEncountered = true;
								break;
							
							default:
								WriteDebug(string.Format("GetPathInfoFromString():  -> Unknown option: {0}", character));
								break;
						}
					}
					
				}

				WriteDebug(string.Format("GetPathInfoFromString(): Effective Options for '{0}':", currentInputPath));
				WriteDebug(string.Format("GetPathInfoFromString():  -> IsLiteral? {0}", effectiveIsLiteral));				
				WriteDebug(string.Format("GetPathInfoFromString():  -> Recurse? {0}", effectiveRecurse));				
				WriteDebug(string.Format("GetPathInfoFromString():  -> IncludeDirs? {0}", effectiveIncludeDirectories));				
				WriteDebug(string.Format("GetPathInfoFromString():  -> IncludeFiles? {0}", effectiveIncludeFiles));				
				WriteDebug(string.Format("GetPathInfoFromString():  -> ObjectType: {0}", this._objectType));				

				// If object type is unknown, try to figure it out
				ResourceType objectType = this._objectType;
				if (objectType == ResourceType.Unknown) {
					WriteDebug("GetPathInfoFromString(): Object type is unknown; attempting to detect");
					if (remainingPath.Contains(":") && WmiInfo.TestIsValidWmiPath(currentInputPath)) {
						// Not a valid file/folder or registry path. If it's a WMI path, regex can
						// cause root to look like a file share, so this check must come before the
						// test to see if the share exists (or else it will hang)
						objectType = ResourceType.ProviderDefined;
					}
					else if (ROE.ThirdParty.Microsoft.Experimental.IO.LongPathCommon.Exists(root, out isContainer)) {
						objectType = ResourceType.FileObject;
					}
					else if (rootToLower.EndsWith("hklm:") || rootToLower.EndsWith("hkcu:") || rootToLower.StartsWith("hkey_")) {
						objectType = ResourceType.RegistryKey;
					}
					else if (rootToLower == "ad:" || string.Format(@"{0}\{1}", root, remainingPath).ToLower().Contains("dc=")) {
						objectType = ResourceType.DSObjectAll;
					}
					else if (rootToLower.StartsWith("wmi namespace:") || rootToLower.StartsWith("microsoft.wsman.management") || rootToLower.StartsWith("wsmanconfig:")) {
						objectType = ResourceType.ProviderDefined;
					}
				}

				switch (objectType) {
					case ResourceType.FileObject:
						WriteDebug("GetPathInfoFromString(): Object is FileObject; resolving path(s)");
						IEnumerable<string> resolvedPaths = new List<string>();

						if (effectiveIsLiteral) {
							((List<string>)resolvedPaths).Add(string.Format(@"{0}\{1}", root, remainingPath));
						}
						else {
							((List<string>)resolvedPaths).Add(string.Format(@"{0}\", root));
							foreach (string pathPart in (Regex.Split(remainingPath, @"\\"))) {
								if (string.IsNullOrEmpty(pathPart)) { continue; }
								resolvedPaths = ResolveFilePathsList(resolvedPaths, pathPart, effectiveIncludeDirectories, effectiveIncludeFiles);
							}
						}

						// Paths have been resolved
						foreach (string currentPath in resolvedPaths) {
							WriteDebug(string.Format("GetPathInfoFromString(): Calling GetPathInfoFromFilePath on '{0}'. effectiveIncludeDirectories = {1}, effectiveIncludeFiles = {2}", currentPath, effectiveIncludeDirectories, effectiveIncludeFiles));
							foreach (AdaptedSecurityDescriptorPathInformation pathInfo in GetPathInfoFromFilePath(currentPath, effectiveRecurse, effectiveIncludeDirectories, effectiveIncludeFiles)) {
								WriteDebug(string.Format("GetPathInfoFromString(): Got PathInfo for object with path '{0}'", pathInfo.SdPath.ToString()));
								yield return FinalizePathInfo(pathInfo);
							}
						}
						break;

					case ResourceType.RegistryKey:
					case ResourceType.RegistryWow6432Key:
						WriteDebug("GetPathInfoFromString(): Registry object");					
						Microsoft.Win32.RegistryView view;
						if (objectType == ResourceType.RegistryKey) {
							view = Microsoft.Win32.RegistryView.Default;
						}
						else {
							view = Microsoft.Win32.RegistryView.Registry32;
						}
						WriteDebug(string.Format("GetPathInfoFromString():  -> View: {0}", view));
						
						Match regexMatch = Regex.Match(rootToLower, @"^(\\\\(?<computername>.*)\\)?(?<basekey>[^:]+):?");
						
						Microsoft.Win32.RegistryHive hive;
						string displayNameFormat = @"{0}\{1}";
						string sdPathFormat;
						switch (regexMatch.Groups["basekey"].Value) {
							case "hklm":
							case "machine":
							case "localmachine":
							case "hkey_local_machine":
								hive = Microsoft.Win32.RegistryHive.LocalMachine;
								sdPathFormat = @"MACHINE\{0}";
								break;
								
							case "hkcu":
							case "currentuser":
							case "hkey_current_user":
								hive = Microsoft.Win32.RegistryHive.CurrentUser;
								sdPathFormat = @"CURRENT_USER\{0}";
								break;
								
							default:
								WriteWarning(string.Format("No support for registry hive '{0}'", regexMatch.Groups["basekey"]));
								continue;
							
						}
						WriteDebug(string.Format("GetPathInfoFromString():  -> Hive: {0}", hive));
						
						string computerName = regexMatch.Groups["computername"].Value;
						if (!string.IsNullOrEmpty(computerName)) { 
							sdPathFormat = @"\\{1}\" + sdPathFormat;
							displayNameFormat += " ({2})";
							WriteDebug(string.Format("GetPathInfoFromString():  -> ComputerName: {0}", computerName));
						}

						Microsoft.Win32.RegistryKey baseKey;
						try {
							baseKey = Microsoft.Win32.RegistryKey.OpenRemoteBaseKey(hive, computerName, view);
						}
						catch (Exception e) {
							WriteError(new ErrorRecord(
								new Exception(string.Format("Error opening base key with the following parameters: Hive = {0}; ComputerName = {1}; View = {2}: {3}", hive, computerName, view, e.Message)),
								"TBD",
								ErrorCategory.InvalidData,
								root
							));
							continue;
						}

						IEnumerable<string> resolvedKeyPaths = new List<string>();
						
						if (effectiveIsLiteral) {
							((List<string>)resolvedKeyPaths).Add(remainingPath);
						}
						else {
							((List<string>)resolvedKeyPaths).Add(string.Empty);
							foreach (string pathPart in (Regex.Split(remainingPath, @"\\"))) {
								if (string.IsNullOrEmpty(pathPart)) { continue; }
								resolvedKeyPaths = ResolveRegistryPathsList(resolvedKeyPaths, pathPart, baseKey, false);
							}
						}

						if (effectiveRecurse) {
							// Use ResolveRegistryPathsList to get one level deep, too
							resolvedKeyPaths = ResolveRegistryPathsList(resolvedKeyPaths, "*", baseKey, true);
						}

						foreach (string currentRegistryKey in resolvedKeyPaths) {
							yield return FinalizePathInfo(
								new AdaptedSecurityDescriptorPathInformation(
									string.Format(sdPathFormat, currentRegistryKey, computerName),
									string.Format(displayNameFormat, baseKey.Name, currentRegistryKey, computerName),
									objectType,  // RegistryKey or RegistryWow64Key
									true         // isContainer
								)
							);
						}
						WriteDebug("GetPathInfoFromString(): Disposing of BaseKey");						
						baseKey.Dispose();
						break;
							
					case ResourceType.DSObjectAll:
					case ResourceType.DSObject:
						if (effectiveRecurse) {
							// For now, recursion doesn't work with AD paths
							WriteWarning("PAC module doesn't support recursive calls to AD paths. Please use the AD provider...");
						}
						
						if (!string.IsNullOrEmpty(remainingPath)) {
							// Ideally, the whole path is contained in root
							// In practice, root can contain part of the distinguished name, and remaining path can contain
							// the other part if the '\' was used to escape a valid LDAP path character. One way to stop this
							// from happening is to modify the regex above, but that would require knowing all possible characters
							// that can be escaped. I'm trying to repair the potentially broken DN here:
							root = string.Format(@"{0}\{1}", root, remainingPath);
						}

						if (root.StartsWith("ad:")) {
							root = root.Substring(3);
						}
							
						if (root.StartsWith("ldap://")) {
							root = root.Substring(7);
						}
								
						yield return FinalizePathInfo(new AdaptedActiveDirectorySecurityDescriptorPathInformation(root, null));
						break;

					case ResourceType.ProviderDefined:
						WriteDebug("GetPathInfoFromString(): Provider defined");

						if (rootToLower.StartsWith("microsoft.wsman.management") || rootToLower.StartsWith("wsmanconfig:")) {
							WriteDebug("GetPathInfoFromString():  -> WSMan object");
							WriteWarning("Can't pass WSMan objects by string path yet");
						}
						else if (rootToLower.StartsWith("wmi namespace:") || WmiInfo.TestIsValidWmiPath(currentInputPath)) {
							WriteDebug("GetPathInfoFromString():  -> WMI Namespace");
							string wmiPath = currentInputPath;
							
							Match wmiMatch = Regex.Match(wmiPath, @"^WMI Namespace: (?<wmiPath>.*?)(\s+\((?<computername>.*)\))?$", RegexOptions.IgnoreCase);
							if (wmiMatch.Success) {
								wmiPath = string.Format(
									@"\\{0}\{1}:__SystemSecurity=@",
									wmiMatch.Groups["computername"].Value ?? ".",  // If computername wasn't found, . for localhost
									wmiMatch.Groups["wmiPath"].Value
								);
							}
							
							WriteDebug(string.Format("GetPathInfoFromString():  -> Getting CimInstance for path '{0}'", wmiPath));
							foreach (AdaptedSecurityDescriptorPathInformation currentWmiPathInfo in GetPathInfoFromPSObject(new PSObject[] { new PSObject(WmiInfo.GetSingleWmiInstance<CimInstance>(wmiPath)) })) {
								yield return currentWmiPathInfo;
							}
						}
						else {
							goto case ResourceType.Unknown;
						}
						break;
						
					case ResourceType.Unknown:
						WriteError(new ErrorRecord(
							new Exception(string.Format("Unable to determine ObjectType for '{0}'", currentInputPath)),
							"",
							ErrorCategory.InvalidData,
							currentInputPath
						));
						break; 
						
					default:
						yield return FinalizePathInfo(
							new AdaptedSecurityDescriptorPathInformation(
								currentInputPath,
								currentInputPath,
								objectType,
								false         // Path is unknown; assume it is not a container??
							)
						);
						break;
				}
			}
		}
		
		internal IEnumerable<AdaptedSecurityDescriptorPathInformation> GetPathInfoFromPSObject(PSObject[] psObjects) {
			AdaptedSecurityDescriptorPathInformation pathInfo;
			object inputObject;
			
			foreach (PSObject inputPSObject in psObjects) {
				pathInfo = new AdaptedSecurityDescriptorPathInformation();
				inputObject = inputPSObject.BaseObject;

	// I don't like how this is multipe if statements and doing checks with is-then-cast. Would like to work in a switch statement
	// and/or use as for single cast...
				if (inputObject is AdaptedSecurityDescriptorPathInformation) {
					pathInfo = (AdaptedSecurityDescriptorPathInformation) inputObject;
					WriteDebug("GetPathInfoFromPSObject(): Current object is already path information object");
				}
				else if (inputObject is AdaptedCommonAce) {
					WriteDebug("GetPathInfoFromPSObject(): Current object is AdaptedCommonAce, so returning path information contained in Path property...");
					pathInfo = ((AdaptedCommonAce) inputObject).Path;
				}
				else if (inputObject is string || inputObject is string[]) {
					/*
						This is going to happen a lot; use GetPacPathInfo cmdlet to try to parse the string
					*/
					
					WriteDebug("GetPathInfoFromPSObject(): Current object is a string (or array of strings); Calling GetPathInfoFromString()");
					string[] stringArray;
					if (inputObject is string) {
						stringArray = new string[] { (string) inputObject };
					}
					else {
						stringArray = (string[]) inputObject;
					}

					foreach (AdaptedSecurityDescriptorPathInformation stringPathInfo in GetPathInfoFromString(stringArray)) {
						WriteDebug(string.Format("GetPathInfoFromString(): PathInfo path = {0}", stringPathInfo.SdPath));
						yield return stringPathInfo;
					}
					continue;
				}
				else if (inputObject is ObjectSecurity) {

					WriteDebug("GetPathInfoFromPSObject(): Current object is ObjectSecurity instance; building path information from it");

					pathInfo.AccessRightType = ((ObjectSecurity) inputObject).AccessRightType;
					
					if (inputObject is DirectorySecurity || inputObject is RegistrySecurity) {
						pathInfo.IsContainer = true;
					}
					else if (inputObject is ActiveDirectorySecurity) {
						pathInfo.IsContainer = true;
						pathInfo.IsDS = true;
						pathInfo.AccessRightType = typeof(Enums.ActiveDirectoryRights);
					}


					string[] psPath;
					
					try {
						psPath = Regex.Split((string) inputPSObject.Properties["PsPath"].Value, "::");

						switch (psPath[0]) {
	// ObjectType will be unknown if PsPath property isn't present. That's OK, though, because w/o SdPath, can't write SD back out...
							case @"Microsoft.PowerShell.Core\FileSystem":
								pathInfo.SdPath = new SecurityDescriptorStringPath( psPath[1] );
								pathInfo.ObjectType = ResourceType.FileObject;
								break;

							case @"Microsoft.PowerShell.Core\Registry":
								pathInfo.SdPath = new SecurityDescriptorStringPath( 
									Regex.Replace(psPath[1], "^HKEY_(LOCAL_)?", ""),
									psPath[1]
								);
								pathInfo.ObjectType = ResourceType.RegistryKey;
								break;
								
							case @"Microsoft.ActiveDirectory.Management\ActiveDirectory":
								pathInfo.SdPath = new SecurityDescriptorStringPath( psPath[1].Replace("//RootDSE/", "") );
								pathInfo.ObjectType = ResourceType.DSObjectAll;
								break;
								
							default:
								pathInfo.SdPath = new SecurityDescriptorStringPath(string.Join("::", psPath));
								break;
						}
					}
					catch {
						WriteWarning(string.Format("Error parsing PsPath property on '{0}' object", inputPSObject.GetType().FullName));
						pathInfo.SdPath = new SecurityDescriptorStringPath("<UNKNOWN>");
					}
					
					pathInfo.SdPath.DisplayName = string.Format("{0} (Coerced from .NET {1} object)", pathInfo.SdPath.DisplayName, inputObject.GetType().Name);

				}
				else if (inputObject is FileSystemInfo) {
					/*
						File or Directory object (from Get-Item or Get-ChildItem)
					*/
					
					WriteDebug("GetPathInfoFromPSObject(): Current object is FileSystemInfo instance");
					FileSystemInfo unboxedFsInfo = (FileSystemInfo) inputObject;
					pathInfo.IsContainer = (unboxedFsInfo.Attributes & FileAttributes.Directory) != 0;
					pathInfo.SdPath = new SecurityDescriptorStringPath(unboxedFsInfo.FullName);
					pathInfo.AccessRightType = typeof(FileSystemRights);
					pathInfo.ObjectType = ResourceType.FileObject;
				}
				else if (inputObject is Microsoft.Win32.RegistryKey) {
					/*
						Registry key

						If this came from Get-Item or Get-ChildItem, PSObject will contain extra NoteProperties,
						and we can be guaranteed this is for the local machine (at least I don't think gi and gci
						can work against remote systems). In that case, use a string SdPath and get all of the
						cool features that go along with it (InheritedFrom, bypassAclPermissions, etc).
						
						If this came from RegistryKey.OpenSubKey(), it could be for a remote system. I don't know
						of a way to tell if it is local or remote, so simply use the RegistrySafeHandle as the
						SdPath. That means it will work if the RegistryKey object is to a remote machine (but you
						won't get the InheritedFrom info, and bypassAclPermissions won't work)
					*/
					
					WriteDebug("GetPathInfoFromPSObject(): Current object is RegistryKey instance");
					pathInfo.IsContainer = true;
					pathInfo.AccessRightType = typeof(RegistryRights);
					if (inputPSObject.Properties["PSPath"] == null) {
						WriteDebug("GetPathInfoFromPSObject():   -> RegistryKey object does not have extra PS properties; treating it as a KernelObject");
						pathInfo.SdPath = new SecurityDescriptorSafeHandle( 
							((Microsoft.Win32.RegistryKey) inputObject).Handle, 
							((Microsoft.Win32.RegistryKey) inputObject).Name 
						);
						pathInfo.ObjectType = ResourceType.KernelObject;
					}
					else {
						WriteDebug("GetPathInfoFromPSObject():   -> RegistryKey object has extra PS properties; treating it as a string path");
						
						// Send this to GetPathInfoFromString() so we don't have to duplicate the work of figuring out
						// the difference b/w SdPath and DisplayName. If it ever changes, we'll only need to change it
						// in one place (even though this adds some overhead)

/*  PULLED B/C OBJECTTYPE GOES ALONG WITH THE CMDLET INSTANCE. NEED TO CONFIRM THAT GET-CHILDITEM CAN'T DO ANYTING W/ VIEWS, AND THEN WHAT THIS PART WAS DOING ISN'T NECESSARY


						// This little check may be able to be removed. Find out if the registry provider does anything
						// with views. If not, ResourceType.RegistryKey can always be passed.
						ResourceType objectType;
						if (((Microsoft.Win32.RegistryKey) inputObject).View == Microsoft.Win32.RegistryView.Registry32) {
							objectType = ResourceType.RegistryWow6432Key;
						}
						else {
							objectType = ResourceType.RegistryKey;
						}
*/						
						try {
							foreach (AdaptedSecurityDescriptorPathInformation currentPathInfoFromString in GetPathInfoFromString(
								new string[] { ((Microsoft.Win32.RegistryKey) inputObject).Name }
							)) {
								pathInfo = currentPathInfoFromString;
								break;  // There can be only one!!
							};
						}
						catch (Exception e) {
							WriteError(new ErrorRecord(
								e,
								"",
								ErrorCategory.InvalidData,
								inputPSObject
							));
							continue;
						}
					}
				}

				else if (inputObject is System.ServiceProcess.ServiceController) {
					WriteDebug("GetPathInfoFromPSObject(): Current object is ServiceController instance");
					System.ServiceProcess.ServiceController service = (System.ServiceProcess.ServiceController) inputObject;
					pathInfo.ObjectType = ResourceType.Service;
					pathInfo.AccessRightType = typeof(ServiceAccessRights);
					pathInfo.SdPath = new SecurityDescriptorStringPath(
						string.Format(@"\\{0}\{1}", service.MachineName, service.ServiceName),
						string.Format("Service: {0}", service.DisplayName)
					);
				}
				
				else if (inputObject is System.Diagnostics.Process) {
					WriteDebug("GetPathInfoFromPSObject(): Current object is Process instance");
					System.Diagnostics.Process process = (System.Diagnostics.Process) inputObject;
					pathInfo.ObjectType = ResourceType.KernelObject;
					pathInfo.AccessRightType = typeof(ProcessAccessRights);

					IntPtr processHandle = IntPtr.Zero;
					try {
						processHandle = process.Handle;
						if (processHandle == IntPtr.Zero) {
							throw new Exception("Handle property is null");
						}
					}
					catch (Exception e) {
						WriteError(new ErrorRecord(
							new Exception(string.Format("Unable to access process handle for process with PID {0}: {1}", process.Id, e.Message)),
							"",
							ErrorCategory.InvalidData,
							process
						));
						continue;
					}
					
					pathInfo.SdPath = new SecurityDescriptorHandleRef(
						new HandleRef(process, processHandle),
						string.Format(@"Process: {0} ({1})", process.ProcessName, process.Id)
					);
				}
				
				else if (inputObject is ManagementBaseObject || inputObject is CimInstance) {
					WriteDebug("GetPathInfoFromPSObject(): Current object is WMI/CIM instance");
					// A few WMI instances are supported. We'll need more information before
					// we continue
					WmiInfo wmiInfo = WmiInfo.Create(inputObject);
					Dictionary<string, object> wmiProperties;
					switch (wmiInfo.ClassName) {
						case "Win32_Service":
							wmiProperties = WmiInfo.GetPropertyDictionary(inputObject, new List<string>() { "DisplayName", "Name" });
							pathInfo.ObjectType = ResourceType.Service;
							pathInfo.AccessRightType = typeof(ServiceAccessRights);
							pathInfo.SdPath = new SecurityDescriptorStringPath(
								string.Format(@"\\{0}\{1}", wmiInfo.ComputerName, wmiProperties["Name"].ToString()),
								string.Format("Service: {0}", wmiProperties["DisplayName"].ToString())
							);
							break;
							
						case "Win32_Printer":
						case "MSFT_Printer":   // Get-Printer result
							pathInfo.IsContainer = true;
							wmiProperties = WmiInfo.GetPropertyDictionary(inputObject, new List<string>() { "Name" });
							pathInfo.ObjectType = ResourceType.Printer;
							pathInfo.AccessRightType = typeof(PrinterRights);
							pathInfo.SdPath = new SecurityDescriptorStringPath(
								string.Format(@"\\{0}\{1}", wmiInfo.ComputerName, wmiProperties["Name"].ToString()),
								string.Format("Printer: {0}", wmiProperties["Name"].ToString())
							);
							break;

						case "Win32_LogicalShareSecuritySetting":
						case "Win32_Share":
						case "MSFT_SmbShare":
							wmiProperties = WmiInfo.GetPropertyDictionary(inputObject, new List<string>() { "Name" });
							pathInfo.ObjectType = ResourceType.LMShare;
							pathInfo.AccessRightType = typeof(ShareRights);
							string shareName = string.Format(@"\\{0}\{1}", wmiInfo.ComputerName, wmiProperties["Name"].ToString());
							pathInfo.SdPath = new SecurityDescriptorStringPath(
								shareName,
								string.Format("Share: {0}", shareName)
							);
							break;
							
						case "__SystemSecurity":  // WMI Namespace
							pathInfo.IsContainer = true;
							pathInfo.ObjectType = ResourceType.ProviderDefined;
							pathInfo.AccessRightType = typeof(WmiNamespaceRights);
							pathInfo.SdPath = new SecurityDescriptorStringPath(
								wmiInfo.Path,
								string.Format("WMI Namespace: {0} ({1})", wmiInfo.Namespace, wmiInfo.ComputerName)
							);
							break;

						case "Win32_Process":
							WriteDebug("Getting System.Diagnostics.Process instance from Win32_Process WMI instance...");
							PSObject psProc;
							try {
								wmiProperties = WmiInfo.GetPropertyDictionary(inputObject, new List<string>() { "ProcessID" });
								psProc = new PSObject(
									System.Diagnostics.Process.GetProcessById(
										int.Parse(wmiProperties["ProcessID"].ToString()),
										wmiInfo.ComputerName
									)
								);
							}
							catch (Exception e) {
								WriteError(new ErrorRecord(
									e,
									"",
									ErrorCategory.InvalidData,
									inputObject
								));
								yield break;
							}

							foreach (AdaptedSecurityDescriptorPathInformation procPathInfo in GetPathInfoFromPSObject(new PSObject[] { psProc })) {
								yield return procPathInfo;
							}
							continue;
							
						default:
							WriteError(new ErrorRecord(
								new Exception(string.Format("Unsupported {0}: {1}", inputObject.GetType().Name, wmiInfo.ClassName)),
								"TBD", 
								ErrorCategory.InvalidData, 
								inputObject
							));
							yield break;
					}
				}
				else if (inputObject.GetType().FullName.StartsWith("Microsoft.ActiveDirectory.Management.AD")) {
					// Using reflection b/c not all computers will have AD module installed. Need to come up with
					// a better way to do this
					
					/*
					Microsoft.ActiveDirectory.Management.ADObject adObject = (Microsoft.ActiveDirectory.Management.ADObject) inputObject;
					pathInfo = new AdaptedActiveDirectorySecurityDescriptorPathInformation(adObject.DistinguishedName, adObject.ObjectClass);
					*/

					WriteDebug("GetPathInfoFromPSObject(): Current object is AD module object instance");
					
					Type typeInfo = inputObject.GetType();
					try {
						pathInfo = new AdaptedActiveDirectorySecurityDescriptorPathInformation(
							typeInfo.GetProperty("DistinguishedName").GetValue(inputObject).ToString(), 
							typeInfo.GetProperty("ObjectClass").GetValue(inputObject).ToString()
						);
					}
					catch {
						WriteError(new ErrorRecord(
							new Exception("Error getting DistinguishedName and/or ObjectClass from object"),
							"TBD",
							ErrorCategory.InvalidData,
							inputObject
						));
						yield break;
					}
				}
				else if (inputObject.GetType().FullName == "Microsoft.WSMan.Management.WSManConfigLeafElement") {
					// For some reason, 'is' keyword doesn't work for the this test...
					
					pathInfo.ObjectType = ResourceType.ProviderDefined;
					pathInfo.AccessRightType = typeof(WsManAccessRights);
					pathInfo.SdPath = new SecurityDescriptorStringPath(
						inputPSObject.Properties["PsPath"].Value.ToString(),
						string.Format("WSManConfig: {0}", inputPSObject.Properties["PsPath"].Value.ToString())
					);
				}
				
				else if (inputObject is AdaptedSecurityDescriptor) {
					// Set-SecurityDescriptor can be used to set a security descriptor from itself. In that case, the
					// cmdlet will still call GetPathInfoFromPSObject back on itself
					pathInfo = ((AdaptedSecurityDescriptor) inputObject)._pathInfo;
				}
				
				if (pathInfo.InstanceType == null) {
					// If this is already set, we don't want to overwrite it (might have come from a pathInfo that was
					// passed into method)
					pathInfo.InstanceType = inputObject.GetType();
				}
				
				yield return FinalizePathInfo(pathInfo);
			}
		}

		public AdaptedSecurityDescriptorPathInformation FinalizePathInfo(AdaptedSecurityDescriptorPathInformation pathInfo) {
			/*
				Since path infos can come from more than one location, this is a way to
				perform specific actions against a finalized one. 
			*/
			
			if (this._bypassAclPermissions > 0) {
				/*
					To bypass the ACL check, we need to get a handle to the object. Only certain objects
					are supported (right now file/folder and registry objects)
				*/			

				WriteDebug(string.Format("FinalizePathInfo(): BypassAclCheck mode; requested permissions = {0}", this._bypassAclPermissions));
				
				if (pathInfo.ObjectType == ResourceType.FileObject) {
					try {
						pathInfo.SdPath = new SecurityDescriptorSafeHandle(
							GetFileHandleWithBackupSemantics(pathInfo.SdPath.ToString(), this._bypassAclPermissions),
							pathInfo.SdPath.ToString()
						);
						pathInfo.BypassAclMode = true;
						WriteDebug("FinalizePathInfo():  -> FileObject; SafeHandle successfully obtained");
					}
					catch (Exception e) {
						WriteWarning(string.Format("Error getting FileObject '{0}' handle in BypassAclCheck mode: {1}", pathInfo.SdPath.ToString(), e.Message));
					}
				}
				else if (pathInfo.ObjectType == ResourceType.RegistryKey) {
					// If pathInfo is for a RegistryKey that had to be converted to a KernelObject,
					// we'll never get here, which is fine)
					
					if (pathInfo.SdPath is SecurityDescriptorStringPath) {
						Microsoft.Win32.RegistryHive hive = 0;
						string hiveString, subKeyPath, pathOptions;
						SplitPath(
							((SecurityDescriptorStringPath) pathInfo.SdPath).Path, 
							out hiveString, 
							out subKeyPath, 
							out pathOptions
						);
						
						switch (hiveString) {
							case "MACHINE":
								hive = Microsoft.Win32.RegistryHive.LocalMachine;
								break;
							case "CURRENT_USER":
								hive = Microsoft.Win32.RegistryHive.CurrentUser;
								break;
							default:
								WriteWarning(string.Format("Unable to bypass ACL check for registry keys in the '{0}' hive", hiveString));
								break;
						}
						
						if (hive != 0) {
							try {
								pathInfo.SdPath = new SecurityDescriptorSafeHandle(
									GetRegistryHandleWithBackupSemantics(
										hive, 
										subKeyPath, 
										this._bypassAclPermissions
									),
									pathInfo.SdPath.ToString()
								);
								//pathInfo.ObjectType = ResourceType.KernelObject;
								pathInfo.BypassAclMode = true;
								WriteDebug("FinalizePathInfo():  -> RegistryKey; SafeHandle successfully obtained");
							}
							catch (Exception e) {
								WriteWarning(string.Format("Error opening '{0}' key in bypass ACL mode: {1}", pathInfo.SdPath.ToString(), e.Message));
							}
						}
					}
				}
				else {
					WriteWarning(string.Format("BypassAclCheck is not implemented for {0} objects", pathInfo.ObjectType));
				}
			}

			else if (pathInfo.SdPath is SecurityDescriptorSafeHandle) {
				// Check to see if handle is closed; if so, bypassAclPermissions must not have been set, so
				// create a new SecurityDescriptorStringPath
				// 
				// This needs to be refactored so that the whole pathInfo object isn't being recreated...
				SecurityDescriptorSafeHandle safeHandleSdPath = (SecurityDescriptorSafeHandle) pathInfo.SdPath;
				if (safeHandleSdPath.Handle.IsClosed) {
					foreach (AdaptedSecurityDescriptorPathInformation currentPathInfo in GetPathInfoFromString(new string[] { pathInfo.SdPath.DisplayName })) {
						pathInfo = currentPathInfo;
						break;
					}
				}
			}
			else if (pathInfo.SdPath is SecurityDescriptorHandleRef) {
				// Check to see if HandleRef is invalid; if so, create a new one (this is only used for Process
				// instances right now)
				SecurityDescriptorHandleRef handleRefSdPath = (SecurityDescriptorHandleRef) pathInfo.SdPath;
				if (handleRefSdPath.IsInvalid) {
					throw new Exception("Cannot change security descriptor for objects with HandleRefs");
				}
			}
			
			return pathInfo;
		}
	

		#region Registry methods
		private static string NormalizeSearchPattern(string searchPattern) {
			// Right now used when searching for registry paths. Function currently takes a string and replaces
			// * with .* and ? with . for Regex matching...
			
			if (string.IsNullOrEmpty(searchPattern)) {
				searchPattern = "*";
			}
			searchPattern = Regex.Escape(searchPattern);
			return string.Format("^{0}$", searchPattern.Replace(@"\*", ".*").Replace(@"\?", "."));
		}
		
		internal IEnumerable<string> ResolveRegistryPathsList(IEnumerable<string> inputPaths, string searchPattern, Microsoft.Win32.RegistryKey baseKey, bool recurse) {

			string normalizedSearchPattern = NormalizeSearchPattern(searchPattern);
			string normalizedCurrentPath;

			foreach (string path in inputPaths) {
				WriteDebug(string.Format(@"ResolveRegistryPath(): Working on {0}\{1}", baseKey.Name, path));
				if (searchPattern == ".") {
					yield return path;
					continue;
				}
				else if (searchPattern == "..") {
throw new Exception("Not ready for .. in registry paths");					
				}
				
				if (string.IsNullOrEmpty(path)) {
					normalizedCurrentPath = string.Empty;
				}
				else {
					normalizedCurrentPath = path + @"\";
				}

				Microsoft.Win32.RegistryKey currentKey;
				try {
					currentKey = baseKey.OpenSubKey(path);
				}
				catch (Exception e) {
					WriteError(new ErrorRecord(
						new Exception(string.Format(@"Error opening key '{0}\{1}': {2}", baseKey.Name, path, e.Message)),
						"TBD",
						ErrorCategory.InvalidData,
						path
					));
					continue;
				}
				
				foreach (string subKeyName in currentKey.GetSubKeyNames()) {
					if (Regex.IsMatch(subKeyName, normalizedSearchPattern, RegexOptions.IgnoreCase)) {
						yield return normalizedCurrentPath + subKeyName;
					}
					
					if (recurse) {
						foreach (string currentRecursiveSubKey in ResolveRegistryPathsList(new List<string> { normalizedCurrentPath + subKeyName }, "*", baseKey, true)) {
							yield return currentRecursiveSubKey;
						}
					}
				}
				currentKey.Dispose();
			}
		}

		private SafeFileHandle GetFileHandleWithBackupSemantics(string fileName, int desiredAccess) {

			WriteDebug(string.Format("GetFileHandleWithBackupSemantics(): Calling CreateFile on '{0}' with desiredAccess = {1}", fileName, desiredAccess));
			return PInvoke.File.CreateFile(
				fileName,
				desiredAccess,
				(uint) (FileShare.ReadWrite | FileShare.Delete),     // Share mode; allow read/write/delete by other processes
				IntPtr.Zero,   // Security attributes; not used
				(uint)FileMode.Open, // Creation disposition; this means only open if it exists
				0x2000000,     // Flags and attributes; this flag means FILE_FLAG_BACKUP_SEMANTICS, which will honor SeBackupPrivilege and SeRestorePrivilege
				IntPtr.Zero    // Template file; not used
			);
		}

		
		private SafeRegistryHandle GetRegistryHandleWithBackupSemantics(Microsoft.Win32.RegistryHive hive, string subKey, int desiredAccess) {
			WriteDebug(string.Format(@"GetRegistryHandleWithBackupSemantics(): Calling RegCreateKeyEx on '{0}\{1}' with desiredAccess = {2}", hive, subKey, desiredAccess));

            SafeRegistryHandle returnHandle;
            Registry.RegResult disposition;

			int exitCode = Registry.RegCreateKeyEx(
				new IntPtr((int) hive),
				subKey,
				0,     // Reserved; should always be 0
				null,  // Class; don't worry about it
				Registry.RegOptions.BackupRestore,  // Options
				desiredAccess,
				IntPtr.Zero,       // Security Attributes
				out returnHandle,
				out disposition
			);
			if (exitCode != 0) {
				throw new Win32Exception(exitCode);
			}

			if (disposition == Registry.RegResult.CreatedNewKey) {
				WriteWarning(string.Format(@"GetRegistryHandleWithBackupSemantics: '{0}\{1}' key was created because it didn't exist"));
			}
			return returnHandle;
		}

		#endregion

		#region File/Folder methods
		internal IEnumerable<AdaptedSecurityDescriptorPathInformation> GetPathInfoFromFilePath(string path, bool recurse, bool includeDirectories, bool includeFiles) {
			
			bool isContainer;
			
			// Make sure path exists, and if it does, find out if it is a file or folder
			if (ROE.ThirdParty.Microsoft.Experimental.IO.LongPathCommon.Exists(path, out isContainer)) {
				if (isContainer & includeDirectories || !isContainer & includeFiles) {
					yield return new AdaptedSecurityDescriptorPathInformation(
						ROE.ThirdParty.Microsoft.Experimental.IO.LongPathCommon.NormalizeLongPath(path), 
						path, 
						ResourceType.FileObject, 
						isContainer
					);
				}

				if (isContainer && recurse) {
					IEnumerable<string> fileSystemEntries = ROE.ThirdParty.Microsoft.Experimental.IO.LongPathDirectory.EnumerateFileSystemEntries(path, "*", true, includeFiles);
					string currentChildPath;

					using (IEnumerator<string> fseEnumerator = fileSystemEntries.GetEnumerator()) {
						while (true) {
							currentChildPath = null;
							try {
								if (!fseEnumerator.MoveNext()) { break; }
								currentChildPath = fseEnumerator.Current;
							}
							catch (Exception e) {
								WriteError(new ErrorRecord(
									new Exception(string.Format("Error enumerating '{0}': {1}", path, e.Message)), 
									"TBD", 
									ErrorCategory.InvalidData, 
									path
								));
							}
							if (currentChildPath != null) { 
								foreach (AdaptedSecurityDescriptorPathInformation pathInfo in GetPathInfoFromFilePath(currentChildPath, recurse, includeDirectories, includeFiles)) {
									yield return pathInfo;
								}
							}
						}
					}
				}
			}
			else {
				WriteError(new ErrorRecord(
					new Exception(string.Format("'{0}' doesn't exist", path)),
					"TBD",
					ErrorCategory.InvalidData,
					path
				));
			}
		}
		

		internal IEnumerable<string> ResolveFilePathsList(IEnumerable<string> inputPaths, string searchPattern, bool includeDirectories, bool includeFiles) {
			foreach (string path in inputPaths) {
				WriteDebug(string.Format("ResolveFilePaths(): Current path = {0}", path));				
				if (searchPattern == ".") {
					/*
						c:\temp\.\test 
						= c:\temp\. + test
						= c:\temp + test
						= c:\temp\test
					
						If searchPattern is a . just return the current path
					*/
					WriteDebug(string.Format("ResolveFilePaths():  -> searchPattern is '{0}', so returning '{1}'", searchPattern, path));

					yield return path;
					continue;
				}
				else if (searchPattern == "..") {
					// Return parent of current path

					string parentPath = null;
					try {
						parentPath = this.SessionState.Path.ParseParent(path, null);
					}
					catch (Exception e) {
						WriteError(new ErrorRecord(
							new Exception(string.Format("Error getting parent for '{0}': {1}", path, e.Message)), 
							"TBD", 
							ErrorCategory.InvalidData, 
							path
						));
					}
					
					if (!string.IsNullOrEmpty(parentPath)) {
						WriteDebug(string.Format("ResolveFilePaths():  -> searchPattern is '{0}', so returning '{1}'", searchPattern, parentPath));
						yield return parentPath;
					}
					continue;
				}
				else if (!ROE.ThirdParty.Microsoft.Experimental.IO.LongPathDirectory.Exists(path)) {
					// This is either a file path, or the path doesn't exist. During normal resolve process, this
					// will happen to files, so don't return error
					continue;
				}

				// Always include directories since path could be something like c:\*\*\*. To get to second *, you must include
				// directories.
				IEnumerable<string> fileSystemEntries = ROE.ThirdParty.Microsoft.Experimental.IO.LongPathDirectory.EnumerateFileSystemEntries(path, searchPattern, true, includeFiles);

				using (IEnumerator<string> fseEnumerator = fileSystemEntries.GetEnumerator()) {
					string currentFsePath;
					while (true) {
						currentFsePath = null;
						try {
							if (!fseEnumerator.MoveNext()) { break; }
							currentFsePath = fseEnumerator.Current;
						}
						catch (Exception e) {
							WriteError(new ErrorRecord(
								new Exception(string.Format("Error enumerating '{0}': {1}", path, e.Message)), 
								"TBD", 
								ErrorCategory.InvalidData, 
								path
							));
							continue;
						}
						yield return currentFsePath;
					}
				}
			}
		}


		#endregion
		

		#region SD methods
		internal IEnumerable<AdaptedSecurityDescriptor> GetAdaptedSecurityDescriptor(PSObject[] inputObjects) {

			AdaptedSecurityDescriptor returnAdaptedSd;
			foreach (PSObject inputObject in inputObjects) {
				if (inputObject.BaseObject is AdaptedSecurityDescriptor) {
					WriteDebug("GetAdaptedSecurityDescriptor(): Current object is already AdaptedSecurityDescriptor; returning this instance");
// requestedSecurityInformation doesn't matter; SD has already been obtained
					yield return (AdaptedSecurityDescriptor) inputObject.BaseObject;
					continue;
				}
				
				WriteDebug("GetAdaptedSecurityDescriptor(): Calling GetPathInfoFromPSObject() on -InputObject");
				foreach (AdaptedSecurityDescriptorPathInformation pathInfo in this.GetPathInfoFromPSObject(new PSObject[] { inputObject })) {
					returnAdaptedSd = null;
					if (inputObject.BaseObject is ObjectSecurity) {
						/*
							Already an ObjectSecurity object, e.g., DirectorySecurity, RegistrySecurity, etc.
							
							If the object was obtained from Get-Acl, PsPath will be attached to it, and we can
							use that information. If it wasn't obtained from Get-Acl, the PathInformation stuff
							will be missing. That's OK if users just want to view the SD, though.
						*/
						WriteDebug("GetAdaptedSecurityDescriptor(): Path information obtained; SD binary form coming from ObjectSecurity instance");
						byte[] binaryForm = ((ObjectSecurity) inputObject.BaseObject).GetSecurityDescriptorBinaryForm();
						try {
// requestedSecurityInformation doesn't matter; the module isn't responsible for getting the SD
							returnAdaptedSd = AdaptedSecurityDescriptor.GetAdaptedSecurityDescriptor(pathInfo, binaryForm);
						}
						catch (Exception e) {
							WriteError(new ErrorRecord(
								new Exception(string.Format("Error converting ObjectSecurity object at '{0}' into AdaptedSecurityDescriptor object: {1}", pathInfo.SdPath.ToString(), e.Message)),
								"TBD",
								ErrorCategory.InvalidData,
								pathInfo
							));
							continue;						
						}
					}
					else if (pathInfo.ObjectType == ResourceType.ProviderDefined) {
						/*
							For now, only ProviderDefined objects are WsMan 'Sddl' objects, and WMI Namespaces.
							To figure out which one, check AccessRightType (this puts the work of figuring out
							what inputObject contains onto GetPathInfo)
						*/
						
						if (pathInfo.AccessRightType == typeof(WmiNamespaceRights)) {
							/*
								CimInstance or ManagementObject

								Until I figure out how to use GetNamedSecurityInfo() or GetSecurityInfo() with
								WMI namespaces, looks like we're stuck invoking the GetSD method (I used GetSD
								instead of GetScurityDescriptor b/c it returns binary form instead of having to
								worry about converting Win32_SecurityDescriptor instance into binary or SDDL
								forms)
							*/
							byte[] binaryForm;
							
							object wmiNamespaceObject = inputObject.BaseObject;

							try {
								
								if (wmiNamespaceObject is AdaptedCommonAce || wmiNamespaceObject is string) {
									// Path should contain the WMI path that will allow us to get the WMI instance
									
									SecurityDescriptorStringPath sdStringPath = pathInfo.SdPath as SecurityDescriptorStringPath;
									
									if (sdStringPath != null) {
										WriteDebug(string.Format("GetAdaptedSecurityDescriptor(): Calling WmiInfo.GetSingleWmiInstance() for WMI path '{0}' (type is {1})", sdStringPath.Path, pathInfo.InstanceType.Name));
										if (pathInfo.InstanceType == typeof(CimInstance)) {
											wmiNamespaceObject = WmiInfo.GetSingleWmiInstance<CimInstance>(sdStringPath.Path);
										}
										else if (pathInfo.InstanceType == typeof(ManagementBaseObject) || pathInfo.InstanceType == typeof(ManagementObject)) {
											wmiNamespaceObject = WmiInfo.GetSingleWmiInstance<ManagementObject>(sdStringPath.Path);
										}
									}
								
								}
							
								if (wmiNamespaceObject is ManagementObject) {
									ManagementBaseObject results = ((ManagementObject) wmiNamespaceObject).InvokeMethod(
										"GetSD",
										null,
										null
									);
			 
									binaryForm = (byte[]) results.Properties["SD"].Value;

								}
								else if (wmiNamespaceObject is CimInstance) {
									CimInstance cimInstance = (CimInstance) wmiNamespaceObject;
									CimMethodResult results;

									CimSession cimSession = CimSession.Create(cimInstance.GetCimSessionComputerName());
									results = cimSession.InvokeMethod(cimInstance, "GetSD", null);
									
									binaryForm = (byte[]) results.OutParameters["SD"].Value;
								}
								else {
									WriteError(new ErrorRecord(
										new Exception("inputObject is not WMI object"),
										"",
										ErrorCategory.InvalidData,
										inputObject.BaseObject
									));
									continue;
								}

// requestedSecurityInformation doesn't matter; module isn't responsible for getting the SD
								returnAdaptedSd = new AdaptedSecurityDescriptor(pathInfo, binaryForm, 0);					
							}
							catch (Exception e) {
								WriteError(new ErrorRecord(
									new Exception(string.Format("Error getting security descriptor for WMI object: {0}", e.Message)),
									"TBD",
									ErrorCategory.InvalidData,
									pathInfo
								));
								continue;
							}
						}
						else if (pathInfo.AccessRightType == typeof(WsManAccessRights)) {

							if (inputObject.Properties["Name"].Value.ToString() != "Sddl") {
								WriteError(new ErrorRecord(
									new Exception(string.Format("inputObject type is unsupported: {0}", inputObject.Properties["Name"].Value.ToString())),
									"TBD",
									ErrorCategory.InvalidData,
									inputObject
								));
								continue;
							}

							try {
// requestedSecurityInformation doesn't matter; module isn't responsible for getting the SD
								returnAdaptedSd = new AdaptedSecurityDescriptor(pathInfo, inputObject.Properties["Value"].Value.ToString());
							}
							catch (Exception e) {
								WriteError(new ErrorRecord(
									new Exception(string.Format("Error creating adapted SD for WSMan object: {0}", e.Message)),
									"TBD",
									ErrorCategory.InvalidData,
									inputObject
								));
								continue;
							}
						}
						else {
							WriteError(new ErrorRecord(
								new Exception(string.Format("inputObject has ProviderDefined type, but type is unsupported: {0}", inputObject.BaseObject.GetType().FullName)),
								"TBD",
								ErrorCategory.InvalidData,
								inputObject
							));
							continue;
						}
					}
					
					else if (pathInfo.ObjectType != ResourceType.Unknown && pathInfo.SdPath != null) {
						/*
							GetPathInfo() must have gotten some info from the object, but we don't have
							the binary or SDDL forms of the SD. That means we'll need to depend on the
							AdaptedSecurityDescriptor constructor to look it up
						*/
						WriteDebug("GetAdaptedSecurityDescriptor(): Getting binary form of security descriptor");
						GetSecurityInformation getSdSections = this._securityDescriptorSections;
						if (getSdSections == 0) { getSdSections = PacSdOption.DefaultGetSecurityDescriptorSections; }
						
						try {
							byte[] binaryForm = GetSecurityInfo(pathInfo, getSdSections);
							returnAdaptedSd = AdaptedSecurityDescriptor.GetAdaptedSecurityDescriptor(pathInfo, binaryForm, getSdSections);
						}
						catch (Exception e) {
							WriteError(new ErrorRecord(
								new Exception(string.Format("Error getting security descriptor for {0} object with path '{1}': {2}", pathInfo.ObjectType, pathInfo.SdPath, e.Message)),
								"TBD",
								ErrorCategory.InvalidData,
								inputObject
							));
							continue;
						}
					}
					
					else {
						/*
							Unknown object type.
						*/
						
						WriteError(new ErrorRecord(
							new Exception(string.Format("Unknown object type: {0}", inputObject.BaseObject.GetType().FullName)),
							"TBD",
							ErrorCategory.InvalidData,
							inputObject
						));
						continue;
					}
				
					if (returnAdaptedSd.AreAccessRulesCanonical == false) {
						WriteWarning(string.Format("Access rules for '{0}' are not in canonical order", returnAdaptedSd.Path));
					}
					if (returnAdaptedSd.AreAuditRulesCanonical == false) {
						WriteWarning(string.Format("Audit rules for '{0}' are not in canonical order", returnAdaptedSd.Path));
					}
					
					yield return returnAdaptedSd;
				}
			}
		}
		
		internal IEnumerable<AdaptedSecurityDescriptor> GetAdaptedSecurityDescriptor(IEnumerable<AdaptedSecurityDescriptorPathInformation> pathInfoObjects) {
			WriteDebug("GetAdaptedSecurityDescriptor(): IEnumerable pathInfo overload");
			AdaptedSecurityDescriptor returnAdaptedSd;
			GetSecurityInformation getSdSections = this._securityDescriptorSections;
			if (getSdSections == 0) { getSdSections = PacSdOption.DefaultGetSecurityDescriptorSections; }

			byte[] binaryForm;
			foreach (AdaptedSecurityDescriptorPathInformation pathInfo in pathInfoObjects) {
				binaryForm = null;
				try {
					binaryForm = GetSecurityInfo(pathInfo, getSdSections);
					returnAdaptedSd = AdaptedSecurityDescriptor.GetAdaptedSecurityDescriptor(pathInfo, binaryForm, getSdSections);
				}	
				catch (Exception e) {
					WriteError(new ErrorRecord(
						new Exception(string.Format("Error getting security descriptor for {0} object with path {1}: {2}", pathInfo.ObjectType, pathInfo.SdPath, e.Message)),
						"TBD",
						ErrorCategory.InvalidData,
						pathInfo
					));
					continue;
				
				}
				
				yield return returnAdaptedSd;
			}
		}
		
		internal byte[] GetSecurityInfo(AdaptedSecurityDescriptorPathInformation pathInfo, GetSecurityInformation requestedSecurityInformation) {
			IntPtr pOwner, pGroup, pDacl, pSacl, pSecurityDescriptor;
			pOwner = pGroup = pDacl = pSacl = pSecurityDescriptor = IntPtr.Zero;
			uint exitCode;
			SecurityInformation securityInformation = (SecurityInformation) (int) requestedSecurityInformation;

			WriteDebug( string.Format("GetSecurityInfo(): Getting binary SD info for path '{0}'", pathInfo.SdPath.ToString()) );
			WriteDebug( string.Format("GetSecurityInfo():  -> BypassAclCheck enabled? {0}", pathInfo.BypassAclMode) );
			ResourceType objectType = pathInfo.ObjectType;
			if (pathInfo.BypassAclMode && (objectType == ResourceType.RegistryKey || objectType == ResourceType.RegistryWow6432Key)) {
				objectType = ResourceType.KernelObject;
			}
			
			SecurityDescriptorPath sdPath = pathInfo.SdPath;
			if (sdPath is SecurityDescriptorStringPath) {
WriteDebug(string.Format("sdPath is SecurityDescriptorStringPath: {0}", ((SecurityDescriptorStringPath) sdPath).Path));
				exitCode = NativeMethods.GetNamedSecurityInfo(
					((SecurityDescriptorStringPath) sdPath).Path, 
					objectType, 
					securityInformation, 
					out pOwner, 
					out pGroup, 
					out pDacl, 
					out pSacl, 
					out pSecurityDescriptor
				);
			}
			else if (sdPath is SecurityDescriptorSafeHandle) {

				SecurityDescriptorSafeHandle safeHandleSdPath = (SecurityDescriptorSafeHandle) sdPath;

				if (safeHandleSdPath.Handle.IsClosed || safeHandleSdPath.Handle.IsInvalid) {
// This only fixes if BypassAclMode was used and handle was closed b/c of that; if SafeHandle was used outside of that, this won't fix it being closed or invalid
					WriteDebug("GetSecurityInfo(): Current path info SafeHandle is closed or invalid; calling FinalizePathInfo()");
					pathInfo = FinalizePathInfo(pathInfo);
					
					safeHandleSdPath = (SecurityDescriptorSafeHandle) pathInfo.SdPath;
				}
				
				exitCode = NativeMethods.GetSecurityInfo(
					safeHandleSdPath.Handle, 
					objectType, 
					securityInformation, 
					out pOwner, 
					out pGroup, 
					out pDacl, 
					out pSacl, 
					out pSecurityDescriptor
				);
				
				if (pathInfo.BypassAclMode) {
					// Close handle (SetSecurityInfo() can re-open it if necessary)
					WriteDebug("GetSecurityInfo(): Closing BypassAclMode handle");
					safeHandleSdPath.Handle.Dispose();
				}
			}
			else if (sdPath is SecurityDescriptorHandleRef) {
				
				SecurityDescriptorHandleRef handleRefSdPath = (SecurityDescriptorHandleRef) sdPath;
				
				if (handleRefSdPath.IsInvalid) {
					WriteDebug("GetSecurityInfo(): Current path info HandleRef is invalid; calling FinalizePathInfo() to get a new valid HandleRef");
					pathInfo = FinalizePathInfo(pathInfo);
					
					handleRefSdPath = (SecurityDescriptorHandleRef) sdPath;
				}
				
				exitCode = NativeMethods.GetSecurityInfo(
					handleRefSdPath.Handle, 
					objectType, 
					securityInformation, 
					out pOwner, 
					out pGroup, 
					out pDacl, 
					out pSacl, 
					out pSecurityDescriptor
				);
				
				WriteDebug("GetSecurityInfo(): Clearing reference to HandleRef");
				handleRefSdPath.SetHandleRefAsInvalid();
			}
			else {
				throw new Exception("Unknown Path format");
			}

			WriteDebug(string.Format("GetSecurityInfo():  -> Function exited with code {0}", exitCode));			
			if (exitCode != 0) {
				throw new Win32Exception((int)exitCode);
			}

			// I've seen this happen with ADMIN shares, e.g., \\.\c$. exitCode is 0, but
			// no SD is returned
			if (pSecurityDescriptor == IntPtr.Zero) {
				throw new Exception("No security descriptor available");
			}

			byte[] binarySd;
			try {
				int sdSize = NativeMethods.GetSecurityDescriptorLength(pSecurityDescriptor);
				
				binarySd = new byte[sdSize];
				Marshal.Copy(pSecurityDescriptor, binarySd, 0, sdSize);
				WriteDebug(string.Format("GetSecurityInfo():  -> SD is {0} bytes",  sdSize));			
			}
			catch(Exception e) {
				throw e;
			}
			finally {
				if (kernel32.LocalFree(pSecurityDescriptor) != IntPtr.Zero) {
					WriteError(new ErrorRecord(
						new Exception(String.Format("Error freeing memory for security descriptor at path '{0}'", sdPath.ToString())),
						"",
						ErrorCategory.InvalidData,
						sdPath
					));
				}
			}
			
			return binarySd;
		}
		#endregion
		#endregion

		static class NativeMethods {
            // http://msdn.microsoft.com/en-us/library/windows/desktop/aa446645%28v=vs.85%29.aspx
            [DllImport("advapi32.dll", EntryPoint = "GetNamedSecurityInfoW", CharSet = CharSet.Unicode)]
            internal static extern uint GetNamedSecurityInfo(
                string ObjectName,
                System.Security.AccessControl.ResourceType ObjectType,
                SecurityInformation SecurityInfo,
                out IntPtr pSidOwner,
                out IntPtr pSidGroup,
                out IntPtr pDacl,
                out IntPtr pSacl,
                out IntPtr pSecurityDescriptor
            );

            // http://msdn.microsoft.com/en-us/library/windows/desktop/aa446654%28v=vs.85%29.aspx
            [DllImport("advapi32.dll", SetLastError=true)]
            internal static extern uint GetSecurityInfo(
                HandleRef handle,
                System.Security.AccessControl.ResourceType ObjectType,
                SecurityInformation SecurityInfo,
                out IntPtr pSidOwner,
                out IntPtr pSidGroup,
                out IntPtr pDacl,
                out IntPtr pSacl,
                out IntPtr pSecurityDescriptor
            );

            [DllImport("advapi32.dll", SetLastError=true)]
            internal static extern uint GetSecurityInfo(
                SafeHandle handle,
                System.Security.AccessControl.ResourceType ObjectType,
                SecurityInformation SecurityInfo,
                out IntPtr pSidOwner,
                out IntPtr pSidGroup,
                out IntPtr pDacl,
                out IntPtr pSacl,
                out IntPtr pSecurityDescriptor
            );

            // http://msdn.microsoft.com/en-us/library/windows/desktop/aa446650%28v=vs.85%29.aspx
            [DllImport("advapi32.dll")]
            internal static extern Int32 GetSecurityDescriptorLength(
                IntPtr pSecurityDescriptor
            );
		}
	}


	

	public class PacModuleModificationCmdlet : PacModuleCmdlet {
		[Parameter()]
		public SwitchParameter Apply { get; set; }
		protected bool _currentApply;  // Changed by helper methods if non SD object is being used

		[Parameter()]
        public SwitchParameter PassThru { get; set; }

		[Parameter()]
        public SwitchParameter Force { get; set; }

		// Used for ShouldContinue call in SetSecurityInfo method
		bool _setSecurityInfoShouldContinueYesToAll = false;
		bool _setSecurityInfoShouldContinueNoToAll = false;
		
		protected override void BeginProcessing() {
			base.BeginProcessing();

			if (this.PacSDOption.BypassAclCheck && this.Apply) {
// Also put a check to see if WhatIf is active; should this be done if part of -WhatIf check?

				WriteDebug("BypassAclCheck option was passed; enabling 'SeBackupPrivilege'");
				if (EnablePrivilege("SeRestorePrivilege")) {
					_bypassAclPermissions |= (int) (FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership);
				}
			}
			
			this._currentApply = this.Apply;
		}

		protected void SetCurrentApplySwitch() {
			// _currentApply is what is tested against each SD object (can be used more than once in each
			// ProcessRecord() iteration).
			//
			// Methods can call this when they've detected an input object that is not a security descriptor.
			// If that happens, this method will check to see if Apply and/or PassThru were passed as
			// parameters. If not, this method will set _currentApply to true
			if (!( this.MyInvocation.BoundParameters.ContainsKey("Apply") || this.MyInvocation.BoundParameters.ContainsKey("PassThru"))) {
				WriteDebug("SetCurrentApplySwitch(): Apply and PassThru not passed as parameters; setting _currentApply to true");
				this._currentApply = true;
			}
		}
		
		protected void ResetCurrentApplySwitch() {
			//
			if (this._currentApply != this.Apply) {
				WriteDebug(string.Format("ResetCurrentApplySwitch(): Setting current apply switch from {0} back to -Apply value of {1}", this._currentApply, this.Apply));
				this._currentApply = this.Apply;
			}
		}

		// Used by Add-Ace, Remove-Ace, Enable/Disable-AclInheritance, etc to be able to return an ObjectSecurity (wrapped by PSObject)
		// or an AdaptedSecurityObject. That enables those commands to still work with actual ObjectSecurity classes w/o converting them
		// to ADaptedSecurityDescriptor objects.
		internal IEnumerable<object> GetObjectSecurityPSObjectOrAdaptedSecurityDescriptorObject(PSObject[] inputPSObjects) {
			foreach (PSObject currentPSObject in inputPSObjects) {
				if (currentPSObject.BaseObject is ObjectSecurity) {
					// Already in acceptable format, just send object back out
					// (sending as PSObject to retain path information; caller
					// will know to check for PSObject)
					yield return currentPSObject;
				}
				else if (currentPSObject.BaseObject is AdaptedSecurityDescriptor) {
					// Already in acceptable format. Notice that real SD object is being returned
					yield return currentPSObject.BaseObject;
				}
				else {
					this.SetCurrentApplySwitch();
					foreach (AdaptedSecurityDescriptor currentAdaptedSd in GetAdaptedSecurityDescriptor(new PSObject[] { currentPSObject })) {
						yield return currentAdaptedSd;
					}
				}
			}
		}

		private SecurityInformation GetFinalSecurityInformationSections(SecurityInformation startingSections, dynamic securityDescriptor) {
			SecurityInformation finalSections = startingSections;
			
			if (securityDescriptor != null && (finalSections & SecurityInformation.Dacl) != 0) {
				// Need to set bit specifying whether or not Dacl is protect or unprotected
				if (securityDescriptor.AreAccessRulesProtected == true) {
					finalSections |= SecurityInformation.ProtectedDacl;
				}
				else {
					finalSections |= SecurityInformation.UnprotectedDacl;
				}
			}
			else if ((finalSections & (SecurityInformation.ProtectedDacl | SecurityInformation.UnprotectedDacl)) != 0) {
				finalSections |= SecurityInformation.Dacl;
			}

			if (securityDescriptor != null && (finalSections & SecurityInformation.Sacl) != 0) {
				// Need to set bit specifying whether or not Dacl is protect or unprotected
				if (securityDescriptor.AreAuditRulesProtected == true) {
					finalSections |= SecurityInformation.ProtectedSacl;
				}
				else {
					finalSections |= SecurityInformation.UnprotectedSacl;
				}
			}
			else if ((finalSections & (SecurityInformation.ProtectedSacl | SecurityInformation.UnprotectedSacl)) != 0) {
				finalSections |= SecurityInformation.Sacl;
			}
			
			return finalSections;
		}

		internal SecurityInformation GetSecurityInformationSections(dynamic securityDescriptor) {

			SecurityInformation sdSections;

			if (this.MyInvocation.BoundParameters.ContainsKey("PacSDOption") && this.PacSDOption.SecurityDescriptorSections != 0) {
				// If -PacSDOption was specified, those sections will be used since the user said
				// they wanted them...
				sdSections = (SecurityInformation) this.PacSDOption.SecurityDescriptorSections;
			}
			else if (securityDescriptor is AdaptedSecurityDescriptor) {
				// Get most accurate modified info
				sdSections = securityDescriptor.GetModifiedSecurityInformation();
			}
			else if (securityDescriptor is ObjectSecurity) {

				// Not the best way to do this, but maybe it'll work?
				
				sdSections = 0;
				if ( !( string.IsNullOrEmpty(securityDescriptor.GetSecurityDescriptorSddlForm(AccessControlSections.Owner)) )) {
					sdSections |= SecurityInformation.Owner;
				}

				if ( !( string.IsNullOrEmpty(securityDescriptor.GetSecurityDescriptorSddlForm(AccessControlSections.Group)) )) {
					sdSections |= SecurityInformation.Group;
				}

				if ( !( string.IsNullOrEmpty(securityDescriptor.GetSecurityDescriptorSddlForm(AccessControlSections.Access)) )) {
					sdSections |= SecurityInformation.Dacl;
				}

				if ( !( string.IsNullOrEmpty(securityDescriptor.GetSecurityDescriptorSddlForm(AccessControlSections.Audit)) )) {
					sdSections |= SecurityInformation.Sacl;
				}
			}
			else {
throw new Exception("Unknown SD type; this should be ErrorRecord");				
			}

			WriteDebug(string.Format("GetSecurityInformationSections(): Returning the following SD sections: {0}", sdSections));
			return sdSections;
		}

		internal void SetPacSecurityDescriptor(PSObject[] inputObject, AdaptedSecurityDescriptor adaptedSdObject, SecurityInformation setSdSections) {
			
//			SecurityInformation setSdSections = GetSecurityInformationSections(adaptedSdObject);
			
			foreach (AdaptedSecurityDescriptorPathInformation pathInfo in GetPathInfoFromPSObject( inputObject ) ) {

				if (pathInfo.ObjectType != adaptedSdObject.ObjectType && !(pathInfo.ObjectType.ToString().StartsWith("Registry") && adaptedSdObject.ObjectType.ToString().StartsWith("Registry"))) {
					// Object types don't match
					WriteError(new ErrorRecord(
						new Exception(string.Format("'{0}' object type ({1}) doesn't match the object type for '{2}' ({3})", adaptedSdObject.Path.ToString(), adaptedSdObject.ObjectType, pathInfo.SdPath.ToString(), pathInfo.ObjectType)),
						"",
						ErrorCategory.InvalidData,
						pathInfo
					));
					continue;
				}
				
				if (ShouldProcess(
						string.Format("Set security descriptor for '{0}' {1} ({2})", pathInfo.SdPath.ToString(), pathInfo.ObjectType, setSdSections),
						string.Format("Do you want to set the security descriptor for '{0}' {1} ({2} sections)", pathInfo.SdPath.ToString(), pathInfo.ObjectType, setSdSections),
						"Set Security Descriptor"
					)) {

					SetSecurityInfo(pathInfo, adaptedSdObject, GetFinalSecurityInformationSections(setSdSections, adaptedSdObject));
				}
			}
		}

		internal void SetSecurityInfo(AdaptedSecurityDescriptorPathInformation pathInfo, AdaptedSecurityDescriptor adaptedSD, SecurityInformation securityInformation) {
			
			if (securityInformation == 0) { return; }

			string shouldContinueTitle = "Set Security Descriptor";
			string shouldContinueFormatter = "Do you want to set the security descriptor with the following properties on the '{0}' {1}?\n\n{2}";

			RawSecurityDescriptor rawSD = adaptedSD.RawSD;

			if (pathInfo.ObjectType == ResourceType.ProviderDefined) {

				// ProviderDefined means we can't depend on the Win32 call to set the SD
				
				// For now, all sections are set when SD is set, so change securityInformation to reflect that:
				securityInformation = SecurityInformation.Owner | SecurityInformation.Group | SecurityInformation.Dacl | SecurityInformation.Sacl;

				if (this.Force || ShouldContinue(
					string.Format(
						shouldContinueFormatter, 
						pathInfo.SdPath.ToString(), 
						pathInfo.ObjectType, 
						adaptedSD.ToString(securityInformation, 0, false, false, true)
					),
					shouldContinueTitle,
					ref this._setSecurityInfoShouldContinueYesToAll,
					ref this._setSecurityInfoShouldContinueNoToAll
				)) {

					string providerPath = null;
					if (pathInfo.SdPath is SecurityDescriptorStringPath) {
						providerPath = ((SecurityDescriptorStringPath) pathInfo.SdPath).Path;
					}
					
					if (pathInfo.InstanceType == typeof(ManagementBaseObject) || pathInfo.InstanceType == typeof(ManagementObject) || pathInfo.InstanceType == typeof(CimInstance)) {

						dynamic invokeCmdletInstance;
					
						if (pathInfo.InstanceType == typeof(CimInstance)) {

							CimInstance cimInstance;
							try {
								cimInstance = WmiInfo.GetSingleWmiInstance<CimInstance>(providerPath);
							}
							catch (Exception e) {
								WriteError(new ErrorRecord(
									new Exception(string.Format("Error getting WMI object for instance with path '{0}': {1}", providerPath, e.Message)),
									"",
									ErrorCategory.InvalidData,
									providerPath
								));
								return;
							}
							
							invokeCmdletInstance = new Microsoft.Management.Infrastructure.CimCmdlets.InvokeCimMethodCommand();
							invokeCmdletInstance.InputObject = cimInstance;
							invokeCmdletInstance.MethodName = "SetSD";
							
							Hashtable argumentHt = new Hashtable();
							argumentHt.Add("SD", adaptedSD.GetSecurityDescriptorBinaryForm());
							invokeCmdletInstance.Arguments = argumentHt;
						}
						else {
							ManagementObject wmiObject;
							try {
								wmiObject = WmiInfo.GetSingleWmiInstance<ManagementObject>(providerPath);
							}
							catch (Exception e) {
								WriteError(new ErrorRecord(
									new Exception(string.Format("Error getting WMI object for instance with path '{0}': {1}", providerPath, e.Message)),
									"",
									ErrorCategory.InvalidData,
									providerPath
								));
								return;
							}

							invokeCmdletInstance = new Microsoft.PowerShell.Commands.InvokeWmiMethod();
							invokeCmdletInstance.InputObject = wmiObject;
							invokeCmdletInstance.Name = "SetSD";
							invokeCmdletInstance.EnableAllPrivileges = true;
							invokeCmdletInstance.ArgumentList = new object[1] { adaptedSD.GetSecurityDescriptorBinaryForm() };
						}
						
						
						try {
							foreach (dynamic invokeResult in invokeCmdletInstance.Invoke()) {
								uint returnValue;
								
								if (invokeResult is ManagementBaseObject) {
									returnValue = (uint) WmiInfo.GetPropertyDictionary(invokeResult)["ReturnValue"];
								}
								else if (invokeResult is PSObject) {
									returnValue = (uint) ((PSObject) invokeResult).Properties["ReturnValue"].Value;
								}
								else {
									WriteWarning(string.Format("Unknown return type from call to {0}: {1}", invokeCmdletInstance.GetType().Name, invokeResult.GetType().FullName));
									continue;
								}

								WriteDebug(string.Format("SetSecurityInfo(): Invoking SetSD WMI method ({0}) return code = {1}", invokeCmdletInstance.GetType().Name, returnValue));								
								if (returnValue != 0) {
									WriteError(new ErrorRecord(
										new Exception(string.Format("Invoking SetSD WMI method on '{0}' returned exit code {1}", providerPath, returnValue)),
										"",
										ErrorCategory.InvalidData,
										providerPath
									));
									return;
								}
							}
							
						}
						catch (Exception e) {
							WriteError(new ErrorRecord(
								new Exception(string.Format("Error invoking SetSD WMI method on '{0}': {1}", providerPath, e.Message)),
								"",
								ErrorCategory.InvalidData,
								providerPath
							));
							return;
						}
					}
					else if (pathInfo.InstanceType.FullName == "Microsoft.WSMan.Management.WSManConfigLeafElement") {
						string wsmanPath = null, sddlValue = null;
						if (pathInfo.SdPath is SecurityDescriptorStringPath) {
							wsmanPath = ((SecurityDescriptorStringPath) pathInfo.SdPath).Path;
						}
						
						sddlValue = adaptedSD.GetSecurityDescriptorSddlForm();

						WriteDebug(string.Format("Calling Set-Item with Path = '{0}' and Value = '{1}'", wsmanPath, sddlValue));
						using (PowerShell ps = PowerShell.Create()) {

							Hashtable psParams = new Hashtable();
							psParams.Add("Force", true);
							psParams.Add("Path", wsmanPath);
							psParams.Add("Value", sddlValue);
							
							ps.AddCommand("Set-Item").AddParameters(psParams);

							ps.Invoke();
						}
						
						
					}
					else {
						WriteWarning(string.Format("{0} instances aren't supported by Set-SecurityDescriptor; no changes will be made", pathInfo.InstanceType.FullName));
					}
				}
			}
			else {
				// Non provider defined
				
				#region Get binary forms
				byte[] ownerBinaryForm, groupBinaryForm, daclBinaryForm, saclBinaryForm;
				if (rawSD.Owner != null) {
					ownerBinaryForm = new byte[rawSD.Owner.BinaryLength];
					rawSD.Owner.GetBinaryForm(ownerBinaryForm, 0);
				}
				else {
					ownerBinaryForm = new byte[0];
				}
				
				if (rawSD.Group != null) {
					groupBinaryForm = new byte[rawSD.Group.BinaryLength];
					rawSD.Group.GetBinaryForm(groupBinaryForm, 0);
				}
				else {
					groupBinaryForm = new byte[0];
				}
				
				if (rawSD.DiscretionaryAcl != null) {
					daclBinaryForm = new byte[rawSD.DiscretionaryAcl.BinaryLength];
					rawSD.DiscretionaryAcl.GetBinaryForm(daclBinaryForm, 0);
				}
				else {
					daclBinaryForm = new byte[0];
				}
				
				if (rawSD.SystemAcl != null) {
					saclBinaryForm = new byte[rawSD.SystemAcl.BinaryLength];
					rawSD.SystemAcl.GetBinaryForm(saclBinaryForm, 0);
				}
				else {
					saclBinaryForm = new byte[0];
				}
				#endregion

				int exitCode;
				ResourceType objectType = pathInfo.ObjectType;

				if (this.PacSDOption.BypassAclCheck && (objectType == ResourceType.RegistryKey || objectType == ResourceType.RegistryWow6432Key)) {
					objectType = ResourceType.KernelObject;
				}
				
				SecurityDescriptorPath sdPath = pathInfo.SdPath;

				WriteDebug(string.Format("SetSecurityInfo() for {0} with path of '{1}' ({3}) and sections '{2}' (SD size is {4})", objectType, sdPath, securityInformation, sdPath.GetType().Name, rawSD.BinaryLength));
				
				if (this.Force || ShouldContinue(
					string.Format(
						shouldContinueFormatter, 
						pathInfo.SdPath.ToString(), 
						pathInfo.ObjectType, 
						adaptedSD.ToString(securityInformation, 0, false, false, true)
					),
					shouldContinueTitle,
					ref this._setSecurityInfoShouldContinueYesToAll,
					ref this._setSecurityInfoShouldContinueNoToAll
				)) {

					if ((securityInformation & SecurityInformation.Owner) != 0) {
						this.EnablePrivilege("SeTakeOwnershipPrivilege");
						this.EnablePrivilege("SeRestorePrivilege");
					}

					if ((securityInformation & SecurityInformation.Sacl) != 0) {
						this.EnablePrivilege("SeSecurityPrivilege");
					}

					if (sdPath is SecurityDescriptorStringPath) {
						exitCode = NativeMethods.SetNamedSecurityInfo(
							((SecurityDescriptorStringPath) sdPath).Path, 
							objectType, 
							securityInformation, 
							ownerBinaryForm, 
							groupBinaryForm, 
							daclBinaryForm, 
							saclBinaryForm
						);
					}
					else if (sdPath is SecurityDescriptorSafeHandle) {
						SecurityDescriptorSafeHandle safeHandleSdPath = (SecurityDescriptorSafeHandle) sdPath;

						if (safeHandleSdPath.Handle.IsClosed || safeHandleSdPath.Handle.IsInvalid) {
	// This only fixes if BypassAclMode was used and handle was closed b/c of that; if SafeHandle was used outside of that, this won't fix it being closed or invalid
							WriteDebug("SetSecurityInfo(): Current path info SafeHandle is closed or invalid; calling FinalizePathInfo()");
							pathInfo = FinalizePathInfo(pathInfo);
							
							safeHandleSdPath = (SecurityDescriptorSafeHandle) pathInfo.SdPath;
						}

						exitCode = NativeMethods.SetSecurityInfo(
							((SecurityDescriptorSafeHandle) sdPath).Handle, 
							objectType, 
							securityInformation, 
							ownerBinaryForm, 
							groupBinaryForm, 
							daclBinaryForm, 
							saclBinaryForm
						);

						if (pathInfo.BypassAclMode) {
							// Close handle (SetSecurityInfo() can re-open it if necessary)
							WriteDebug("SetSecurityInfo(): Closing BypassAclMode handle");
							safeHandleSdPath.Handle.Dispose();
						}
					}
					else if (sdPath is SecurityDescriptorHandleRef) {
						SecurityDescriptorHandleRef handleRefSdPath = (SecurityDescriptorHandleRef) sdPath;
						
						if (handleRefSdPath.IsInvalid) {
							WriteDebug("SetSecurityInfo(): Current path info HandleRef is invalid; calling FinalizePathInfo() to get a new valid HandleRef");
							pathInfo = FinalizePathInfo(pathInfo);
							
							handleRefSdPath = (SecurityDescriptorHandleRef) sdPath;
						}

						exitCode = NativeMethods.SetSecurityInfo(
							handleRefSdPath.Handle, 
							objectType, 
							securityInformation, 
							ownerBinaryForm, 
							groupBinaryForm, 
							daclBinaryForm, 
							saclBinaryForm
						);
						WriteWarning(string.Format("DEBUG: Security descriptor for '{0}' set; need to release HandleRef?", sdPath));
					}
					else {
						throw new Exception("Unknown Path format");
					}
					
					if (exitCode != 0) {
						WriteError(new ErrorRecord(
							new Exception(string.Format("Error setting security descriptor on '{0}' ({1}): {2}", sdPath.ToString(), objectType, (new Win32Exception(exitCode)).Message)),
							"",
							ErrorCategory.InvalidData,
							pathInfo
						));
					}
				}
			}
		}
		
		static class NativeMethods {
            // http://msdn.microsoft.com/en-us/library/windows/desktop/aa379579%28v=vs.85%29.aspx
            [DllImport("advapi32.dll", EntryPoint = "SetNamedSecurityInfoW", CharSet = CharSet.Unicode)]
            public static extern int SetNamedSecurityInfo(
                string ObjectName,
                System.Security.AccessControl.ResourceType ObjectType,
                SecurityInformation SecurityInfo,
                byte[] pSidOwner,
                byte[] pSidGroup,
                byte[] pDacl,
                byte[] pSacl
            );

            // http://msdn.microsoft.com/en-us/library/windows/desktop/aa379588(v=vs.85).aspx
            [DllImport("advapi32.dll")]
            public static extern int SetSecurityInfo(
                HandleRef handle,
                System.Security.AccessControl.ResourceType ObjectType,
                SecurityInformation SecurityInfo,
                byte[] pSidOwner,
                byte[] pSidGroup,
                byte[] pDacl,
                byte[] pSacl
            );

            [DllImport("advapi32.dll")]
            public static extern int SetSecurityInfo(
                SafeHandle handle,
                System.Security.AccessControl.ResourceType ObjectType,
                SecurityInformation SecurityInfo,
                byte[] pSidOwner,
                byte[] pSidGroup,
                byte[] pDacl,
                byte[] pSacl
            );
		
		}
	}
}