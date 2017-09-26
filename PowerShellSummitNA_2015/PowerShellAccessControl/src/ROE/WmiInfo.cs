namespace ROE.PowerShellAccessControl {

	public class WmiInfo {
		public WmiInfo(ManagementBaseObject wmiObject) {
			ClassName = wmiObject.Properties["__CLASS"].Value.ToString();
			ComputerName = wmiObject.Properties["__SERVER"].Value.ToString();
			Path = wmiObject.Properties["__PATH"].Value.ToString();
			Namespace = wmiObject.Properties["__NAMESPACE"].Value.ToString();
//			InstanceType = wmiObject.GetType();
		}
		
		public WmiInfo(CimInstance cimObject) {
			ClassName = cimObject.CimSystemProperties.ClassName;
			ComputerName = cimObject.CimSystemProperties.ServerName;
			Path = GetWmiPath(cimObject);
			Namespace = cimObject.CimSystemProperties.Namespace;
//			InstanceType = cimObject.GetType();
		}
		
		public string ClassName { get; private set; }
		public string ComputerName { get; private set; }
		public string Path { get; private set; }
		public string Namespace { get; private set; }
//		public Type InstanceType { get; private set; }

		public static string GetWmiPath(ManagementBaseObject wmiObject) {
			return wmiObject.Properties["__PATH"].Value.ToString();
		}

		internal static string ValidWmiPathRegex = @"^\\\\(?<computername>[^\\]*)\\(?<namespace>[^:]*):(?<classname>[^=\.]*)(?<separator>\.|(=@))(?<keyvaluepairs>.*)?$";
		public static bool TestIsValidWmiPath(string path) {
			return Regex.Match(path, ValidWmiPathRegex).Success;
		}

		public static T GetSingleWmiInstance<T>(string wmiPath) {
			
			if (typeof(T) == typeof(CimInstance)) {
				// Confirm it's a valid path:

				Match cimMatch = Regex.Match(wmiPath, ValidWmiPathRegex);

				if (cimMatch.Success == false) {
					throw new Exception("WMI path is in unknown format");
				}

				using (Microsoft.Management.Infrastructure.CimCmdlets.GetCimInstanceCommand getCimInstance = new Microsoft.Management.Infrastructure.CimCmdlets.GetCimInstanceCommand()) {
					getCimInstance.ComputerName = new string[] { cimMatch.Groups["computername"].Value };
					getCimInstance.Namespace = cimMatch.Groups["namespace"].Value;
					getCimInstance.ClassName = cimMatch.Groups["classname"].Value;
					
					if (cimMatch.Groups["separator"].Value == ".") {
						getCimInstance.Filter = string.Join(
							" AND ",
							cimMatch.Groups["keyvaluepairs"].Value.Split(',')
						);
					}

					foreach (CimInstance cimInstance in getCimInstance.Invoke<CimInstance>()) {
						return (T) Convert.ChangeType(cimInstance, typeof(T));
					}
				}
			}
			else if (typeof(T) == typeof(ManagementObject) || typeof(T) == typeof(ManagementBaseObject)) {
				ManagementObject wmiObject = new ManagementObject(wmiPath);
				
				return (T) Convert.ChangeType(wmiObject, typeof(T));
			}
			
			
			throw new Exception(string.Format("Unknown return type: {0}", typeof(T).FullName));
		}

		public static string GetWmiPath(CimInstance cimObject) {
			// Get key value pairs:
			List<string> keyValuePairs = new List<string>();
			bool isKeyProperty;
			string formatter;
			foreach (CimPropertyDeclaration property in cimObject.CimClass.CimClassProperties) {
				isKeyProperty = false;
				formatter = "{0}=\"{1}\""; // Default unless if{} block below changes it
				
				foreach (CimQualifier qualifier in property.Qualifiers) {
					if (qualifier.Name == "key") {
						isKeyProperty = true;
						break;
					}
				}
				
				if (isKeyProperty) {
					if (Regex.Match(property.CimType.ToString(), @"^Boolean$|^(U|S)Int\d+$").Success) {
						// Value needs quotes around it
						formatter = "{0}={1}";
					}
					else if (property.CimType == Microsoft.Management.Infrastructure.CimType.DateTime) {
						// Needs to be converted to a datetime object
						formatter = string.Format("{{0}}=\"{0}\"", ManagementDateTimeConverter.ToDmtfDateTime(((DateTime) cimObject.CimInstanceProperties[property.Name].Value)));
					}
					
					keyValuePairs.Add(string.Format(formatter, property.Name, cimObject.CimInstanceProperties[property.Name].Value.ToString()));
				}
			}
			
			return string.Format(
				@"\\{0}\{1}:{2}{3}",
				cimObject.CimSystemProperties.ServerName,
				cimObject.CimSystemProperties.Namespace.Replace(@"/", @"\"),
				cimObject.CimSystemProperties.ClassName,
				keyValuePairs.Count == 0 ? "=@" : string.Format(".{0}", string.Join(",", keyValuePairs))
			);
		}

		public static WmiInfo Create(object inputObject) {
			if (inputObject is ManagementBaseObject) {
				return new WmiInfo((ManagementBaseObject) inputObject);
			}
			else if (inputObject is CimInstance) {
				return new WmiInfo((CimInstance) inputObject);
			}
			else {
				throw new Exception("inputObject must be a ManagementBaseObject or CimInstance");
			}
		}


		public static Dictionary<string, object> GetPropertyDictionary(object wmiObject) {
			return GetPropertyDictionary(wmiObject, null);
		}
		public static Dictionary<string, object> GetPropertyDictionary(object wmiObject, List<string> propertyNames) {
			if (wmiObject is ManagementBaseObject) {
				return GetPropertyDictionary((ManagementBaseObject) wmiObject, propertyNames);
			}
			else if (wmiObject is CimInstance) {
				return GetPropertyDictionary((CimInstance) wmiObject, propertyNames);
			}
			else {
				throw new Exception("wmiObject must be a ManagementBaseObject or CimInstance");
			}
		}
		
		public static Dictionary<string, object> GetPropertyDictionary(ManagementBaseObject wmiObject) {
			return GetPropertyDictionary(wmiObject, null);
		}
		public static Dictionary<string, object> GetPropertyDictionary(ManagementBaseObject wmiObject, List<string> propertyNames) {
			Dictionary<string, object> returnDictionary = new Dictionary<string, object>();
			if (propertyNames == null) {
				propertyNames = new List<string>();
				foreach(PropertyData prop in wmiObject.Properties) {
					propertyNames.Add(prop.Name);
				}
			}
			
			foreach (string currentPropertyName in propertyNames) {
				try {
					returnDictionary.Add(currentPropertyName, wmiObject.Properties[currentPropertyName].Value);
				}
				catch {
					// If property doesn't exist, it won't be added to dictionary
				}
			}
			
			return returnDictionary;
		}

		public static Dictionary<string, object> GetPropertyDictionary(CimInstance cimObject) {
			return GetPropertyDictionary(cimObject, null);
		}
		public static Dictionary<string, object> GetPropertyDictionary(CimInstance cimObject, List<string> propertyNames) {
			Dictionary<string, object> returnDictionary = new Dictionary<string, object>();
			if (propertyNames == null) {
				propertyNames = new List<string>();
				foreach(CimProperty prop in cimObject.CimInstanceProperties) {
					propertyNames.Add(prop.Name);
				}
			}
			
			foreach (string currentPropertyName in propertyNames) {
				try {
					returnDictionary.Add(currentPropertyName, cimObject.CimInstanceProperties[currentPropertyName].Value);
				}
				catch {
					// If property doesn't exist, it won't be added to dictionary
				}
			}
			
			return returnDictionary;
		}

	}
}