namespace ROE.PowerShellAccessControl {
	public class GenericAceConverter : TypeConverter {
		/*
			This class can be used to convert lots of different types of ACEs into at least
			a GenericAce. If possible, it will convert it to at least a QualifiedAce.
			
			This is used by the PacAuthorizationRuleConverter class as a way to get ACEs
			into QualifiedAces (if they're not qualified, that class will throw an error)
		*/
		
		public static GenericAceConverter Converter {
			get {
				return _converter ??
					(_converter = new GenericAceConverter());
			}
		}
		private static GenericAceConverter _converter;

		readonly string ACE_NOT_AUDIT_RULE = "Destination type is audit rule, but ACE does not contain audit flags";
		readonly string ACE_NOT_ACCESS_RULE = "Desintation type is access rule, but ACE contains audit flags";

		public override bool CanConvertFrom(ITypeDescriptorContext context, Type sourceType) {
            if (sourceType.IsSubclassOf(typeof(AuthorizationRule))) { return true; }
			else if (sourceType.IsSubclassOf(typeof(QualifiedAce))) { return true; }
			else if (sourceType.IsSubclassOf(typeof(AdaptedAce))) { return true; }
            else if (sourceType == typeof(ManagementBaseObject)) { return true; }
            else if (sourceType == typeof(CimInstance)) { return true; }
			return base.CanConvertFrom(context, sourceType);

		}
		
		public override object ConvertFrom(ITypeDescriptorContext context, CultureInfo culture, object value) {
		
            AceFlags aceFlags = AceFlags.None;
            int accessMask = 0;
            AceQualifier aceQualifier;
            SecurityIdentifier securityIdentifier;

            ObjectAceFlags objectAceFlags = ObjectAceFlags.None;
            Guid objectType = Guid.Empty;
            Guid inheritedObjectType = Guid.Empty;

			if (value is QualifiedAce) {
				return value;
			}
			else if (value is AdaptedAce) {
				// AdaptedAces have Generic/Common/Object ACEs already
				return ((AdaptedAce) value).GetBaseAceObject();
			}
            else if (value is AuthorizationRule) {
                AuthorizationRule authRule = value as AuthorizationRule;
            
                // AccessMask is internal, so using reflection to get it (otherwise, we'd have to check for each rule type to get the right property to use)
                accessMask = (int) typeof(AuthorizationRule).InvokeMember("AccessMask", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.GetProperty, null, authRule, null);

                if ((authRule.InheritanceFlags & InheritanceFlags.ContainerInherit) != 0) {
                    aceFlags |= AceFlags.ContainerInherit;
                }

                if ((authRule.InheritanceFlags & InheritanceFlags.ObjectInherit) != 0) {
                    aceFlags |= AceFlags.ObjectInherit;
                }

                if ((authRule.PropagationFlags & PropagationFlags.InheritOnly) != 0) {
                    aceFlags |= AceFlags.InheritOnly;
                }

                if ((authRule.PropagationFlags & PropagationFlags.NoPropagateInherit) != 0) {
                    aceFlags |= AceFlags.NoPropagateInherit;
                }

                if (authRule.IsInherited) {
                    aceFlags |= AceFlags.Inherited;
                }

                securityIdentifier = (SecurityIdentifier) authRule.IdentityReference.Translate(typeof(SecurityIdentifier));
				
				if (value is AccessRule || value is PacAccessRule) {
					AccessControlType? accessAceType = null;
					
					if (value is AccessRule || value is PacAccessRule) {
						dynamic accessRule = value;
						accessAceType = accessRule.AccessControlType;
					}

					if (accessAceType == AccessControlType.Allow) {
						aceQualifier = AceQualifier.AccessAllowed;
					}
					else if (accessAceType == AccessControlType.Deny) {
						aceQualifier = AceQualifier.AccessDenied;
					}
					else {
						throw new Exception("Unknown AccessControlType");
					}
				}
				else if (value is AuditRule || value is PacAuditRule) {

					AuditFlags auditFlags = 0;

					if (value is AuditRule) {
						auditFlags = ((AuditRule) value).AuditFlags;
					}
					else if (value is PacAuditRule) {
						auditFlags = ((PacAuditRule) value).AuditFlags;
					}

					aceQualifier = AceQualifier.SystemAudit;
					if ((auditFlags & AuditFlags.Success) != 0) {
						aceFlags |= AceFlags.SuccessfulAccess;
					}

					if ((auditFlags & AuditFlags.Failure) != 0) {
						aceFlags |= AceFlags.FailedAccess;
					}
				}
				else {
					throw new Exception(string.Format("Unable to convert ACE to GenericAce: Unknown source type '{0}'", value.GetType().FullName));
				}
				
				if (value is ObjectAccessRule || value is PacObjectAccessRule || value is ObjectAuditRule || value is PacObjectAuditRule) {
					dynamic objectRule = value;
					
					if (objectRule.ObjectFlags != ObjectAceFlags.None) { 
						objectAceFlags = objectRule.ObjectFlags;
						objectType = objectRule.ObjectType;
						inheritedObjectType = objectRule.InheritedObjectType;
					}
				}

				if (objectAceFlags == ObjectAceFlags.None) {
					// Must not be an object ACE, so create a CommonAce
					return new CommonAce(aceFlags, aceQualifier, accessMask, securityIdentifier, false, null);
				}
				else {
					return new ObjectAce(aceFlags, aceQualifier, accessMask, securityIdentifier, objectAceFlags, objectType, inheritedObjectType, false, null);
				}
				
            }
			else if (value is ManagementBaseObject || value is CimInstance) {
				//Helper.TestWmiClassIsInstanceOf(value, new string[] { "Win32_ACE", "__ACE" } )) {
				string className = WmiInfo.Create(value).ClassName;
				if (className != "Win32_ACE" && className != "__ACE") {
					throw new Exception("WMI object must be of type 'Win32_ACE' or '__ACE'");
				}
				
				Dictionary<string, object> wmiProperties = WmiInfo.GetPropertyDictionary(value);

				aceQualifier = (AceQualifier) Enum.ToObject(typeof(AceQualifier), wmiProperties["AceType"]);
				aceFlags = (AceFlags) Enum.ToObject(typeof(AceFlags), wmiProperties["AceFlags"]);
				accessMask = Convert.ToInt32((uint) wmiProperties["AccessMask"]);
				
				securityIdentifier = new SecurityIdentifier((string) WmiInfo.GetPropertyDictionary(wmiProperties["Trustee"])["SIDString"]);
				
				string objectTypeString = (string) wmiProperties["GuidObjectType"];
				string inheritedObjectTypeString = (string) wmiProperties["GuidInheritedObjectType"];
				
				if (!String.IsNullOrEmpty(objectTypeString)) {
					objectAceFlags |= ObjectAceFlags.ObjectAceTypePresent;
					objectType = new Guid(objectTypeString);
				}
				else {
					objectType = Guid.Empty;
				}
				
				if (!String.IsNullOrEmpty(inheritedObjectTypeString)) {
					objectAceFlags |= ObjectAceFlags.InheritedObjectAceTypePresent;
					inheritedObjectType = new Guid(inheritedObjectTypeString);
				}
				else {
					inheritedObjectType = Guid.Empty;
				}
			}
            else {
                throw new Exception("Unknown rule type");
            }

            if (objectAceFlags == ObjectAceFlags.None) {
                // Must not be an object ACE, so assign CommonAce
                return new CommonAce(aceFlags, aceQualifier, accessMask, securityIdentifier, false, null);
            }
            else {
                return new ObjectAce(aceFlags, aceQualifier, accessMask, securityIdentifier, objectAceFlags, objectType, inheritedObjectType, false, null);
            }

		}
		
		public override bool CanConvertTo(ITypeDescriptorContext context, Type destinationType) {
            if (destinationType.IsSubclassOf(typeof(AuthorizationRule))) { 
				switch (destinationType.Name) {
					case "PacAuthorizationRule":
					case "FileSystemAccessRule":
					case "FileSystemAuditRule":
					case "RegistryAccessRule":
					case "RegistryAuditRule":
					case "ActiveDirectoryAccessRule":
					case "ActiveDirectoryAuditRule":
					case "PacAccessRule":
					case "PacObjectAccessRule":
					case "PacAuditRule":
					case "PacObjectAuditRule":
						return true; 
					default:
						return false;
				}
			
			}
			else if (destinationType == typeof(AuthorizationRule)) { return true; }
			else if (destinationType.IsSubclassOf(typeof(QualifiedAce))) { return true; }
			else if (destinationType.IsSubclassOf(typeof(AdaptedAce))) { return true; }
			else if (destinationType == typeof(ManagementBaseObject)) { return true; }
			else if (destinationType == typeof(CimInstance)) { return true; }

			return base.CanConvertTo(context, destinationType);
		}

		public override object ConvertTo(ITypeDescriptorContext context, CultureInfo culture, object value, Type destinationType) {
			GenericAce genericAce = (GenericAce) this.ConvertFrom(value);
			AceFlagsConverter aceFlagsConverter = new AceFlagsConverter();
			
			SecurityIdentifier securityIdentifier;
			AccessControlType accessControlType = AccessControlType.Allow;
			int accessMask;
			
			if (genericAce is QualifiedAce) {
				securityIdentifier = ((QualifiedAce) genericAce).SecurityIdentifier;
				accessMask = ((QualifiedAce) genericAce).AccessMask;
				
				// If ACE is audit ACE, this won't be used at all; otherwise AceType is already 'Allow'
				if (((QualifiedAce) genericAce).AceQualifier == AceQualifier.AccessDenied) {
					accessControlType = AccessControlType.Deny;
				}
			}
			else {
				throw new Exception("Unknown value type");
			}

			if (destinationType == typeof(AuthorizationRule) || destinationType == typeof(PacAuthorizationRule)) {
				AceQualifier aceQualifier = ((QualifiedAce) genericAce).AceQualifier;
				// Generic. Go ahead and create a PacAccessRule or PacAuditRule.
				if (aceQualifier == AceQualifier.SystemAudit) {
					destinationType = typeof(PacAuditRule);
				}
				else if (aceQualifier == AceQualifier.AccessAllowed || aceQualifier == AceQualifier.AccessDenied) {
					destinationType = typeof(PacAccessRule);
				}
				else {
					throw new Exception("Unknown QualifiedAce");
				}
			}

			if (destinationType == typeof(QualifiedAce)) {
				return (QualifiedAce) genericAce;
			}
			else if (destinationType == typeof(CommonAce)) {
				return (CommonAce) genericAce;
			}
			else if ((destinationType == typeof(ObjectAce)) && (genericAce is ObjectAce)) {
				// If genericAce isn't an ObjectAce, switch statement will build it
				return (ObjectAce) genericAce;
			}
			else if (destinationType == typeof(PacAccessRule)) {
				return new PacAccessRule((CommonAce) genericAce);
			}
			else if (destinationType == typeof(PacAuditRule)) {
				return new PacAuditRule((CommonAce) genericAce);
			}
			else if (destinationType == typeof(PacObjectAccessRule)) {
				if (genericAce is CommonAce) {
					return new PacObjectAccessRule((CommonAce) genericAce);
				}
				else if (genericAce is ObjectAce) {
					return new PacObjectAccessRule((ObjectAce) genericAce);
				}
				else {
					throw new Exception("PacObjectAccessRule requires source ACE to be CommonAce or ObjectAce");
				}
			}
			else if (destinationType == typeof(PacObjectAuditRule)) {
				if (genericAce is CommonAce) {
					return new PacObjectAuditRule((CommonAce) genericAce);
				}
				else if (genericAce is ObjectAce) {
					return new PacObjectAuditRule((ObjectAce) genericAce);
				}
				else {
					throw new Exception("PacObjectAuditRule requires source ACE to be CommonAce or ObjectAce");
				}
			}
			
			Guid objectAceType, inheritedObjectAceType;
			if (genericAce is ObjectAce) {
				objectAceType = ((ObjectAce) genericAce).ObjectAceType;
				inheritedObjectAceType = ((ObjectAce) genericAce).InheritedObjectAceType;
			}
			else {
				objectAceType = Guid.Empty;
				inheritedObjectAceType = Guid.Empty;
			}
			
			switch (destinationType.Name) {
				case "ObjectAce":
					// If it makes it this far, the ObjectAce will have no GUIDs (if it did, the
					// function would have already returned the object ACE above)
					return new ObjectAce(
						genericAce.AceFlags,
						((QualifiedAce) genericAce).AceQualifier,
						accessMask,
						securityIdentifier,
						ObjectAceFlags.None,
						objectAceType,
						inheritedObjectAceType,
						false,
						null
					);
									
				case "FileSystemAccessRule":
					if (genericAce.AuditFlags != AuditFlags.None) { throw new Exception(ACE_NOT_ACCESS_RULE); }
					return new FileSystemAccessRule(
						securityIdentifier, 
						(FileSystemRights) Enum.ToObject(typeof(FileSystemRights), accessMask), 
						genericAce.InheritanceFlags, 
						genericAce.PropagationFlags, 
						accessControlType
					);
				case "FileSystemAuditRule":
					if (genericAce.AuditFlags == AuditFlags.None) { throw new Exception(ACE_NOT_AUDIT_RULE); }
					return new FileSystemAuditRule(
						securityIdentifier, 
						(FileSystemRights) Enum.ToObject(typeof(FileSystemRights), accessMask),
						genericAce.InheritanceFlags,
						genericAce.PropagationFlags,
						genericAce.AuditFlags
					);
				case "RegistryAccessRule":
					if (genericAce.AuditFlags != AuditFlags.None) { throw new Exception(ACE_NOT_ACCESS_RULE); }
					return new RegistryAccessRule(
						securityIdentifier, 
						(RegistryRights) Enum.ToObject(typeof(RegistryRights), accessMask), 
						genericAce.InheritanceFlags, 
						genericAce.PropagationFlags, 
						accessControlType
					);
				case "RegistryAuditRule":
					if (genericAce.AuditFlags == AuditFlags.None) { throw new Exception(ACE_NOT_AUDIT_RULE); }
					return new RegistryAuditRule(
						securityIdentifier, 
						(RegistryRights) Enum.ToObject(typeof(RegistryRights), accessMask),
						genericAce.InheritanceFlags,
						genericAce.PropagationFlags,
						genericAce.AuditFlags
					);
				case "ActiveDirectoryAccessRule":
					if (genericAce.AuditFlags != AuditFlags.None) { throw new Exception(ACE_NOT_ACCESS_RULE); }
					return new ActiveDirectoryAccessRule(
						securityIdentifier, 
						(System.DirectoryServices.ActiveDirectoryRights) Enum.ToObject(typeof(System.DirectoryServices.ActiveDirectoryRights), accessMask),
						accessControlType,
						objectAceType,
						(ActiveDirectorySecurityInheritance) aceFlagsConverter.ConvertTo(genericAce.AceFlags, typeof(ActiveDirectorySecurityInheritance)),
						inheritedObjectAceType
					);
				case "ActiveDirectoryAuditRule":
					if (genericAce.AuditFlags == AuditFlags.None) { throw new Exception(ACE_NOT_AUDIT_RULE); }
					return new ActiveDirectoryAuditRule(
						securityIdentifier, 
						(System.DirectoryServices.ActiveDirectoryRights) Enum.ToObject(typeof(System.DirectoryServices.ActiveDirectoryRights), accessMask),
						genericAce.AuditFlags,
						objectAceType,
						(ActiveDirectorySecurityInheritance) aceFlagsConverter.ConvertTo(genericAce.AceFlags, typeof(ActiveDirectorySecurityInheritance)),
						inheritedObjectAceType
					);				
				
				case "ManagementBaseObject":
				case "ManagementObject":
					// Not sure why anyone would want to do this, but this code should create a Win32_ACE object
					ManagementClass aceClass = new ManagementClass("Win32_ACE");
					ManagementClass trusteeClass = new ManagementClass("Win32_Trustee");
					
					ManagementBaseObject wmiAce = aceClass.CreateInstance();
					ManagementBaseObject wmiTrustee = trusteeClass.CreateInstance();
					
					wmiTrustee.Properties["SIDString"].Value = securityIdentifier.ToString();
					wmiAce.Properties["Trustee"].Value = wmiTrustee;
					wmiAce.Properties["AccessMask"].Value = (uint) accessMask;
					wmiAce.Properties["AceFlags"].Value = (uint) genericAce.AceFlags;
					wmiAce.Properties["AceType"].Value = (uint) ((QualifiedAce) genericAce).AceQualifier;
					
					return wmiAce;
				
				case "CimInstance":
					// Same as ManagementBaseObject above
					CimSession cimSession = CimSession.Create("localhost");

					CimInstance cimAce = new CimInstance(cimSession.GetClass("root/cimv2", "Win32_ACE"));
					CimInstance cimTrustee = new CimInstance(cimSession.GetClass("root/cimv2", "Win32_Trustee"));

					cimTrustee.CimInstanceProperties["SIDString"].Value = securityIdentifier.ToString();
					cimAce.CimInstanceProperties["Trustee"].Value = cimTrustee;
					cimAce.CimInstanceProperties["AccessMask"].Value = (uint) accessMask;
					cimAce.CimInstanceProperties["AceFlags"].Value = (uint) genericAce.AceFlags;
					cimAce.CimInstanceProperties["AceType"].Value = (uint) ((QualifiedAce) genericAce).AceQualifier;
					
					return cimAce;
			}
			
		    return base.ConvertTo(context, culture, value, destinationType);
		}
	}


	public class PacAuthorizationRuleConverter : TypeConverter {
		readonly string ACE_NOT_AUDIT_RULE = "Destination type is audit rule, but ACE does not contain audit flags";
		readonly string ACE_NOT_ACCESS_RULE = "Desintation type is access rule, but ACE contains audit flags";

		public override bool CanConvertFrom(ITypeDescriptorContext context, Type sourceType) {
            if (sourceType.IsSubclassOf(typeof(AuthorizationRule))) { return true; }
			else if (sourceType.IsSubclassOf(typeof(QualifiedAce))) { return true; }
			else if (sourceType.IsSubclassOf(typeof(AdaptedAce))) { return true; }
            else if (sourceType == typeof(ManagementBaseObject)) { return true; }
            else if (sourceType == typeof(CimInstance)) { return true; }
			return base.CanConvertFrom(context, sourceType);

		}
		
		public override object ConvertFrom(ITypeDescriptorContext context, CultureInfo culture, object value) {
		
            AceFlags aceFlags = AceFlags.None;
            int accessMask = 0;
            AceQualifier aceQualifier;
            SecurityIdentifier securityIdentifier;

            ObjectAceFlags objectAceFlags = ObjectAceFlags.None;
            Guid objectType = Guid.Empty;
            Guid inheritedObjectType = Guid.Empty;

			QualifiedAce qualifiedAce = null;
			if (value is AdaptedCommonAce) {
				// Get the QualifiedAce from the AdaptedAce
				qualifiedAce = (QualifiedAce) ((AdaptedAce) value).GetBaseAceObject();
			}
			else if (value is QualifiedAce) {
				qualifiedAce = (QualifiedAce) value;
			}
			else {
				if (value is AuthorizationRule) {
					// Get information needed to build a qualified ACE
					AuthorizationRule authRule = value as AuthorizationRule;
				
					// AccessMask is internal, so using reflection to get it (otherwise, we'd have to check for each rule type to get the right property to use)
					accessMask = (int) typeof(AuthorizationRule).InvokeMember("AccessMask", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.GetProperty, null, authRule, null);

					if ((authRule.InheritanceFlags & InheritanceFlags.ContainerInherit) != 0) {
						aceFlags |= AceFlags.ContainerInherit;
					}

					if ((authRule.InheritanceFlags & InheritanceFlags.ObjectInherit) != 0) {
						aceFlags |= AceFlags.ObjectInherit;
					}

					if ((authRule.PropagationFlags & PropagationFlags.InheritOnly) != 0) {
						aceFlags |= AceFlags.InheritOnly;
					}

					if ((authRule.PropagationFlags & PropagationFlags.NoPropagateInherit) != 0) {
						aceFlags |= AceFlags.NoPropagateInherit;
					}

					if (authRule.IsInherited) {
						aceFlags |= AceFlags.Inherited;
					}

					securityIdentifier = (SecurityIdentifier) authRule.IdentityReference.Translate(typeof(SecurityIdentifier));

					if (value is AccessRule) {

						if (((AccessRule) value).AccessControlType == AccessControlType.Allow) {
							aceQualifier = AceQualifier.AccessAllowed;
						}
						else {
							aceQualifier = AceQualifier.AccessDenied;
						}

					}
					else if (value is AuditRule) { 
						AuditRule auditRule = value as AuditRule;
						if ((auditRule.AuditFlags & AuditFlags.Success) != 0) {
							aceFlags |= AceFlags.SuccessfulAccess;
						}

						if ((auditRule.AuditFlags & AuditFlags.Failure) != 0) {
							aceFlags |= AceFlags.FailedAccess;
						}

						aceQualifier = AceQualifier.SystemAudit;
					}
					else {
						throw new Exception( "Unknown AuthorizationRule type" );
					}
				}
				else if (value is ManagementBaseObject || value is CimInstance) {
					//Helper.TestWmiClassIsInstanceOf(value, new string[] { "Win32_ACE", "__ACE" } )) {
					string className = WmiInfo.Create(value).ClassName;
					if (className != "Win32_ACE" && className != "__ACE") {
						throw new Exception("WMI object must be of type 'Win32_ACE' or '__ACE'");
					}
					
					Dictionary<string, object> wmiProperties = WmiInfo.GetPropertyDictionary(value);

					aceQualifier = (AceQualifier) Enum.ToObject(typeof(AceQualifier), wmiProperties["AceType"]);
					aceFlags = (AceFlags) Enum.ToObject(typeof(AceFlags), wmiProperties["AceFlags"]);
					accessMask = Convert.ToInt32((uint) wmiProperties["AccessMask"]);
					
					securityIdentifier = new SecurityIdentifier((string) WmiInfo.GetPropertyDictionary(wmiProperties["Trustee"])["SIDString"]);
					
					string objectTypeString = (string) wmiProperties["GuidObjectType"];
					string inheritedObjectTypeString = (string) wmiProperties["GuidInheritedObjectType"];
					
					if (!String.IsNullOrEmpty(objectTypeString)) {
						objectAceFlags |= ObjectAceFlags.ObjectAceTypePresent;
						objectType = new Guid(objectTypeString);
					}
					else {
						objectType = Guid.Empty;
					}
					
					if (!String.IsNullOrEmpty(inheritedObjectTypeString)) {
						objectAceFlags |= ObjectAceFlags.InheritedObjectAceTypePresent;
						inheritedObjectType = new Guid(inheritedObjectTypeString);
					}
					else {
						inheritedObjectType = Guid.Empty;
					}
				}
				else {
					throw new Exception("Unknown rule type");
				}

				// If ACE was an ObjectAce, get that information
				if ((value is ObjectAccessRule) && (((ObjectAccessRule) value).ObjectFlags != ObjectAceFlags.None)) { 
					objectAceFlags = ((ObjectAccessRule) value).ObjectFlags;
					objectType = ((ObjectAccessRule) value).ObjectType;
					inheritedObjectType = ((ObjectAccessRule) value).InheritedObjectType;
				}
				else if ((value is ObjectAuditRule) && (((ObjectAuditRule) value).ObjectFlags != ObjectAceFlags.None)) {
					objectAceFlags = ((ObjectAuditRule) value).ObjectFlags;
					objectType = ((ObjectAuditRule) value).ObjectType;
					inheritedObjectType = ((ObjectAuditRule) value).InheritedObjectType;
				}

				if (objectAceFlags == ObjectAceFlags.None) {
					// Must not be an object ACE, so assign CommonAce
					qualifiedAce = new CommonAce(aceFlags, aceQualifier, accessMask, securityIdentifier, false, null);
				}
				else {
					qualifiedAce = new ObjectAce(aceFlags, aceQualifier, accessMask, securityIdentifier, objectAceFlags, objectType, inheritedObjectType, false, null);
				}
			}
			
			switch (qualifiedAce.AceQualifier) {
				case AceQualifier.AccessAllowed:
				case AceQualifier.AccessDenied:
					return new PacAccessRule( qualifiedAce );
					
				case AceQualifier.SystemAudit:
					return new PacAuditRule( qualifiedAce );

				default:
					throw new Exception("Unknown QualifiedAce type");
			}

		}
		


		public override bool CanConvertTo(ITypeDescriptorContext context, Type destinationType) {
            if (destinationType.IsSubclassOf(typeof(AuthorizationRule))) { 
				switch (destinationType.Name) {
					case "FileSystemAccessRule":
					case "FileSystemAuditRule":
					case "RegistryAccessRule":
					case "RegistryAuditRule":
					case "ActiveDirectoryAccessRule":
					case "ActiveDirectoryAuditRule":
					case "PacAccessRule":
					case "PacObjectAccessRule":
					case "PacAuditRule":
					case "PacObjectAuditRule":
						return true; 
					default:
						return false;
				}
			
			} 
			else if (destinationType.IsSubclassOf(typeof(QualifiedAce))) { return true; }
			else if (destinationType.IsSubclassOf(typeof(AdaptedCommonAce))) { return true; }
			else if (destinationType == typeof(ManagementBaseObject)) { return true; }
			else if (destinationType == typeof(CimInstance)) { return true; }

			return base.CanConvertTo(context, destinationType);
		}

		public override object ConvertTo(ITypeDescriptorContext context, CultureInfo culture, object value, Type destinationType) {
			return base.ConvertTo(context, culture, value, destinationType);
		}
		
/*
		public override object ConvertTo(ITypeDescriptorContext context, CultureInfo culture, object value, Type destinationType) {
			PacAuthorizationRule = (PacAuthorizationRule) this.ConvertFrom(value);

			if (destinationType == typeof(QualifiedAce)) {
				return (QualifiedAce) genericAce;
			}
			else if (destinationType == typeof(CommonAce)) {
				return (CommonAce) genericAce;
			}
			else if ((destinationType == typeof(ObjectAce)) && (genericAce is ObjectAce)) {
				// If genericAce isn't an ObjectAce, switch statement will build it
				return (ObjectAce) genericAce;
			}
			else if (destinationType == typeof(PacAccessRule)) {
throw new Exception("PacAuthorizationRule conversion not implemented");
//				return new PacAccessRule((CommonAce) genericAce);
			}
			else if (destinationType == typeof(PacAuditRule)) {
//				return new PacAuditRule((CommonAce) genericAce);
throw new Exception("PacAuthorizationRule conversion not implemented");
			}
			else if (destinationType == typeof(PacObjectAccessRule)) {
				if (genericAce is CommonAce) {
//					return new PacObjectAccessRule((CommonAce) genericAce);
throw new Exception("PacAuthorizationRule conversion not implemented");
				}
				else if (genericAce is ObjectAce) {
//					return new PacObjectAccessRule((ObjectAce) genericAce);
throw new Exception("PacAuthorizationRule conversion not implemented");
				}
				else {
throw new Exception("PacObjectAccessRule requires source ACE to be CommonAce or ObjectAce");
				}
			}
			else if (destinationType == typeof(PacObjectAuditRule)) {
				if (genericAce is CommonAce) {
//					return new PacObjectAuditRule((CommonAce) genericAce);
throw new Exception("PacAuthorizationRule conversion not implemented");
				}
				else if (genericAce is ObjectAce) {
//					return new PacObjectAuditRule((ObjectAce) genericAce);
throw new Exception("PacAuthorizationRule conversion not implemented");
				}
				else {
throw new Exception("PacObjectAuditRule requires source ACE to be CommonAce or ObjectAce");
				}
			}
			
			Guid objectAceType, inheritedObjectAceType;
			if (genericAce is ObjectAce) {
				objectAceType = ((ObjectAce) genericAce).ObjectAceType;
				inheritedObjectAceType = ((ObjectAce) genericAce).InheritedObjectAceType;
			}
			else {
				objectAceType = Guid.Empty;
				inheritedObjectAceType = Guid.Empty;
			}
			
			switch (destinationType.Name) {
				case "ObjectAce":
					// If it makes it this far, the ObjectAce will have no GUIDs (if it did, the
					// function would have already returned the object ACE above)
					return new ObjectAce(
						genericAce.AceFlags,
						((QualifiedAce) genericAce).AceQualifier,
						accessMask,
						securityIdentifier,
						ObjectAceFlags.None,
						objectAceType,
						inheritedObjectAceType,
						false,
						null
					);
									
				case "FileSystemAccessRule":
					if (genericAce.AuditFlags != AuditFlags.None) { throw new Exception(ACE_NOT_ACCESS_RULE); }
					return new FileSystemAccessRule(
						securityIdentifier, 
						(FileSystemRights) Enum.ToObject(typeof(FileSystemRights), accessMask), 
						genericAce.InheritanceFlags, 
						genericAce.PropagationFlags, 
						accessControlType
					);
				case "FileSystemAuditRule":
					if (genericAce.AuditFlags == AuditFlags.None) { throw new Exception(ACE_NOT_AUDIT_RULE); }
					return new FileSystemAuditRule(
						securityIdentifier, 
						(FileSystemRights) Enum.ToObject(typeof(FileSystemRights), accessMask),
						genericAce.InheritanceFlags,
						genericAce.PropagationFlags,
						genericAce.AuditFlags
					);
				case "RegistryAccessRule":
					if (genericAce.AuditFlags != AuditFlags.None) { throw new Exception(ACE_NOT_ACCESS_RULE); }
					return new RegistryAccessRule(
						securityIdentifier, 
						(RegistryRights) Enum.ToObject(typeof(RegistryRights), accessMask), 
						genericAce.InheritanceFlags, 
						genericAce.PropagationFlags, 
						accessControlType
					);
				case "RegistryAuditRule":
					if (genericAce.AuditFlags == AuditFlags.None) { throw new Exception(ACE_NOT_AUDIT_RULE); }
					return new RegistryAuditRule(
						securityIdentifier, 
						(RegistryRights) Enum.ToObject(typeof(RegistryRights), accessMask),
						genericAce.InheritanceFlags,
						genericAce.PropagationFlags,
						genericAce.AuditFlags
					);
				case "ActiveDirectoryAccessRule":
					if (genericAce.AuditFlags != AuditFlags.None) { throw new Exception(ACE_NOT_ACCESS_RULE); }
					return new ActiveDirectoryAccessRule(
						securityIdentifier, 
						(System.DirectoryServices.ActiveDirectoryRights) Enum.ToObject(typeof(System.DirectoryServices.ActiveDirectoryRights), accessMask),
						accessControlType,
						objectAceType,
						(ActiveDirectorySecurityInheritance) appliesToConverter.ConvertTo(genericAce.AceFlags, typeof(ActiveDirectorySecurityInheritance)),
						inheritedObjectAceType
					);
				case "ActiveDirectoryAuditRule":
					if (genericAce.AuditFlags == AuditFlags.None) { throw new Exception(ACE_NOT_AUDIT_RULE); }
					return new ActiveDirectoryAuditRule(
						securityIdentifier, 
						(System.DirectoryServices.ActiveDirectoryRights) Enum.ToObject(typeof(System.DirectoryServices.ActiveDirectoryRights), accessMask),
						genericAce.AuditFlags,
						objectAceType,
						(ActiveDirectorySecurityInheritance) appliesToConverter.ConvertTo(genericAce.AceFlags, typeof(ActiveDirectorySecurityInheritance)),
						inheritedObjectAceType
					);				
				
				case "ManagementBaseObject":
					// Not sure why anyone would want to do this, but this code should create a Win32_ACE object
					ManagementClass aceClass = new ManagementClass("Win32_ACE");
					ManagementClass trusteeClass = new ManagementClass("Win32_Trustee");
					
					ManagementBaseObject wmiAce = aceClass.CreateInstance();
					ManagementBaseObject wmiTrustee = trusteeClass.CreateInstance();
					
					wmiTrustee.Properties["SIDString"].Value = securityIdentifier.ToString();
					wmiAce.Properties["Trustee"].Value = wmiTrustee;
					wmiAce.Properties["AccessMask"].Value = (uint) accessMask;
					wmiAce.Properties["AceFlags"].Value = (uint) genericAce.AceFlags;
					wmiAce.Properties["AceType"].Value = (uint) ((QualifiedAce) genericAce).AceQualifier;
					
					return wmiAce;
				
				case "CimInstance":
					// Same as ManagementBaseObject above
					CimSession cimSession = CimSession.Create("localhost");

					CimInstance cimAce = new CimInstance(cimSession.GetClass("root/cimv2", "Win32_ACE"));
					CimInstance cimTrustee = new CimInstance(cimSession.GetClass("root/cimv2", "Win32_Trustee"));

					cimTrustee.CimInstanceProperties["SIDString"].Value = securityIdentifier.ToString();
					cimAce.CimInstanceProperties["Trustee"].Value = cimTrustee;
					cimAce.CimInstanceProperties["AccessMask"].Value = (uint) accessMask;
					cimAce.CimInstanceProperties["AceFlags"].Value = (uint) genericAce.AceFlags;
					cimAce.CimInstanceProperties["AceType"].Value = (uint) ((QualifiedAce) genericAce).AceQualifier;
					
					return cimAce;
			}
			
		    return base.ConvertTo(context, culture, value, destinationType);
		}
*/
	}


	public class AceFlagsConverter : TypeConverter {
		/*
			Converts between the following (ConvertFrom returns AceFlags):
				- AceFlags - This flags enum contains more than inheritance and propagation info, but those are the only values used during conversion
				- ActiveDirectorySecurityInheritance
		*/

		public override bool CanConvertFrom(ITypeDescriptorContext context, Type sourceType) {
            if (sourceType == typeof(ActiveDirectorySecurityInheritance)) { return true; }
			else if (sourceType == typeof(AppliesTo)) { return true; }
			else if (sourceType == typeof(FriendlyAppliesTo)) { return true; }
			else if (sourceType == typeof(AceFlags)) { return true; }

            return base.CanConvertFrom(context, sourceType);

		}
		
		public override object ConvertFrom(ITypeDescriptorContext context, CultureInfo culture, object value) {
			if (value is FriendlyAppliesTo) {
				value = ((FriendlyAppliesTo) value).AppliesToEnum;
			}
			
			if (value is AceFlags) { return ((AceFlags) value) & AceFlags.InheritanceFlags; }
			else if (value is AppliesTo) {
				AppliesTo appliesTo = (AppliesTo) value;

				AceFlags aceFlags = AceFlags.None;
				
				if ((appliesTo & AppliesTo.Object) == 0) {
					aceFlags |= AceFlags.InheritOnly;
				}
				
				if ((appliesTo & AppliesTo.ChildContainers) != 0) {
					aceFlags |= AceFlags.ContainerInherit;
				}
				
				if ((appliesTo & AppliesTo.ChildObjects) != 0) {
					aceFlags |= AceFlags.ObjectInherit;
				}
				
				if ((appliesTo & AppliesTo.DirectChildrenOnly) != 0) {
					aceFlags |= AceFlags.NoPropagateInherit;
				}
				
				return aceFlags;
			}
			else if (value is ActiveDirectorySecurityInheritance) {
				switch (value.ToString()) {
					case "All":
						return AceFlags.ContainerInherit;
						
					case "Children":
						return AceFlags.ContainerInherit | AceFlags.InheritOnly | AceFlags.NoPropagateInherit;
					
					case "Descendents":
						return AceFlags.ContainerInherit | AceFlags.InheritOnly;
					
					case "None":
						return AceFlags.None;
					
					case "SelfAndChildren":
						return AceFlags.ContainerInherit | AceFlags.NoPropagateInherit;
					
					default:
						throw new Exception("Unknown ActiveDirectorySecurityInheritance value");
				}
			}
			
			return base.ConvertFrom(context, culture, value);
		}

		public override bool CanConvertTo(ITypeDescriptorContext context, Type destinationType) {

            if (destinationType == typeof(ActiveDirectorySecurityInheritance)) { return true; }
			else if (destinationType == typeof(AppliesTo)) { return true; }
			else if (destinationType == typeof(AceFlags)) { return true; }

			return base.CanConvertTo(context, destinationType);
		}

		public override object ConvertTo(ITypeDescriptorContext context, CultureInfo culture, object value, Type destinationType) {

			AceFlags aceFlags = (AceFlags) this.ConvertFrom(value);
			
			if (destinationType == typeof(AceFlags)) {
				return aceFlags;
			}
			else if (destinationType == typeof(AppliesTo)) {
				AppliesTo appliesTo = 0;
				
				if ((aceFlags & AceFlags.ContainerInherit) != 0) {
					appliesTo |= AppliesTo.ChildContainers;
				}

				if ((aceFlags & AceFlags.ObjectInherit) != 0) {
					appliesTo |= AppliesTo.ChildObjects;
				}

				if ((aceFlags & AceFlags.InheritOnly) == 0) {
					appliesTo |= AppliesTo.Object;
				}

				if ((aceFlags & AceFlags.NoPropagateInherit) != 0) {
					appliesTo |= AppliesTo.DirectChildrenOnly;
				}
				
				return appliesTo;
			}
			else if (destinationType == typeof(ActiveDirectorySecurityInheritance)) {
				// Ignore ObjectInheritFlag:
				aceFlags &= AceFlags.ContainerInherit | AceFlags.InheritOnly | AceFlags.NoPropagateInherit;
				
				if (aceFlags == AceFlags.ContainerInherit) {
					return ActiveDirectorySecurityInheritance.All;
				}
				else if (aceFlags == (AceFlags.ContainerInherit | AceFlags.InheritOnly | AceFlags.NoPropagateInherit)) {
					return ActiveDirectorySecurityInheritance.Children;
				}
				else if (aceFlags == (AceFlags.ContainerInherit | AceFlags.InheritOnly)) {
					return ActiveDirectorySecurityInheritance.Descendents;
				}
				else if (aceFlags == AceFlags.None) {
					return ActiveDirectorySecurityInheritance.None;
				}
				else if (aceFlags == (AceFlags.ContainerInherit | AceFlags.NoPropagateInherit)) {
					return ActiveDirectorySecurityInheritance.SelfAndChildren;
				}
				else {
					// Throw error? For now fall through to the default call to base below
				}
			}
			
			return base.ConvertTo(context, culture, value, destinationType);
		}
	}

	public class AceTypeConverter : TypeConverter {

		public override bool CanConvertFrom(ITypeDescriptorContext context, Type sourceType) {
            if (sourceType == typeof(AceQualifier)) { return true; }
			else if (sourceType == typeof(Enums.AceType)) { return true; }
			else if (sourceType == typeof(string)) { return true; }

            return base.CanConvertFrom(context, sourceType);

		}
		
		public override object ConvertFrom(ITypeDescriptorContext context, CultureInfo culture, object value) {

			if (value is Enums.AceType) {
				value = ((Enums.AceType) value).ToString();
			}
			
			if (value is AceQualifier) { 
				switch ((AceQualifier) value) {
					case AceQualifier.AccessAllowed:
						return Enums.AceType.Allow;
					case AceQualifier.AccessDenied:
						return Enums.AceType.Deny;
					case AceQualifier.SystemAudit:
						return Enums.AceType.Audit;
					default:
						throw new Exception(String.Format("Unknown AceQualifier: {0}", value));
				}
			}
			else if (value is string) {
				string aceTypeString = (value as string).ToLower();
				
				if (aceTypeString.StartsWith("allow")) {
					return Enums.AceType.Allow;
				}
				else if (aceTypeString.StartsWith("deny")) {
					return Enums.AceType.Deny;
				}
				else if (aceTypeString.StartsWith("audit")) {
					return Enums.AceType.Audit;
				}
				else {
					throw new Exception(String.Format("Unknown AceType: {0}", aceTypeString));
				}
			}
			
			return base.ConvertFrom(context, culture, value);
		}

		public override bool CanConvertTo(ITypeDescriptorContext context, Type destinationType) {
			return base.CanConvertTo(context, destinationType);
		}

		public override object ConvertTo(ITypeDescriptorContext context, CultureInfo culture, object value, Type destinationType) {
			return base.ConvertTo(context, culture, value, destinationType);
		}
	}


	public class AppliesToConverter : TypeConverter {

		public override bool CanConvertFrom(ITypeDescriptorContext context, Type sourceType) {
            if (sourceType == typeof(FriendlyAppliesTo)) { return true; }

            return base.CanConvertFrom(context, sourceType);

		}
		
		public override object ConvertFrom(ITypeDescriptorContext context, CultureInfo culture, object value) {
			if (value is FriendlyAppliesTo) { 
				return ((FriendlyAppliesTo) value).AppliesToEnum;
			}
			
			return base.ConvertFrom(context, culture, value);
		}

		public override bool CanConvertTo(ITypeDescriptorContext context, Type destinationType) {
			if (destinationType == typeof(ActiveDirectorySecurityInheritance)) { return true; }

			return base.CanConvertTo(context, destinationType);
			
		}

		public override object ConvertTo(ITypeDescriptorContext context, CultureInfo culture, object value, Type destinationType) {
			if (!this.CanConvertTo(context, destinationType)) {
				return base.ConvertTo(context, culture, value, destinationType);
			}

			Enums.AppliesTo appliesTo;
			if (!(value is Enums.AppliesTo)) {
				value = ConvertFrom(context, culture, value);
			}
			
			appliesTo = (Enums.AppliesTo) value;
			
			if (destinationType == typeof(ActiveDirectorySecurityInheritance)) {
				switch ((int) appliesTo & 11) {  // 11 Ignores ChildObjects completely
					case 1: // Object
						return ActiveDirectorySecurityInheritance.None;
					
					case 2: // ChildContainers
						return ActiveDirectorySecurityInheritance.Descendents;
						
					case 3: // Object, ChildContainers
						return ActiveDirectorySecurityInheritance.All;
						
					case 10: // ChildContainers (DirectChildrenOnly)
						return ActiveDirectorySecurityInheritance.Children;

					case 11: // Object and ChildContainers (DirectChildrenOnly)
						return ActiveDirectorySecurityInheritance.SelfAndChildren;

					default:
						// Throw error?
						break;
				}
			}
			
			return base.ConvertTo(context, culture, value, destinationType);
		}
	}

	public class AccessMaskDisplayConverter : TypeConverter {

		public override bool CanConvertFrom(ITypeDescriptorContext context, Type sourceType) {
            if (sourceType == typeof(int)) { return true; }

            return base.CanConvertFrom(context, sourceType);

		}
		
		public override object ConvertFrom(ITypeDescriptorContext context, CultureInfo culture, object value) {
			if (value is int) { 
				return new AccessMaskDisplay(((int) value), typeof(int));
			}
			
			return base.ConvertFrom(context, culture, value);
		}

		public override bool CanConvertTo(ITypeDescriptorContext context, Type destinationType) {
            if (destinationType == typeof(int)) { return true; }
			return base.CanConvertTo(context, destinationType);
		}

		public override object ConvertTo(ITypeDescriptorContext context, CultureInfo culture, object value, Type destinationType) {
			if (value is AccessMaskDisplay && destinationType == typeof(int)) {
				return ((AccessMaskDisplay) value).AccessMask;
			}
			return base.ConvertTo(context, culture, value, destinationType);
		}
	}
}



