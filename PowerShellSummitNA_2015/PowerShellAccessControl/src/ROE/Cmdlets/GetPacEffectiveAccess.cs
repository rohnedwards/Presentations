using System.Diagnostics;
using System.Linq;

namespace ROE.PowerShellAccessControl {

	[Cmdlet(VerbsCommon.Get, "PacEffectiveAccess")]
	[OutputType(new Type[] { typeof(PacAuthorizationRule), typeof(PacObjectAccessRule), typeof(PacObjectAuditRule) })]
	public class GetPacEffectiveAccessCommand : PacModuleCmdlet {
		#region Parameters
		[Parameter()]
		[Alias("UserPrincipal", "User", "Group", "IdentityReference")]
		public PacPrincipal Principal { 
			get {
				return _principal ??
						new PacPrincipal(System.Security.Principal.WindowsIdentity.GetCurrent().User);
			}
			
			set {
				_principal = value;
			}
		}
		PacPrincipal _principal;

		[Parameter()]
		public PacPrincipal DevicePrincipal { get; set; }
		
		[Parameter()]
		[Alias("ListAllRights")]
		public SwitchParameter Detailed { get; set; }

		[Parameter()]
		public string[] GroupClaims { get; set; }

		[Parameter()]
		public string[] DeviceClaims { get; set; }

		[Parameter()]
		public ObjectAceTypeFilter[] ObjectAceType { 
			get { 
				return _objectAceType ??
					(_objectAceType = new ObjectAceTypeFilter[] { }); 
			}
			set { _objectAceType = value; }
		}
		ObjectAceTypeFilter[] _objectAceType = null;
		#endregion

		Dictionary<string, SafeAuthzRMHandle> authzRMHandles;
		Dictionary<Tuple<string, SecurityIdentifier, SecurityIdentifier>, SafeAuthzClientContextHandle> authzClientContextHandles;

		protected override void BeginProcessing() {

			base.BeginProcessing();

			authzRMHandles = new Dictionary<string, SafeAuthzRMHandle>();
			authzClientContextHandles = new Dictionary<Tuple<string, SecurityIdentifier, SecurityIdentifier>, SafeAuthzClientContextHandle>();

			for (int i = 1; i < this.ObjectAceType.Length; i++) {
				this.ObjectAceType[0].AddAdditionalFilter(this.ObjectAceType[i]);
			}
		}

		protected override void ProcessRecord() {

			string currentAuthzRMKey;
			SafeAuthzRMHandle currentAuthzRMHandle;
			foreach (AdaptedSecurityDescriptor currentSd in this.GetAdaptedSecurityDescriptor(this.InputObject)) {

				#region Get resource manager handle
				currentAuthzRMKey = currentSd.ComputerName;
				if (currentAuthzRMKey == null) { currentAuthzRMKey = string.Empty; }
				if (!authzRMHandles.ContainsKey(currentAuthzRMKey)) {
					
					try {
						currentAuthzRMHandle = GetResourceManagerHandle(currentAuthzRMKey);
					}
					catch (Exception e) {
						if (e is System.EntryPointNotFoundException) {
							// This can happen on pre Win 8/2012 systems. No need to warn the user
							WriteWarning(string.Format("Remote resource manager not supported; using local resource manager"));
						}
						else {
							WriteWarning(string.Format("Error initializing remote resource manager on '{0}': {1} ({2})", currentAuthzRMKey, e.Message, e.GetType().FullName));
						}
						
						try {
							if (!authzRMHandles.ContainsKey(string.Empty)) {
								authzRMHandles.Add(string.Empty, GetResourceManagerHandle(string.Empty));
							}
							
							currentAuthzRMHandle = authzRMHandles[string.Empty];
						
						}
						catch (Exception e2) {
							WriteError(new ErrorRecord(
								e2,
								"",
								ErrorCategory.InvalidData,
								null
							));
							continue;
						}
					}

					authzRMHandles.Add(currentAuthzRMKey, currentAuthzRMHandle);
				}
				
				currentAuthzRMHandle = authzRMHandles[currentAuthzRMKey];
				#endregion


				#region Get client context
				SecurityIdentifier userSid = null, deviceSid = null;
				userSid = this.Principal.SecurityIdentifier;
				
				Tuple<string, SecurityIdentifier, SecurityIdentifier> currentClientContextKey = Tuple.Create(currentAuthzRMKey, userSid, deviceSid);
				SafeAuthzClientContextHandle currentClientContextHandle;
				if (!authzClientContextHandles.ContainsKey(currentClientContextKey)) {
					SafeAuthzClientContextHandle currentUserContextHandle, currentDeviceContextHandle;
					currentDeviceContextHandle = SafeAuthzClientContextHandle.InvalidHandle;

					byte[] sidBytes = new byte[this.Principal.SecurityIdentifier.BinaryLength];
					this.Principal.SecurityIdentifier.GetBinaryForm(sidBytes, 0);

					if (!NativeMethods.AuthzInitializeContextFromSid(
						NativeMethods.AuthzContextFlags.None,
						sidBytes,
						currentAuthzRMHandle,
						IntPtr.Zero,
						NativeMethods.LUID.NullLuid,
						IntPtr.Zero,
						out currentUserContextHandle
					)) {
						
						WriteError(new ErrorRecord(
							new Win32Exception(Marshal.GetLastWin32Error()),
							"",
							ErrorCategory.InvalidData,
							this.Principal
						));
						continue;
					}
					
//					WriteWarning("Don't forget optional device context + claims and groups; doing that will handle closing unused handles...");
					currentClientContextHandle = currentUserContextHandle;

					authzClientContextHandles.Add(currentClientContextKey, currentClientContextHandle);
				}
				currentClientContextHandle = authzClientContextHandles[currentClientContextKey];
				#endregion

				#region Do access check
				SafeHGlobalHandle objectTypeListSafeHandle = SafeHGlobalHandle.InvalidHandle;
				NativeMethods.AUTHZ_ACCESS_REQUEST request = new NativeMethods.AUTHZ_ACCESS_REQUEST();
				request.DesiredAccess = NativeMethods.MAXIMUM_ALLOWED_DESIRED_ACCESS;
				request.PrincipalSelfSid = null;
				request.ObjectTypeList = objectTypeListSafeHandle.ToIntPtr();
				request.ObjectTypeListLength = 0;
				request.OptionalArguments = IntPtr.Zero;

				List<NativeMethods.OBJECT_TYPE_LIST> objectTypeList = new List<NativeMethods.OBJECT_TYPE_LIST>();
				List<ActiveDirectoryAceTypeInstance> objectAceTypeInstances = null;

				try {
					if (currentSd is AdaptedActiveDirectorySecurityDescriptor) {
//						WriteWarning("Should PrincipalSelfSid be looked up for REQUEST?");
						
						NativeMethods.OBJECT_TYPE_LIST currentObjectTypeListElement;

						// We've got to build an OBJECT_TYPE_LIST[] array. First, get a list of ObjectAceType objects
						// that the user specified throught the -ObjectAceType parameter (if this is null, we'll just
						// get an empty list back, which is fine):
						objectAceTypeInstances = this.ObjectAceType[0].GetEffectiveAccessList();

						// The first element must always be the actual AD object's ObjectAceType with a level of 0
	WriteDebug("Get-PacEffectiveAccess: Inserting ObjectAceType at level 0");
						objectAceTypeInstances.Insert(
							0,
							new ActiveDirectoryAceTypeInstance(
								((AdaptedActiveDirectorySecurityDescriptor) currentSd).ObjectAceType.ToString(),
								"", // Name doesn't matter; users won't see this
								"", // DisplayName doesn't matter
								ActiveDirectoryObjectAceTypeGuidType.ClassObject, // Doesn't matter, either
								0,  // This matters; it's the object level
								Guid.Empty
							)
						);

						byte[] currentGuidBytes;
						foreach (ActiveDirectoryAceTypeInstance currentInstance in objectAceTypeInstances) {
							currentObjectTypeListElement = new NativeMethods.OBJECT_TYPE_LIST();

							try {
								currentGuidBytes = new Guid(currentInstance.AceTypeGuid).ToByteArray();
							}
							catch (Exception e) {
								WriteWarning(string.Format("Error getting GUID byte array for '{0}' {1} with GUID '{2}': {3}", currentInstance.DisplayName, currentInstance.ObjectType, currentInstance.AceTypeGuid, e.Message));
								continue;
							}
							
							IntPtr currentPtr = Marshal.AllocHGlobal(currentGuidBytes.Length);
							Marshal.Copy(currentGuidBytes, 0, currentPtr, currentGuidBytes.Length);

							currentObjectTypeListElement.Level = currentInstance.ObjectTypeListLevel;
							currentObjectTypeListElement.ObjectType = currentPtr;
							objectTypeList.Add(currentObjectTypeListElement);
						}
						
						objectTypeListSafeHandle = SafeHGlobalHandle.AllocHGlobal<NativeMethods.OBJECT_TYPE_LIST>(objectTypeList);
						request.ObjectTypeList = objectTypeListSafeHandle.ToIntPtr();
						request.ObjectTypeListLength = (uint) objectTypeList.Count;
						
					}

					Dictionary<string, List<int>> authzResultDict = new Dictionary<string, List<int>>();
					List<PacEffectiveAccessResult> effectiveAccessResultsList = new List<PacEffectiveAccessResult>();

					// Every object has the "Object Permissions" results (this is the SD that's passed into cmdlet):
					authzResultDict.Add(
						"Object Permissions", 
						GetAccessCheckResult(
							currentSd.GetSecurityDescriptorBinaryForm(), 
							request, 
							currentClientContextHandle
						)
					);

					if (currentSd.ObjectType == ResourceType.FileObject) {
						Match shareMatch = Regex.Match(currentSd.Path.ToString(), @"(?<sharepath>\\\\[^\\]+\\[^\\]+)");

						if (shareMatch.Success) {
							AdaptedSecurityDescriptorPathInformation sharePathInfo = new AdaptedSecurityDescriptorPathInformation(
								shareMatch.Groups["sharepath"].Value, 
								shareMatch.Groups["sharepath"].Value,
								ResourceType.LMShare, 
								false
							);

							try {
								WriteDebug(string.Format("Get-PacEffectiveAccess: Getting share security descriptor for '{0}'", shareMatch.Groups["sharepath"].Value));
								// Get the share's SD:
								byte[] shareSdBytes = GetSecurityInfo(sharePathInfo, GetSecurityInformation.Owner | GetSecurityInformation.Access);

								// Attempt to add result to authz dictionary:
								authzResultDict.Add(
									"Share Permissions",
									GetAccessCheckResult(
										shareSdBytes,
										request,
										currentClientContextHandle
									)
								);
							}
							catch (Exception e) {
							
							}
						}
					}

					foreach (string limitedByName in authzResultDict.Keys) {
						for (int i = 0; i < authzResultDict[limitedByName].Count; i++) { 
							if (effectiveAccessResultsList.Count < ( i + 1)) {
								effectiveAccessResultsList.Add(new PacEffectiveAccessResult(
									currentSd._pathInfo, 
									this.Principal, 
									currentSd.AccessRightType,
									objectAceTypeInstances == null ? Guid.Empty :                                // List is null, so effective access result has no limited object ace type
										(i > 0 ? new Guid(objectAceTypeInstances[i].AceTypeGuid) : Guid.Empty)  // If i = 0, no limiting object ace type, otherwise use the GUID
								));
							}
							
							effectiveAccessResultsList[i].AddResult(
								limitedByName, 
								authzResultDict[limitedByName][i]
							);
						}
					}

					for (int i = 0; i < effectiveAccessResultsList.Count; i++) {
						if (this.Detailed) {
							WriteObject(
								effectiveAccessResultsList[i].GetDetailedEffectiveAccess().Where(
									res => res.AccessMask.ToString() != AccessMaskDisplay.NoAccessString
								), 
								true
							);
						}
						else {
							if (i == 0 || effectiveAccessResultsList[i].AccessMask.ToString() != AccessMaskDisplay.NoAccessString) {
								// Only output object if access is granted (or if it's the first result). The only
								// time this comes into play is with AD effective access
								WriteObject(effectiveAccessResultsList[i]);
							}
						}
					}
				}
				catch (Exception e) {
					WriteError(new ErrorRecord(
						new Exception(string.Format("Error calling AuthzAccessCheck(): {0}", e.Message)),
						"",
						ErrorCategory.InvalidData,
						null
					));
					continue;
				}
				finally {
					objectTypeListSafeHandle.Dispose();
					if (objectTypeList.Count != 0) {
						WriteDebug("Freeing ObjectTypeList:");
						foreach (NativeMethods.OBJECT_TYPE_LIST currentElement in objectTypeList) {
							Marshal.FreeHGlobal(currentElement.ObjectType);
						}
					}
				}

				#endregion
			}
		}
		
		protected override void EndProcessing() {
			WriteDebug("Disposing of RM handles:");
			foreach (string currentKey in authzRMHandles.Keys) {
				WriteDebug(string.Format("  -> {0}", currentKey));
				authzRMHandles[currentKey].Dispose();
			}

			WriteDebug("Disposing of client context handles:");
			foreach (Tuple<string, SecurityIdentifier, SecurityIdentifier> currentKey in authzClientContextHandles.Keys) {
				WriteDebug(string.Format("  -> {0}", currentKey));
				authzClientContextHandles[currentKey].Dispose();
			}

		}

		private List<Int32> GetAccessCheckResult(byte[] sdBytes, NativeMethods.AUTHZ_ACCESS_REQUEST request, SafeAuthzClientContextHandle clientContextHandle) {

			NativeMethods.AUTHZ_ACCESS_REPLY reply = new NativeMethods.AUTHZ_ACCESS_REPLY();
			reply.ResultListLength = (request.ObjectTypeListLength < 1) ? 1 : request.ObjectTypeListLength;
WriteDebug(string.Format("Get-PacEffectiveAccess: Reply ResultListLength = {0}", reply.ResultListLength));
			reply.GrantedAccessMask = Marshal.AllocHGlobal((int) (sizeof(uint) * reply.ResultListLength));
			reply.Error = Marshal.AllocHGlobal((int) (sizeof(uint) * reply.ResultListLength));
			reply.SaclEvaluationResults = IntPtr.Zero;
			
			List<Int32> resultList = new List<Int32>();

			try {
				if (!NativeMethods.AuthzAccessCheck(
					NativeMethods.AuthzAccessCheckFlags.None,
					clientContextHandle,
					ref request,
					IntPtr.Zero,  // Audit event (not used)
					sdBytes,
					null,         // Optional SDs
					0,            // Optional SD count
					ref reply,
					IntPtr.Zero   // Cached results (not used; PInvoke signature would have to be modified to start using this)
				)) {
					throw new Win32Exception(Marshal.GetLastWin32Error());
				}
				
				for (int i = 0; i < reply.ResultListLength; i++) {
					IntPtr grantedMaskPtr = IntPtr.Add(reply.GrantedAccessMask, i * sizeof(Int32));
					resultList.Add(Marshal.ReadInt32(grantedMaskPtr));
				}
			}
			catch (Exception e) {
// This will be to catch the call to the reusable method...
				WriteError(new ErrorRecord(
					new Exception(string.Format("Error calling AuthzAccessCheck(): {0}", e.Message)),
					"",
					ErrorCategory.InvalidData,
					null
				));
			}
			finally {
				Marshal.FreeHGlobal(reply.GrantedAccessMask);
				Marshal.FreeHGlobal(reply.Error);
			}

			return resultList;
		}

		internal static SafeAuthzRMHandle GetResourceManagerHandle(string computerName) {

			SafeAuthzRMHandle authzRMHandle;

			if (computerName == string.Empty) {
				// Get local resource manager
				if (!NativeMethods.AuthzInitializeResourceManager(
					NativeMethods.AuthzResourceManagerFlags.NoAudit,
					IntPtr.Zero,  // Access check callback function (Not used here)
					IntPtr.Zero,  // Dynamic groups callback function (Not used here)
					IntPtr.Zero,  // Callback function to free memory from previous callback (Not used here)
					"",           // Resource manager name
					out authzRMHandle
				)) {
					throw new Win32Exception(Marshal.GetLastWin32Error());
				}

			}
			else {
				NativeMethods.AUTHZ_RPC_INIT_INFO_CLIENT rpcInitInfo = new NativeMethods.AUTHZ_RPC_INIT_INFO_CLIENT();
                rpcInitInfo.version = NativeMethods.AuthzRpcClientVersion.V1;
                rpcInitInfo.objectUuid = NativeMethods.AUTHZ_OBJECTUUID_WITHCAP;
                rpcInitInfo.protocol = NativeMethods.RCP_OVER_TCP_PROTOCOL;
                rpcInitInfo.server = computerName;

				// Attempt to get remote resource manager
                SafeHGlobalHandle pRpcInitInfo = SafeHGlobalHandle.AllocHGlobalStruct(rpcInitInfo);
				if (!NativeMethods.AuthzInitializeRemoteResourceManager(
					pRpcInitInfo.ToIntPtr(), 
					out authzRMHandle
				)) {
					throw new Win32Exception(Marshal.GetLastWin32Error());
				}
			}
			
			return authzRMHandle;
		}

		static class NativeMethods {
            // http://msdn.microsoft.com/en-us/library/windows/desktop/aa376322(v=vs.85).aspx
            public struct AUTHZ_ACCESS_REQUEST {
                public UInt32 DesiredAccess;
                public byte[] PrincipalSelfSid;
                public IntPtr ObjectTypeList;
                public UInt32 ObjectTypeListLength;
                public IntPtr OptionalArguments;
            };

            // http://msdn.microsoft.com/en-us/library/windows/desktop/aa379294(v=vs.85).aspx
            public struct OBJECT_TYPE_LIST {
                public UInt16 Level;
                public UInt16 Sbz;
                public IntPtr ObjectType;
            };

            [DllImport("authz.dll", EntryPoint = "AuthzInitializeResourceManager", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool AuthzInitializeResourceManager(
                AuthzResourceManagerFlags flags, 
                IntPtr pfnAccessCheck, 
                IntPtr pfnComputeDynamicGroups,
                IntPtr pfnFreeDynamicGroups, 
                string szResourceManagerName, 
                out SafeAuthzRMHandle phAuthzResourceManager
            );

            [DllImport("authz.dll", EntryPoint = "AuthzInitializeRemoteResourceManager", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool AuthzInitializeRemoteResourceManager(
                IntPtr rpcInitInfo,
                out SafeAuthzRMHandle phAuthzResourceManager
			);
		
            // http://msdn.microsoft.com/en-us/library/windows/desktop/aa376321(v=vs.85).aspx
            public struct AUTHZ_ACCESS_REPLY {
                public UInt32 ResultListLength;
                public IntPtr GrantedAccessMask;
                public IntPtr SaclEvaluationResults;
                public IntPtr Error;
            };


			public struct LUID {
				public UInt32 LowPart;
				public UInt32 HighPart;
	 
				public static LUID NullLuid {
					get {
						LUID NullLuid;
						NullLuid.LowPart  = 0;
						NullLuid.HighPart = 0;
	 
						return NullLuid;
					}
				}
			}

            [Flags]
            public enum AuthzResourceManagerFlags : uint
            {
				None                         = 0,
                NoAudit                      = 0x1,
                InitializeUnderImpersonation = 0x2,
                NoCentralAccessPolicies      = 0x4
            }

            public enum AuthzAccessCheckFlags : uint {
                None = 0,
                NoDeepCopySD
            }

            public enum AuthzRpcClientVersion : ushort {
                V1 = 1
            }

            public const string AUTHZ_OBJECTUUID_WITHCAP = "9a81c2bd-a525-471d-a4ed-49907c0b23da";
            public const string RCP_OVER_TCP_PROTOCOL = "ncacn_ip_tcp";
			public const int MAXIMUM_ALLOWED_DESIRED_ACCESS = 0x2000000;

            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
            public struct AUTHZ_RPC_INIT_INFO_CLIENT
            {
                public AuthzRpcClientVersion version;
                public string objectUuid;
                public string protocol;
                public string server;
                public string endPoint;
                public string options;
                public string serverSpn;
            }

            [Flags]
            public enum AuthzContextFlags : int {
                None              = 0,
                SkipTokenGroups   = 0x2,
                RequireS4ULogon   = 0x4,
                ComputePrivileges = 0x8
            };

            [DllImport("authz.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool AuthzInitializeContextFromSid(
                AuthzContextFlags flags,
                byte[] UserSid,
                SafeAuthzRMHandle hAuthzResourceManager,
                IntPtr pExpirationTime,
                LUID Identifier,
                IntPtr DynamicGroupArgs,
                out SafeAuthzClientContextHandle authzClientContext
			);

            [DllImport("authz.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool AuthzAccessCheck(
                AuthzAccessCheckFlags flags,
                SafeAuthzClientContextHandle hAuthzClientContext,
                ref AUTHZ_ACCESS_REQUEST pRequest,
                IntPtr AuditEvent,
                byte[] pSecurityDescriptor,
                byte[] OptionalSecurityDescriptorArray,
                UInt32 OptionalSecurityDescriptorCount,
                ref AUTHZ_ACCESS_REPLY pReply,
                IntPtr cachedResults
			);
		}
		

		public class SafeAuthzClientContextHandle : SafeHandleZeroOrMinusOneIsInvalid {
			#region Constructors
			SafeAuthzClientContextHandle() : base(true) { }

			SafeAuthzClientContextHandle(IntPtr handle) : base(true) {
				SetHandle(handle);
			}
			#endregion

			public static SafeAuthzClientContextHandle InvalidHandle {
				get { return new SafeAuthzClientContextHandle(IntPtr.Zero); }
			}

			#region Private implementation
			override protected bool ReleaseHandle() {
				return NativeMethods.AuthzFreeContext(base.handle);
			}
			#endregion

			#region Nested class for P/Invokes
				static class NativeMethods {
				[DllImport("authz.dll", SetLastError = true)]
				[return: MarshalAs(UnmanagedType.Bool)]
				public static extern bool AuthzFreeContext(
					IntPtr handle
				);
			}
			#endregion
		}
		

		internal class SafeAuthzRMHandle : SafeHandleZeroOrMinusOneIsInvalid {
			#region Constructors
			/// <summary>
			/// This safehandle instance "owns" the handle, hence base(true)
			/// is being called. When safehandle is no longer in use it will
			/// call this class's ReleaseHandle method which will release
			/// the resources
			/// </summary>
			SafeAuthzRMHandle() : base(true) { }

			[SuppressMessage("Microsoft.Performance", "CA1811:AvoidUncalledPrivateCode",
							 Justification = "Retain to illustrate semantics and for reuse")]
			SafeAuthzRMHandle(IntPtr handle)
				: base(true)
			{
				SetHandle(handle);
			}
			#endregion

			public static SafeAuthzRMHandle InvalidHandle
			{
				[SuppressMessage("Microsoft.Performance", "CA1811:AvoidUncalledPrivateCode",
								 Justification = "Retain to illustrate semantics")]
				get { return new SafeAuthzRMHandle(IntPtr.Zero); }
			}

			#region Private implementation
			/// <summary>
			/// Release the resource manager handle held by this instance
			/// </summary>
			/// <returns>true if the release was successful. false otherwise.</returns>        
			override protected bool ReleaseHandle()
			{
				return NativeMethods.AuthzFreeResourceManager(handle);
			}
			#endregion

			#region Nested class for P/Invokes
			static class NativeMethods
			{
				[DllImport("authz.dll", SetLastError = true),
				 SuppressUnmanagedCodeSecurity,
				 ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
				[return: MarshalAs(UnmanagedType.Bool)]
				public static extern bool AuthzFreeResourceManager(IntPtr handle);
			}
			#endregion
		}
		
		internal sealed class SafeHGlobalHandle : IDisposable {
			#region Constructor and Destructor
			SafeHGlobalHandle()
			{
				pointer = IntPtr.Zero;
			}

			SafeHGlobalHandle(IntPtr handle)
			{
				pointer = handle;
			}

			~SafeHGlobalHandle()
			{
				Dispose();
			}
			#endregion

			#region Public methods
			public static SafeHGlobalHandle InvalidHandle
			{
				get { return new SafeHGlobalHandle(IntPtr.Zero); }
			}

			/// <summary>
			/// Adds reference to other SafeHGlobalHandle objects, the pointer to
			/// which are refered to by this object. This is to ensure that such
			/// objects being referred to wouldn't be unreferenced until this object
			/// is active.
			/// 
			/// For e.g. when this object is an array of pointers to other objects
			/// </summary>
			/// <param name="children">Collection of SafeHGlobalHandle objects
			/// referred to by this object.</param>
			public void AddSubReference(IEnumerable<SafeHGlobalHandle> children)
			{
				if (references == null)
				{
					references = new List<SafeHGlobalHandle>();
				}

				references.AddRange(children);
			}

			/// <summary>
			/// Allocates from unmanaged memory to represent an array of pointers
			/// and marshals the unmanaged pointers (IntPtr) to the native array
			/// equivalent.
			/// </summary>
			/// <param name="values">Array of unmanaged pointers</param>
			/// <returns>SafeHGlobalHandle object to an native (unmanaged) array of pointers</returns>
			public static SafeHGlobalHandle AllocHGlobal(IntPtr[] values)
			{
				SafeHGlobalHandle result = AllocHGlobal(IntPtr.Size * values.Length);

				Marshal.Copy(values, 0, result.pointer, values.Length);

				return result;
			}

			public static SafeHGlobalHandle AllocHGlobalStruct<T>(T obj) where T : struct
			{
				Debug.Assert(typeof(T).StructLayoutAttribute.Value == LayoutKind.Sequential);

				SafeHGlobalHandle result = AllocHGlobal(Marshal.SizeOf(typeof(T)));

				Marshal.StructureToPtr(obj, result.pointer, false);

				return result;
			}
			
			/// <summary>
			/// Allocates from unmanaged memory to represent an array of structures
			/// and marshals the structure elements to the native array of
			/// structures. ONLY structures with attribute StructLayout of
			/// LayoutKind.Sequential are supported.
			/// </summary>
			/// <typeparam name="T">Native structure type</typeparam>
			/// <param name="values">Collection of structure objects</param>
			/// <param name="count">Number of elements in the collection</param>
			/// <returns>SafeHGlobalHandle object to an native (unmanaged) array of structures</returns>
			public static SafeHGlobalHandle AllocHGlobal<T>(ICollection<T> values) where T : struct
			{
				Debug.Assert(typeof(T).StructLayoutAttribute.Value == LayoutKind.Sequential);

				return AllocHGlobal(0, values, values.Count);
			}
			
			/// <summary>
			/// Allocates from unmanaged memory to represent a structure with a
			/// variable length array at the end and marshal these structure
			/// elements. It is the callers responsibility to marshal what preceeds
			/// the trailinh array into the unmanaged memory. ONLY structures with
			/// attribute StructLayout of LayoutKind.Sequential are supported.
			/// </summary>
			/// <typeparam name="T">Type of the trailing array of structures</typeparam>
			/// <param name="prefixBytes">Number of bytes preceeding the trailing array of structures</param>
			/// <param name="values">Collection of structure objects</param>
			/// <param name="count"></param>
			/// <returns>SafeHGlobalHandle object to an native (unmanaged) structure
			/// with a trail array of structures</returns>
			public static SafeHGlobalHandle AllocHGlobal<T>(int prefixBytes, IEnumerable<T> values, int count) where T
																											   : struct
			{
				Debug.Assert(typeof(T).StructLayoutAttribute.Value == LayoutKind.Sequential);

				SafeHGlobalHandle result = AllocHGlobal(prefixBytes + Marshal.SizeOf(typeof(T)) * count);

				IntPtr ptr = result.pointer + prefixBytes;
				foreach (var value in values)
				{
					Marshal.StructureToPtr(value, ptr, false);
					ptr += Marshal.SizeOf(typeof(T));
				}

				return result;
			}
			
			/// <summary>
			/// Allocates from unmanaged memory to represent a unicode string (WSTR)
			/// and marshal this to a native PWSTR.
			/// </summary>
			/// <param name="s">String</param>
			/// <returns>SafeHGlobalHandle object to an native (unmanaged) unicode string</returns>
			public static SafeHGlobalHandle AllocHGlobal(string s)
			{
				return new SafeHGlobalHandle(Marshal.StringToHGlobalUni(s));
			}

			/// <summary>
			/// Operator to obtain the unmanaged pointer wrapped by the object. Note
			/// that the returned pointer is only valid for the lifetime of this
			/// object.
			/// </summary>
			/// <param name="safeHandle">SafeHGlobalHandle object</param>
			/// <returns>Unmanaged pointer wrapped by the object</returns>
			public IntPtr ToIntPtr()
			{
				return pointer;
			}
			#endregion

			#region IDisposable implmentation
			public void Dispose()
			{
				if (pointer != IntPtr.Zero)
				{
					Marshal.FreeHGlobal(pointer);
					pointer = IntPtr.Zero;
				}

				GC.SuppressFinalize(this);
			}
			#endregion

			#region Private implementation
			[SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope",
							 Justification="Caller will dispose result")]
			static SafeHGlobalHandle AllocHGlobal(int cb)
			{
				if (cb < 0)
				{
					throw new ArgumentOutOfRangeException("cb", "The value of this argument must be non-negative");
				}

				SafeHGlobalHandle result = new SafeHGlobalHandle();

				//
				// CER
				//
				RuntimeHelpers.PrepareConstrainedRegions();
				try { }
				finally
				{
					result.pointer = Marshal.AllocHGlobal(cb);
				}

				return result;
			}
			#endregion

			#region Private members
			/// <summary>
			/// Maintainsreference to other SafeHGlobalHandle objects, the pointer
			/// to which are refered to by this object. This is to ensure that such
			/// objects being referred to wouldn't be unreferenced until this object
			/// is active.
			/// </summary>
			List<SafeHGlobalHandle> references;

			//
			// Using SafeHandle here doesn't buy much since the pointer is
			// eventually stashed into a native structure. Using a SafeHandle would
			// involve calling DangerousGetHandle in place of ToIntPtr which makes
			// code analysis report CA2001: Avoid calling problematic methods.
			//
			[System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Reliability", "CA2006:UseSafeHandleToEncapsulateNativeResources")]
			/// <summary>
			/// Unmanaged pointer wrapped by this object
			/// </summary>
			IntPtr pointer;
			#endregion
		}

	}


	public class PacEffectiveAccessDetailedResult {
		public PacEffectiveAccessDetailedResult(PacEffectiveAccessResult result, bool granted, int accessMask, List<string> limitedBy) {
			this.Path = result.Path;
			this.Principal = result.Principal;
			this.Granted = granted;
			this.AccessMask = new AccessMaskDisplay(accessMask, result.AccessRightType, result.ObjectAceType);
			this.LimitedBy = string.Join(", ", limitedBy.ToArray());
		}

		public AdaptedSecurityDescriptorPathInformation Path { get; private set; }
		public PacPrincipal Principal { get; private set; }
		public bool Granted { get; private set; }
		public AccessMaskDisplay AccessMask { get; private set; }
		public string LimitedBy { get; private set; }
		
	}

	public class PacEffectiveAccessResult {

		public PacEffectiveAccessResult(AdaptedSecurityDescriptorPathInformation pathInfo, PacPrincipal principal, Type accessRightType) : this(pathInfo, principal, accessRightType, Guid.Empty) { }

		public PacEffectiveAccessResult(AdaptedSecurityDescriptorPathInformation pathInfo, PacPrincipal principal, Type accessRightType, Guid objectAceType) {
			this.Path = pathInfo;
			this.Principal = principal;
			this.AccessRightType = accessRightType;
			this.ObjectAceType = objectAceType;
		}
		
		Dictionary<string, int> _results = new Dictionary<string, int>();
		
		public void AddResult(string description, int accessMask) {
			_results.Add(description, accessMask);
			
			int newEffectiveAccessMask = int.MaxValue;
			foreach (string currentKey in _results.Keys) {
				newEffectiveAccessMask &= _results[currentKey];
			}
			_effectiveAccessMask = newEffectiveAccessMask;
		}
		
		int _effectiveAccessMask;
		public AdaptedSecurityDescriptorPathInformation Path { get; private set; }
		public PacPrincipal Principal { get; private set; }
		
		internal Type AccessRightType { 
			get {
				return _accessRightType ??
					typeof(int);
			}

			private set {
				if (value.IsDefined(typeof(FlagsAttribute), false)) {
					_accessRightType = value;
				}
			} 
		}
		Type _accessRightType;

		internal Guid ObjectAceType { get; private set; }
		
		public AccessMaskDisplay AccessMask {
			get {
				if (_oldEffectiveAccessMaskDisplay == null || _effectiveAccessMask != _oldEffectiveAccessMaskDisplay.AccessMask) {
					_oldEffectiveAccessMaskDisplay = new AccessMaskDisplay(_effectiveAccessMask, this.AccessRightType, this.ObjectAceType);
				}
				return _oldEffectiveAccessMaskDisplay;
			}
		}
		AccessMaskDisplay _oldEffectiveAccessMaskDisplay = null;
		
		public IEnumerable<PacEffectiveAccessDetailedResult> GetDetailedEffectiveAccess() {
			return GetDetailedEffectiveAccess(RightsDictionaryViewType.NoCombinedRights);
		}

		public IEnumerable<PacEffectiveAccessDetailedResult> GetDetailedEffectiveAccess(RightsDictionaryViewType viewType) {

			// Rights dictionary will contain all of the detailed rights:
			SortedList<int, string> rightsDictionary;
			try {
				rightsDictionary = AccessMaskDisplay.GetRightsDictionary(this.AccessRightType, viewType);
			}
			catch {
				throw new Exception(string.Format("Unable to get detailed rights for '{0}' type", this.AccessRightType));
			}
			
			List<string> limitedBy = new List<string>();
			bool numericRightGranted;
			
			// A new object will be created for each right, so enumerate each key:
			foreach (int numericRight in rightsDictionary.Keys) {
				// Files and folders (possibly other objects, too) can have more than one SD, so
				// go through each one to see if any deny the current numericRight. If so, add
				// that SD's description to the limitedBy list
				limitedBy.Clear();
				numericRightGranted = true;  // Assume right is granted until you find a _result that denies it
				foreach (string description in _results.Keys) {
					if ((numericRight & _results[description]) != numericRight) {
						numericRightGranted = false;
						limitedBy.Add(description);
					}
				}

				yield return new PacEffectiveAccessDetailedResult(this, numericRightGranted, numericRight, limitedBy);
			}
		}
	}
}
