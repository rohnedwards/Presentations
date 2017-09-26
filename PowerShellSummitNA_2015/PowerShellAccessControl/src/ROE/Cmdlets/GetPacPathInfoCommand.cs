namespace ROE.PowerShellAccessControl {
/*
	Responsible for taking an arbitrary object and giving an AdaptedSecurityDescriptorPathInformation instance.
*/
	[Cmdlet(VerbsCommon.Get, "PacPathInfo", DefaultParameterSetName="ByPath")]
	public class GetPacPathInfoCommand : PacModuleCmdlet {

		#region Cmdlet Overrides
		
		protected override void BeginProcessing() {
			base.BeginProcessing();
		}
		protected override void ProcessRecord() {
			foreach (AdaptedSecurityDescriptorPathInformation currentPathInfo in GetPathInfoFromPSObject(this.InputObject)) {
				WriteObject(currentPathInfo);
			}
		}
		#endregion
	}
}