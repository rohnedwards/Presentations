
namespace ROE.PowerShellAccessControl {

	[Cmdlet(VerbsCommon.Get, "PacSecurityDescriptor")]
	[OutputType(new Type[] { typeof(AdaptedSecurityDescriptor) })]
	public class GetPacSecurityDescriptorCommand : PacModuleCmdlet {
	
		#region Parameters
		[Parameter()]
		public SwitchParameter Audit { get; set; }
		#endregion
		

		protected override void BeginProcessing() {
			if (this.Audit) {
				if (base.PacSDOption.SecurityDescriptorSections == 0) {
					base.PacSDOption.SecurityDescriptorSections = GetSecurityInformation.AllAccessAndAudit;
				}
				else {
					base.PacSDOption.SecurityDescriptorSections |= GetSecurityInformation.Audit;
				}
			}
			
			base.BeginProcessing();
		}
		
		protected override void ProcessRecord() {
			IEnumerable<AdaptedSecurityDescriptor> adaptedSds = this.GetAdaptedSecurityDescriptor(
				this.InputObject
			);

			foreach (AdaptedSecurityDescriptor currentSD in adaptedSds) {
				WriteObject(currentSD);
			}
		}

		protected override void EndProcessing() {

			// Revert any privileges that were enabled
			Dispose();

		}
	}
}