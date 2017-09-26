Import-Module ActiveDirectory
Import-Module PowerShellAccessControl
. 'C:\Program Files\WindowsPowerShell\Modules\PowerShellAccessControl\examples\dsc\cAccessControlEntry.ps1'
TestAceResource -OutputPath C:\powershell\dsc_configs
Start-DscConfiguration -Path C:\powershell\dsc_configs -Wait -Verbose