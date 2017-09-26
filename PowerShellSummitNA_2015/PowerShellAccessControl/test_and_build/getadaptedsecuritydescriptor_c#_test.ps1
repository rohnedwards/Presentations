
gwmi win32_service | select -first 1 | % { [ROE.PowerShellAccessControl.Helper]::GetAdaptedSecurityDescriptor($_)}
get-service | select -last 1 | % { [ROE.PowerShellAccessControl.Helper]::GetAdaptedSecurityDescriptor($_) }
gwmi win32_printer | select -first 2 | % { [ROE.PowerShellAccessControl.Helper]::GetAdaptedSecurityDescriptor($_) }
get-printer | select -first 2 | % { [ROE.PowerShellAccessControl.Helper]::GetAdaptedSecurityDescriptor($_) }
