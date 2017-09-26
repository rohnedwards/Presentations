<#
"My" just went to a void method that uses WriteObject directly instead of yield return
#>

0..19 | % { measure-command { $myrecurse = Get-PacPathInfo C:\powershell -Recurse -ErrorAction SilentlyContinue -ErrorVariable myrecurseerrors } } | Measure-Object -Average -Minimum -Maximum TotalMilliseconds
<#
Count    : 20
Average  : 205.78822
Sum      : 
Maximum  : 466.5956
Minimum  : 173.8218
Property : TotalMilliseconds

PS C:\powershell\git\PowerShellAccessControl\src> $myrecurse.Count
1878

PS C:\powershell\git\PowerShellAccessControl\src> $myrecurseerrors.Count
3

#>

0..19 | % { measure-command { $theirrecurse = dir C:\powershell -Recurse -Force -ErrorAction SilentlyContinue -ErrorVariable theirrecurseerrors} } | Measure-Object -Average -Minimum -Maximum TotalMilliseconds
<#
Count    : 20
Average  : 287.14508
Sum      : 
Maximum  : 496.0332
Minimum  : 255.168
Property : TotalMilliseconds

PS C:\powershell\git\PowerShellAccessControl\src> $theirrecurse.Count
1842   # Missing c:\powershell itself (design difference) and long path objects

PS C:\powershell\git\PowerShellAccessControl\src> $theirrecurseerrors.Count
4

#>

0..19 | % { measure-command { $myrecurse2 = Get-PacPathInfo C:\windows -Recurse -ErrorAction SilentlyContinue -ErrorVariable myrecurse2errors } } | Measure-Object -Average -Minimum -Maximum TotalMilliseconds
<#
Count    : 20
Average  : 18671.374815
Sum      : 
Maximum  : 19550.3667
Minimum  : 18259.3033
Property : TotalMilliseconds

PS C:\powershell\git\PowerShellAccessControl\src> $myrecurse2.Count
150496

PS C:\powershell\git\PowerShellAccessControl\src> $myrecurse2errors.Count
43

#>

0..19 | % { measure-command { $theirrecurse2 = dir C:\Windows -Force -Recurse -ErrorAction SilentlyContinue -ErrorVariable theirrecurse2errors } } | Measure-Object -Average -Minimum -Maximum TotalMilliseconds
<#
Count    : 20
Average  : 40726.65854
Sum      : 
Maximum  : 43197.0008
Minimum  : 39470.9465
Property : TotalMilliseconds

PS C:\powershell\git\PowerShellAccessControl\src> $theirrecurse2.Count
150496  #Count is the same b/c of a file that was added b/w runs

PS C:\powershell\git\PowerShellAccessControl\src> $theirrecurse2errors.Count
43


#>

0..19 | % { measure-command { $myfiles = Get-PacPathInfo C:\powershell -Recurse -File -ErrorAction SilentlyContinue -ErrorVariable myfileserrors } } | Measure-Object -Average -Minimum -Maximum TotalMilliseconds
<#
Count    : 20
Average  : 185.677165
Sum      : 
Maximum  : 387.6199
Minimum  : 165.9303
Property : TotalMilliseconds

PS C:\powershell\git\PowerShellAccessControl\src> $myfiles.Count
1231

PS C:\powershell\git\PowerShellAccessControl\src> $myfileserrors.Count
3
#>

0..19 | % { measure-command { $theirfiles = dir C:\powershell -Recurse -File -ErrorAction SilentlyContinue -ErrorVariable theirfileserrors -Force } } | Measure-Object -Average -Minimum -Maximum TotalMilliseconds
<#
Count    : 20
Average  : 85.314715
Sum      : 
Maximum  : 145.5006
Minimum  : 47.3054
Property : TotalMilliseconds


#>

0..19 | % { measure-command { $theirdirs2 = dir C:\windows -Recurse -Directory -ErrorAction SilentlyContinue -ErrorVariable theirdirs2errors -Force } } | Measure-Object -Average -Minimum -Maximum TotalMilliseconds


measure-command { $sds = Get-PacPathInfo C:\Windows\* -Recurse | % { Get-PacSecurityDescriptor -InputObject $_ } }
measure-command { $acls = dir C:\Windows -Recurse | % { get-acl } }


measure-command { Get-AccessControlEntry "(?r)c:\windows" | Export-Csv -Path c:\windows_permissions_2.csv }
<#
Days              : 0
Hours             : 0
Minutes           : 9
Seconds           : 44
Milliseconds      : 37
Ticks             : 5840372398
TotalDays         : 0.00675969027546296
TotalHours        : 0.162232566611111
TotalMinutes      : 9.73395399666667
TotalSeconds      : 584.0372398
TotalMilliseconds : 584037.2398

#>

measure-command { Get-AccessControlEntry "(?r)c:\windows" -DisplayOptions DontMergeAces | Export-Csv -Path c:\windows_permissions_nomerge.csv }
<#
Days              : 0
Hours             : 0
Minutes           : 8
Seconds           : 3
Milliseconds      : 254
Ticks             : 4832541013
TotalDays         : 0.0055932187650463
TotalHours        : 0.134237250361111
TotalMinutes      : 8.05423502166667
TotalSeconds      : 483.2541013
TotalMilliseconds : 483254.1013
#>

measure-command { Get-AccessControlEntry "(?rd)c:\windows" -DisplayOptions DontMergeAces | Export-Csv -Path c:\windows_folder_permissons_no_merge.csv }
<#
Days              : 0
Hours             : 0
Minutes           : 1
Seconds           : 55
Milliseconds      : 561
Ticks             : 1155614213
TotalDays         : 0.00133751645023148
TotalHours        : 0.0321003948055556
TotalMinutes      : 1.92602368833333
TotalSeconds      : 115.5614213
TotalMilliseconds : 115561.4213

#>