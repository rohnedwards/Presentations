$Sddl = "O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464G:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:PAI(A;OICIIO;GA;;;CO)(A;OICIIO;GA;;;SY)(A;;0x1301bf;;;SY)(A;OICIIO;GA;;;BA)(A;;0x1301bf;;;BA)(A;OICIIO;GXGR;;;BU)(A;;0x1200a9;;;BU)(A;CIIO;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;0x1200a9;;;AC)(A;OICIIO;GXGR;;;AC)"

Measure-Command {
$folders = gci C:\Windows -Directory -Recurse
$mjols = $folders.Where({$_.GetAccessControl().Sddl -eq $Sddl})
}

Measure-Command {
$mine = Get-SecurityDescriptor "(?rd)c:\windows\*" | ? sddl -eq $Sddl
}

measure-command { 
$mine2 = get-pacpathinfo "(?rd)c:\windows\*" | ? {[System.IO.Directory]::GetAccessControl($_.SdPath).Sddl -eq $Sddl }
}
Get-SecurityDescriptor "(?rd)c:\foo" | where sddl -eq "O:BAG:DUD:PARAI(A;OICI;FA;;;BA)"

<#

This one is about 2-5 seconds faster than mine (even when -DontMergeAces is used). Why?
measure-command { $his = dir2 C:\Windows -Recurse -Directory -IncludeHidden -IncludeSystem | ? { $_.GetAccessControl().sddl -eq "O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464G:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:PAI(A;OICIIO;GA;;;CO)(A;OICIIO;GA;;;SY)(A;;0x1301bf;;;SY)(A;OICIIO;GA;;;BA)(A;;0x1301bf;;;BA)(A;OICIIO;GXGR;;;BU)(A;;0x1200a9;;;BU)(A;CIIO;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;0x1200a9;;;AC)(A;OICIIO;GXGR;;;AC)" } }
Days              : 0
Hours             : 0
Minutes           : 0
Seconds           : 15
Milliseconds      : 227
Ticks             : 152279927
TotalDays         : 0.000176249915509259
TotalHours        : 0.00422999797222222
TotalMinutes      : 0.253799878333333
TotalSeconds      : 15.2279927
TotalMilliseconds : 15227.9927


#>