# Make sure you have the Get-PsMemberTypeViews function from 02_adapted_type_system.ps1

$Cert = dir Cert:\LocalMachine\Root | Select-Object -First 1
$File = dir C:\Windows -File | Select-Object -First 1
$RegKey = Get-Item HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion

# Let's look at properties added by ETS on $Cert:
$Cert | Get-PsMemberTypeViews | Where-Object View -match Extended

# Notice the PS* properties. If we look at the extended properties on the Cert, File, and RegKey
# together, you'll notice that those properties are on all of the objects:
'Cert', 'File', 'RegKey' | ForEach-Object {
    $VarType = $_
    Get-Variable -Name $VarType -ValueOnly | Get-PsMemberTypeViews | Where-Object View -match Extended | ForEach-Object {
        [PSCustomObject] @{
            ObjType = $VarType
            MemberName = $_.Name
            MemberType = $_.MemberType
        }
    }
} | Group-Object MemberName | Sort-Object Count

# This is an example of using the ETS for "object normalization"
$Cert.PSPath
$RegKey.PSPath

# Most of the members from the ETS are defined in XML files that live in the PowerShell installation
# directory (for Windows PowerShell; PowerShell Core doesn't seem to have much here):
dir $PSHOME *type*.ps1xml

dir $PSHOME *type*.ps1xml | Sort-Object Length | Select-Object -First 1 | Get-Content

# If they're defined in these type files, then the members will magically get added anytime an object
# of the defined type is instantiated. Let's dump all of them to look at some definitions:
$EtsDict = dir $PSHOME *type*.ps1xml -Recurse | ForEach-Object {
    [xml] $XmlContents = cat $_.FullName

    foreach ($Type in $XmlContents.SelectNodes('//Type[Members]')) {

        foreach ($MemberType in $Type.Members.psadapted.psobject.Properties) {
            foreach ($Member in $MemberType.Value) {

                [PSCustomObject] @{
                    FullName = $_.FullName
                    FileName = $_.Name
                    TypeName = $Type.Name
                    MemberType = $MemberType.Name
                    MemberName = $Member.Name
                    UnstructuredDef = $Member.psadapted.psobject.Properties | Where-Object Name -ne Name | Select-Object Name, @{N='Value'; E={ if ($_.Value -is [System.Xml.XmlElement]) { $_.Value.InnerXml } else { $_.Value }}} | Format-List | Out-String | ForEach-Object Trim
                }
            }
        }
    }
} | Group-Object TypeName -AsHashTable -AsString

$EtsDictByMemberName = $EtsDict.Values | ForEach-Object { $_ } | Group-Object MemberName -AsHashTable -AsString
$EtsDict['System.IO.FileInfo'] | ft

# Note that none of those PS* properties are listed. If it's not there, then a FileInfo object created outside of
# Get-Item and Get-ChildItem shouldn't have them, either:
$FileRaw = [System.IO.FileInfo]::new($File.FullName)
$FileRaw | Get-Member PS*
$FileRaw | Get-Member PS* -Force

# Cmdlets can add any synthetic properties they want to objects returned. You can do it, too, with Add-Member