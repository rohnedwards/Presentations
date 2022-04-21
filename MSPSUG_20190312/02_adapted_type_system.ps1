
function Get-PsMemberTypeViews {
<#
This is a function that will show the properties contained in each "View", and whether or not the property
is included in the default Get-Member output
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        $InputObject,
        [switch] $GroupByProperty
    )

    begin {
        $ViewsToExclude = 'All'
        $MemberViewTypes = [System.Management.Automation.PSMemberViewTypes] | Get-Member -Static -MemberType Property | Where-Object Name -notin $ViewsToExclude | Select-Object -ExpandProperty Name
    }

    process {
        $DefaultGetMemberProps = Get-Member -InputObject $InputObject | Select-Object -ExpandProperty Name
        $DefaultOutput = foreach ($CurrentView in $MemberViewTypes) {
            Get-Member -InputObject $InputObject -View $CurrentView | Select-Object @{N='View'; E={$CurrentView}}, Name, MemberType, @{N='InDefaultGMOutput'; E={$_.Name -in $DefaultGetMemberProps}}
        }

        if ($GroupByProperty) {
            $DefaultOutput | Group-Object Name, MemberType | ForEach-Object {
                [PSCustomObject] @{
                    Name = $_.Group[0].Name
                    MemberType = $_.Group[0].MemberType
                    Views = $_.Group.ForEach({'{0}{1}' -f $_.View, "$(if ($_.InDefaultGMOutput) { '' } else { '*' } )"}) -join '/'
                }
            }
        }
        else {
            $DefaultOutput
        }
    }
}

# Let's look at the $File object from the previous demo:
$File | Get-PsMemberTypeViews -GroupByProperty

# That was a FileInfo object. What about a CIM instance?
$CimInstance = Get-CimInstance Win32_OperatingSystem
$CimInstance | Get-PsMemberTypeViews
$CimInstance | Get-PsMemberTypeViews -GroupByProperty

# Note that there are three properties that show as being in 'Base*', but not adapted: CimClass, CimInstanceProperties, CimSystemProperties
# They're real, and you can access them (even with tab completion):
$CimInstance.CimClass

# But Get-Member won't show them by default:
$CimInstance | Get-Member Cim*
$CimInstance | Get-Member Cim* -Force

# You can see them with Get-Member like this:
$CimInstance | Get-Member -View Base

# Even though Get-Member hides them, there are other ways to see them:
$CimInstance.psobject.Properties | Where-Object Name -like Cim*
$CimInstance.psbase
$CimInstance.psbase.psobject.Properties
$CimInstance.psbase | Get-Member

# As mentioned in the slides, Get-Member will show you the Adapted + Extended members.
# Adapted almost always includes all Base members, so those views are usually pretty similar
# (if not identical)

# That doesn't hold for WMI objects, though:
$WmiInstance = Get-WmiObject Win32_OperatingSystem
$WmiInstance | Get-PsMemberTypeViews -GroupByProperty | Format-Table -AutoSize

# And XML objects hide a lot of base properties:
[xml]::new() | Get-PsMemberTypeViews -GroupByProperty

# XML documents and nodes provide a pretty good example of how the adapted type
# system does it's job to add dynamic properties:
$XmlExample = @'
<root>
<node Attribute='AnAttribute'><child Attribute='ChildAttribute' /></node>
<node Attribute='AnotherAttribute'></node>
</root>
'@ -as [xml]
$XmlExample | Get-PsMemberTypeViews -GroupByProperty | Tee-Object -Variable XmlDocumentMembers | Where-Object Views -eq Adapted
$XmlExample.root | Get-PsMemberTypeViews -GroupByProperty | Tee-Object -Variable XmlRootElementMembers | Where-Object Views -eq Adapted
$XmlExample.root.node[0] | Get-PsMemberTypeViews -GroupByProperty | Tee-Object -Variable XmlChildElementMembers | Where-Object Views -eq Adapted

Compare-Object $XmlRootElementMembers $XmlChildElementMembers -Property Name, Views

# The point of all of that is to show that PowerShell does lots with different types of objects without you even knowing it

# A few more examples:
$ComObject = New-Object -ComObject Shell.Application
$ComObject | Get-PsMemberTypeViews -GroupByProperty

[datetime]::Now | Get-PsMemberTypeViews -GroupByProperty
Get-Item HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion | Get-PsMemberTypeViews -GroupByProperty
Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion | Get-PsMemberTypeViews -GroupByProperty   # This is basically just a property bag


# Not sure if this should stay or not:
$AdapterType = [powershell].Assembly.GetType('System.Management.Automation.Adapter')
$PsAdapters = [powershell].Assembly.GetTypes() | Where-Object {
    $_.IsSubclassOf($AdapterType)
}
$AllAdapters = [System.AppDomain]::CurrentDomain.GetAssemblies() | % { $_.GetTypes() | Where-Object { $_.IsSubclassOf($AdapterType) }}