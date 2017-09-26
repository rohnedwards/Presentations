param(
    [switch] $IgnoreWarnings
)

#gcim win32_computersystem | Out-Null
#Add-Type -Path "$PSScriptRoot\source.cs" -OutputAssembly "$PSScriptRoot\ROE.PowerShellAccessControl.dll" -ReferencedAssemblies System.DirectoryServices, System.Management, Microsoft.Management.Infrastructure -IgnoreWarnings

gcim win32_computersystem | Out-Null # This makes sure the Microsoft.Management.Infrastructure assembly is loaded
$OutputFile = "$PSScriptRoot\ROE.PowerShellAccessControl.dll"
$ReferencedAssemblies = echo System.DirectoryServices, System.Management, Microsoft.Management.Infrastructure, System.ServiceProcess, Microsoft.WSMan.Management, Microsoft.PowerShell.Commands.Management, Microsoft.CSharp, Microsoft.Management.Infrastructure.CimCmdlets #, Microsoft.ActiveDirectory.Management

$UsingStatements = @()
$SourceCode = @()

<# 
dir $PSScriptRoot -Filter *.cs -Recurse | Get-Content | % {
    if ($_ -match "using .*;") {
        $UsingStatements += $_
    }
    else {
        $SourceCode += $_
    }
}
#>
<# #>
dir $PSScriptRoot -Filter *.cs -Recurse | Get-Content -Raw | % {
    foreach ($line in ($_ -split "`n")) {
        if ($line -match "^using .*;") {
            $UsingStatements += $line
        }
        else {
            $SourceCode += $line
        }
    }
}
#>


$UsingStatements = $UsingStatements | Select-Object -Unique
$SourceCode = ($UsingStatements + $SourceCode) -join "`n"

Add-Type -TypeDefinition $SourceCode -ReferencedAssemblies $ReferencedAssemblies -OutputAssembly $OutputFile -IgnoreWarnings:$IgnoreWarnings
