<###############################################
  Viewing access with native PS cmdlets/.NET
###############################################>

# Get-Acl returns an object that has Access and Audit (if -Audit switch was provided) properties, which
# contain the DACL and SACL, respectively. Here's how to list DACL with native code (remember to remove
# the call to Format-Table if you need to do anything with the ACE objects)

Get-Acl $RootFolderPath | Select-Object -ExpandProperty Access | Format-Table

# One big problem with that is it doesn't contain any reference to the object that the ACE belongs to. To 
# fix, you can do the following:
Get-Acl $RootFolderPath | Select-Object @{N="Path"; E={Convert-Path $_.Path}} -ExpandProperty Access | Format-Table

# Another modification that shows both the DACL and SACL:
dir $RootFolderPath -Exclude NoAccess | Get-Acl -Audit | ForEach-Object {
    $PathProperty = @{N="Path"; E={ Convert-Path $_.Path }}
    $AuditAceTypeProperty = @{N="AccessControlType"; E={ "Audit {0}" -f $_.AuditFlags }}
    $_ | Select-Object $PathProperty -ExpandProperty Access
    $_ | Select-Object $PathProperty -ExpandProperty Audit | Select-Object *, $AuditAceTypeProperty
} | Format-Table -GroupBy Path # Export-Csv command here would replace Format-Table

# That works, and the data can be sent to a CSV, Out-GridView, etc
# A few issues, though:
#   1. Generic rights aren't translated (look at the first example; notice the numeric rights?)
#   2. When looking at the ACEs interactively, Format-Table has to be added to get a friendly view
#   3. Filtering has to be done in a Where-Object or Foreach-Object block
#   4. Get-Acl throws terminating errors, so last example (where dir was sent as input) will only work if
#      Get-Acl doesn't encounter any errors. To fix that, you have to use an extra ForEach-Object block
#      so you can wrap the Get-Acl call in a try{} block.
#

#region Get-Acl terminating error example

#Problem:
dir $RootFolderPath | Get-Acl -Audit -ErrorAction SilentlyContinue | ForEach-Object {
    $PathProperty = @{N="Path"; E={ Convert-Path $_.Path }}
    $AuditAceTypeProperty = @{N="AccessControlType"; E={ "Audit {0}" -f $_.AuditFlags }}
    $_ | Select-Object $PathProperty -ExpandProperty Access
    $_ | Select-Object $PathProperty -ExpandProperty Audit | Select-Object *, $AuditAceTypeProperty
} | Format-Table -GroupBy Path

# Pipeline is aborted when NoAccess folder is encountered. To fix the issue, wrap Get-Acl in a try{} block:
dir $RootFolderPath | ForEach-Object {
    try {
        $SD = $_ | Get-Acl -Audit #-ErrorAction SilentlyContinue
    }
    catch {
        Write-Error $_
        return
    }

    $PathProperty = @{N="Path"; E={ Convert-Path $SD.Path }}
    $AuditAceTypeProperty = @{N="AccessControlType"; E={ "Audit {0}" -f $_.AuditFlags }}
    $SD | Select-Object $PathProperty -ExpandProperty Access
    $SD | Select-Object $PathProperty -ExpandProperty Audit | Select-Object *, $AuditAceTypeProperty
} | Format-Table -GroupBy Path

#endregion


# The PowerShell Access Control module tries to address these issues (and more)


<###########################################################
  Viewing access with the PowerShell Access Control Module
############################################################>

# The Get-PacAccessControlEntry fixes all of the issues mentioned above. It can be used with or without
# Get-Acl (when Get-Acl is used, the terminating error problem still exists)

Get-Acl $RootFolderPath -Audit | Get-PacAccessControlEntry
# Notice that generic rights are being translated and the default formatting presents the information in
# an easy to view table.

# Filtering works:
Get-Acl $RootFolderPath -Audit | Get-PacAccessControlEntry -Principal *Users*, *Admin*
Get-Acl $RootFolderPath -Audit | Get-PacAccessControlEntry -Principal *Users*, *Admin* -FolderRights Write
Get-Acl $RootFolderPath -Audit | Get-PacAccessControlEntry -Principal *Users*, *Admin* -FolderRights Modify -Specific
dir $RootFolderPath -Exclude NoAccess | Get-PacAccessControlEntry -ExcludeInherited -FolderRights Modify

# If Get-Acl isn't used, encountering an object that we don't have access to doesn't cause the entire
# command to stop outputting information:
dir $RootFolderPath | sort Name | Get-PacAccessControlEntry -PacSDOption (New-PacSDOption -Audit)
dir $RootFolderPath | sort Name | Get-PacSecurityDescriptor -Audit | Get-PacAccessControlEntry

#region Examples of other object that the PAC module supports
# Registry keys
dir HKLM:\SOFTWARE | select -first 2 | Get-PacAccessControlEntry

# Printer, service and device driver (different types of objects can be checked at the same time):
(Get-CimInstance Win32_Printer | select -first 2), 
(Get-Service | select -first 2), 
([System.ServiceProcess.ServiceController]::GetDevices() | select -first 2) | 
    Get-PacAccessControlEntry

# Process:
Get-Process | where Handle | select -First 2 | Get-PacAccessControlEntry

# WsMan:
dir WSMan:\localhost -Recurse | ? name -eq Sddl | select -first 3 | Get-PacAccessControlEntry

# AD object (See the AD demo script for more):
Import-Module ActiveDirectory
dir AD:\ | Get-PacAccessControlEntry
#endregion

