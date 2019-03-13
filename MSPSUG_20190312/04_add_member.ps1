Get-Command -Syntax Add-Member

[System.Management.Automation.PSMemberTypes] | Get-Member -Static -MemberType Property | Select-Object -ExpandProperty Name

# NoteProperty

# AliasProperty

# ScriptMethod

# ScriptProperty
