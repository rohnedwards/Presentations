# Problem: What if you wanted registry key information to be attached to the key itself, instead of having to
# call Get-ItemProperty?

# Step 1: Mock up the behaviour you want

$RegKey = Get-Item HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion
foreach ($ValueName in $RegKey.GetValueNames()) {
    [PSCustomObject] @{
        # Path = $RegKey.PsPath
        ValueName = $ValueName
        ValueType = $RegKey.GetValueKind($ValueName)
        ValueValue = $RegKey.GetValue($ValueName, $null, 'DoNotExpandEnvironmentNames')
    }
}

# Next, take that code and use Update-TypeData:
$RegKey.GetType().FullName   # Show the type name

Update-TypeData -TypeName Microsoft.Win32.RegistryKey -MemberType ScriptProperty -MemberName Values -Value {
    $RegKey = $this
    foreach ($ValueName in $RegKey.GetValueNames()) {
        [PSCustomObject] @{
            # Path = $RegKey.PsPath
            ValueName = $ValueName
            ValueType = $RegKey.GetValueKind($ValueName)
            ValueValue = $RegKey.GetValue($ValueName, $null, 'DoNotExpandEnvironmentNames')
        }
    }
}

$TempKey = mkdir HKCU:\Software\TmpKey
$TempKey | Format-List Value*
Set-ItemProperty -Path $TempKey.PSPath -Name Test -Value 'testvalue'
$TempKey | Format-List Value*

