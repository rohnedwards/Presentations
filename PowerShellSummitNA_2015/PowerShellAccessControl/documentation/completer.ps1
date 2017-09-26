$NewAceCompleter = {
 
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameter)
    if ($commandName -ne "New-AccessControlEntry") { return }

    $KnownRuleTypes = [System.Security.AccessControl.FileSystemAccessRule].Assembly.GetTypes() | ? name -match "(Access|Audit)Rule"
    $KnownRuleTypes += [wmi], [ciminstance]
    $KnownRuleTypes | ForEach-Object {
        New-Object System.Management.Automation.CompletionResult @(
            $_.FullName, 
            $_.Name, 
            'ParameterValue', 
            $_.FullName
        )
    }
}
 
if (-not $global:options) { $global:options = @{CustomArgumentCompleters = @{};NativeArgumentCompleters = @{}}}
$global:options['CustomArgumentCompleters']['OutputType'] = $NewAceCompleter
$function:tabexpansion2 = $function:tabexpansion2 -replace 'End\r\n{','End { if ($null -ne $options) { $options += $global:options} else {$options = $global:options}'