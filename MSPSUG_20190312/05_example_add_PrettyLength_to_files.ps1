<#
The Length property on files shows the size in bytes. That's very ugly for large files, so let's make a
property to show a prettier form.
#>

# First, here's a helper function to do what I'm after:
function Get-PrettyFileSize {
<#
.SYNOPSIS
Gets a pretty file size, e.g., 1 KB instead of 1024.

.DESCRIPTION
Get-PrettyFileSize is a helper function that simply takes a raw number that 
represents the size, in bytes, of a file, and converts it into a string that 
shows a more readable number of GB, MB, KB, or B.

.EXAMPLE
dir c:\windows -File | Get-PrettyFileSize

#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        # The raw size, in bytes
        [long] $Length,
        # The number of decimal places to show in the string
        [int] $Precision = 1
    )

    begin {
        $SizeDict = [ordered] @{
            1gb.ToString() = 'GB'
            1mb = 'MB'
            1kb = 'KB'
            1 = 'B'
        }

        $Width = 5 + $Precision
        if ($Precision) { $Width += 1 }

        $Formatter = "{0,${Width}:n${Precision}} {1,2}"
    }

    process {
        foreach ($Entry in $SizeDict.GetEnumerator()) {
            if ($Length -ge $Entry.Name) {
                return $Formatter -f ($Length / $Entry.Name), $Entry.Value
            }
        }

        $Formatter -f 0, 'B'
    }
}

# With that helper function defined, we can create synthetic properties using Select-Object
$FilesWithSelect = dir C:\Windows -File | Select-Object *, @{N='PrettyLength'; E={$_ | Get-PrettyFileSize}}
$FilesWithSelect | Get-Member
$FilesWithSelect | Select-Object Name, Length, PrettyLength

# You can also use Add-Member (you could do a NoteProperty, but a ScriptProperty would probably be the easiest)
$FilesWithAddMember = dir C:\Windows -File | Add-Member -MemberType ScriptProperty -Name PrettyLength -Value { $this | Get-PrettyFileSize } -PassThru
$FilesWithAddMember | Get-Member
$FilesWithAddMember | Select-Object Name, Length, PrettyLength


# The only problem with doing that is that you have to do extra work to add that info. You have to collect the
# objects, then modify them. What if we just made all files automatically have that property?

Update-TypeData -TypeName System.IO.FileInfo -MemberType ScriptProperty -MemberName PrettyLength -Value { $this | Get-PrettyFileSize } -Force
dir C:\Windows | Get-Member
dir C:\Windows | select Name, Length, PrettyLength



# That's better, but it still requires the Get-PrettyFileSize command. There's really no reason for that. If we copy the function's definition and
# turn it into a ScriptBlock for a ScriptProperty, then we lose the ability to change the precision easily. What if we make two changes:
#   1. Make this work for folders, too
#   2. Add this as a ScriptMethod and make a ScriptProperty that calls the method
$GetPrettySizeSb = {
    param(
        [int] $Precision = 1
    )

    $Length = if ($this.PsIsContainer) {
        dir $this -Recurse -Force | Measure-Object -Sum Length | Select-Object -ExpandProperty Sum
    }
    else {
        $this.Length
    }

    $SizeDict = [ordered] @{
        1gb.ToString() = 'GB'
        1mb = 'MB'
        1kb = 'KB'
        1 = 'B'
    }

    $Width = 5 + $Precision
    if ($Precision) { $Width += 1 }

    $Formatter = "{0,${Width}:n${Precision}} {1,2}"

    foreach ($Entry in $SizeDict.GetEnumerator()) {
        if ($Length -ge $Entry.Name) {
            return $Formatter -f ($Length / $Entry.Name), $Entry.Value
        }
    }

    $Formatter -f 0, 'B'
}

Update-TypeData -TypeName System.IO.FileSystemInfo -MemberType ScriptMethod -MemberName GetPrettyLength -Value $GetPrettySizeSb -Force
Update-TypeData -TypeName System.IO.FileSystemInfo -MemberType ScriptProperty -MemberName PrettyLength -Value {$this.GetPrettyLength()} -Force

# One thing to be careful about here is that GetPrettyLength() can be expensive against large folder structures, and since PrettyLength calls it,
# you can accidentally cause the shell to hang. It won't do this by default, though:
$Downloads = Get-Item ~\Downloads
$Downloads

# Watch the slowdown when you access the property:
$Downloads | ft Name, Length, PrettyLength

# One way around that issue: make getting the script property an opt-in thing with a fake type name. First, let's get rid of the FileSystemInfo
# ETS info (NOTE: As a general rule, don't use Remove-TypeData -- just open a new PowerShell session)
Remove-TypeData -TypeName System.IO.FileSystemInfo

# We'll add the method back in:
Update-TypeData -TypeName System.IO.FileSystemInfo -MemberType ScriptMethod -MemberName GetPrettyLength -Value $GetPrettySizeSb -Force

# And we'll put it back for file objects (note the different type name from before)
Update-TypeData -TypeName System.IO.FileInfo -MemberType ScriptProperty -MemberName PrettyLength -Value {$this.GetPrettyLength()} -Force

# And finally, let's give a made up type name:
Update-TypeData -TypeName PrettyDirectoryInfo -MemberType ScriptProperty -MemberName PrettyLength -Value {$this.GetPrettyLength()} -Force

# Note that PrettyLength is missing
$Downloads | Get-Member Pretty*

# Let's add the bogus type:
$Downloads.pstypenames.Insert
$Downloads.pstypenames.Insert(0, 'PrettyDirectoryInfo')

# And now it's there:
$Downloads | Get-Member Pretty*


$Downloads | Format-Table Name, Length, PrettyLength
