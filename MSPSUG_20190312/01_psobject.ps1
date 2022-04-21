
# Almost everything is wrapped in a PSObject (this is transparent to the user)
$File = Get-Item "C:\windows\regedit.exe"
$File.GetType().FullName        # System.IO.FileInfo
$File -is [System.IO.FileInfo]  # true

# So it's a FileInfo, but note that it's also a PSObject:
$File -is [psobject]

# But that doesn't show up in the type names:
$File.pstypenames

<# NOTE: pstypenames is a special property the PS engine attached to each object that
         shows the inheritance chain (by default). Extra types can be added to it, though,
         that wouldn't show up in the real inheritance chain.

         Real inheritance chain can be found like this:
             $Type = $File.GetType()
             do {
                 $Type.FullName
             } while ($Type = $Type.BaseType)
#>

# There are some informative semi-hidden properties attached to every PSObject:
#   * psobject   - A view of the PSObject wrapper's adapter
#   * psbase     - A raw view of the object (this is what you'd see if you were writing C# code and had an instance of this object)
#   * psadapted  - The adapted view of the object you see inside PS. This is what Get-Member will show you
#   * psextended - Just the members added by the extended type system ("fake" or PS-only members)

$File.psobject

$File.psbase
$File.psadapted
$File.psextended