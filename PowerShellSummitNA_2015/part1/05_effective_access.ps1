$LimitedUserName = "LimitedUser"
$TestFolderPath = "$RootFolderPath\SomeExtraAces"

# I'm not aware of a native PowerShell way to get effective access. You can do this using the PAC module, though, with
# the Get-EffectiveAccess function:
Get-EffectiveAccess $TestFolderPath

# When no principal is passed, it defaults to the current user. More than one principal can be provided:
Get-EffectiveAccess $TestFolderPath -Principal Everyone, Users, Administrator, $LimitedUserName

# Groups aren't good principals for Get-EffectiveAccess. It will only show any access if there is an ACE specifically
# for that group in the DACL.

# More than one object can be provided:
Get-EffectiveAccess -InputObject (Get-Service bits), ("HKLM:\SOFTWARE") -Principal Administrator, $LimitedUserName


# The -ListAllRights option gives something that looks more like the 'Effective Access' tab in the GUI
Get-Service bits | Get-EffectiveAccess -ListAllRights -Principal $LimitedUserName


# Any object that the module can work with should work with this function
Get-WmiObject __SystemSecurity | Get-EffectiveAccess -Principal $LimitedUserName
Get-WmiObject __SystemSecurity | Get-EffectiveAccess -Principal $LimitedUserName -ListAllRights


# Shares take Share and NTFS permissions into account:
Get-EffectiveAccess -Principal administrator, limiteduser -Path \\dc\readonlyshare -ListAllRights
Get-EffectiveAccess -Principal administrator, limiteduser -Path \\dc\readonlyshare

# Version 3.1 should offer Central Access Policy support, so Centra Access Rules that limit access should
# be shown the way that share and object permissions are currently shown.