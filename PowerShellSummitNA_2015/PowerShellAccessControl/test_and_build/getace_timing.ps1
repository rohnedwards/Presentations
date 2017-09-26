<# With AppliesTo test happening in GetRules() before AdaptedCommonAce was created (and no special FilterRules() method):

0..99 | % { measure-command { Get-AccessControlEntry C:\Windows -AppliesTo Object } } | Measure-Object -Average -Minimum -Maximum totalmilliseconds


Count    : 100
Average  : 4.365134
Sum      : 
Maximum  : 12.6141
Minimum  : 1.8126
Property : TotalMilliseconds

0..99 | % { measure-command { Get-AccessControlEntry C:\Windows } } | Measure-Object -Average -Minimum -Maximum totalmilliseconds


Count    : 100
Average  : 5.457092
Sum      : 
Maximum  : 32.8385
Minimum  : 2.8443
Property : TotalMilliseconds



#>

<# After FilterRules() method was added to GetRules()

0..99 | % { measure-command { Get-AccessControlEntry C:\Windows -AppliesTo Object } } | Measure-Object -Average -Minimum -Maximum totalmilliseconds

Count    : 100
Average  : 4.922414
Sum      : 
Maximum  : 17.9017
Minimum  : 3.0527
Property : TotalMilliseconds

0..99 | % { measure-command { Get-AccessControlEntry C:\Windows } } | Measure-Object -Average -Minimum -Maximum totalmilliseconds


Count    : 100
Average  : 4.356996
Sum      : 
Maximum  : 10.1231
Minimum  : 2.88
Property : TotalMilliseconds

#>