
# Load the DatabaseReporter engine:
. $PSScriptRoot\DatabaseReporter.devel.ps1

$DebugMode = $true  # This makes it so that -ReturnSqlQuery parameter is 
                    # available on all commands (which is great for demos
                    # and testing)

$DBFile = "$PSScriptRoot\Northwind.accdb"
$DBConnectionString = "Provider=Microsoft.ACE.OLEDB.12.0;Data Source='${DBFile}';"
$DBConnectionObject = [System.Data.OleDb.OleDbConnection]::new($DBConnectionString)
Set-DbReaderConnection $DBConnectionObject

DbReaderCommand Get-NwCustomer {
    [MagicDbInfo(FromClause = "Customers")]
    param(
    )
}