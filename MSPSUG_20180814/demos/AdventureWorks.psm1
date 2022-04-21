# Load the DatabaseReporter engine:
. $PSScriptRoot\AdventureWorks\DatabaseReporter.ps1

$DebugMode = $true  # This makes it so that -ReturnSqlQuery parameter is 
                    # available on all commands (which is great for demos
                    # and testing)

# Connect to Database:
$DBConnectionString = 'server=(LocalDB)\v11.0;Database=AdventureWorks2012'
$DBConnectionObject = [System.Data.SqlClient.SqlConnection]::new($DBConnectionString)
Set-DbReaderConnection $DBConnectionObject

DbReaderCommand Get-AwProduct {
    [MagicDbInfo(FromClause = 'FROM Production.Product p')]
    param(
        [MagicDbProp()]
        [int] $ProductID,
        [MagicDbProp()]
        [string] $Name,
        [MagicDbProp(ColumnName='p.Color')]
        [string] $ProductColor,
        [MagicDbProp()]
        [int] $SafetyStockLevel,
        [MagicDbProp()]
        [datetime] $SellStartDate,
        [MagicDbProp()]
        $Size,
        [MagicDbProp()]
        [int] $DaysToManufacture
    )
}