# Load the DatabaseReporter engine:
. $PSScriptRoot\DatabaseReporter.ps1

$DebugMode = $true  # This makes it so that -ReturnSqlQuery parameter is 
                    # available on all commands (which is great for demos
                    # and testing)

$DBConnectionString = 'server=(LocalDB)\v11.0;Database=AdventureWorks2012'
$DBConnectionObject = [System.Data.SqlClient.SqlConnection]::new($DBConnectionString)
Set-DbReaderConnection $DBConnectionObject

DbReaderCommand Get-AwProduct {
    [MagicDbInfo(FromClause = "Production.Product p")]
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
        $DaysToManufacture
    )
}

<#
Changes from previous version:
  * FromClause added an alias for Product table
  * Parameters were added. Note this is just like parameter definition for a
    regular function, except for the extra [MagicDbProp()] attribute. This is
    used to opt-in (and wire-up) the parameter to the SQL query.

[MagicDbProp()] can be empty without any properties as long as the PS parameter
name matches the table column name, and the column isn't ambiguous (the DB 
system cares about that last part). Ideally, though, you'll always include the
'ColumnName' property like the $ProductColor above.
#>

<# 
Now the following commands are possible:

# Show white and grey products:
Get-AwProduct -ProductColor White, Grey

# Return a count of products by color:
Get-AwProduct -GroupBy ProductColor

# Return a count of products by color and size, ordered by count:
Get-AwProduct -GroupBy ProductColor, Size -OrderBy Count

# Return a count of products by color that aren't white or grey
Get-AwProduct -ProductColor Grey, White -GroupBy ProductColor -Negate ProductColor

# Return a count of products by color that don't have a color ($null), or that
# aren't white or grey (without using -Negate parameter)
Get-AwProduct -ProductColor $null, @{Value='grey', 'white'; Negate=$true} -GroupBy ProductColor

# Demo of changing the comparison operator
Get-AwProduct -SafetyStockLevel @{V=600; ComparisonOperator='>'} -GroupBy SafetyStockLevel, ProductColor

#>
