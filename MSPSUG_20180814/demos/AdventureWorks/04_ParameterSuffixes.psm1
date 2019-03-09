# Load the DatabaseReporter engine:
. $PSScriptRoot\DatabaseReporter.ps1

$DebugMode = $true  # This makes it so that -ReturnSqlQuery parameter is 
                    # available on all commands (which is great for demos
                    # and testing)

$DBConnectionString = 'server=(LocalDB)\v11.0;Database=AdventureWorks2012'
$DBConnectionObject = [System.Data.SqlClient.SqlConnection]::new($DBConnectionString)
Set-DbReaderConnection $DBConnectionObject

DbReaderCommand Get-AwProduct {
    [MagicDbInfo(FromClause = "Production.Product p", PSTypeName='AwProduct')]
    param(
        [MagicDbProp(ColumnName='p.ProductID')]
        [int] $ProductID,
        [MagicDbProp(ColumnName='p.Name')]
        [MagicDbFormatTableColumn()]
        [string] $Name,
        [MagicDbProp(ColumnName='p.Color')]
        [MagicDbFormatTableColumn()]
        [string] $ProductColor,
        [MagicDbProp(ColumnName='p.SafetyStockLevel')]
        [MagicDbComparisonSuffix()]
        [int] $SafetyStockLevel,
        [MagicDbProp(ColumnName='p.SellStartDate')]
        [MagicDbFormatTableColumn()]
        [MagicDbComparisonSuffix(GreaterThan='After', LessThan='Before')]
        [datetime] $SellStartDate,
        [MagicDbProp(ColumnName='p.Size')]
        $Size
    )
}

<#
Changes from previous version:
  * SafetyStockLevel and SellStartDate had the [MagicDbComparisonSuffix()]
    attribute added to them. This changes the command so that those parameters
    are actually split in two:
      - $SafetyStockLevel becomes -SafetyStockLevelGreaterThan and 
        -SafetyStockLevelLessThan (GreaterThan and LessThan suffixes are the
        defaults since the attribute had no properties)
      - $SellStartDate becomes -SellStartDateAfter and -SellStartDateBefore
        since the 'GreaterThan' and 'LessThan' properties were supplied with
        those suffixes.

    This changes the behavior of the SQL query to use > and < for those
    parameters.
#>

<# 
Examples:

Get-AwProduct -SafetyStockLevelGreaterThan 100 -SafetyStockLevelLessThan 1000

# These are pretty much the same (depending on when the command is run since
# one of the examples uses relative time)
Get-AwProduct -SellStartDateAfter 7/29/2004
Get-AwProduct -SellStartDateAfter 13.years.ago

#>
