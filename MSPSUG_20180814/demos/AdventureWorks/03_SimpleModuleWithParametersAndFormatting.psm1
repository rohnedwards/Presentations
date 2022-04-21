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
        [int] $SafetyStockLevel,
        [MagicDbProp(ColumnName='p.SellStartDate')]
        [MagicDbFormatTableColumn()]
        [datetime] $SellStartDate,
        [MagicDbProp(ColumnName='p.Size')]
        $Size
    )
}

<#
Changes from previous version:
  * MagicDbInfo() has a PSTypeName property added. This is important (a
    future version of the engine won't require this for formatting, but it is
    currently required)
  * [MagicDbFormatTableColumn()] attribute was added before parameters that we
    wanted displayed in table format by default
  * ColumnName was filled in for all of the parameters (this is a best practice)
#>

<# 
No functional change, just a visual one. Now output is displayed in a table,
even though the same objects still exist. Try this:

Get-AwProduct -ProductColor White  # Notice table output

Get-AwProduct -ProductColor White | Format-List
#>
