# Load the DatabaseReporter engine:
. $PSScriptRoot\DatabaseReporter.ps1

$DebugMode = $true  # This makes it so that -ReturnSqlQuery parameter is 
                    # available on all commands (which is great for demos
                    # and testing)

$DBConnectionString = 'server=(LocalDB)\v11.0;Database=AdventureWorks2012'
$DBConnectionObject = [System.Data.SqlClient.SqlConnection]::new($DBConnectionString)
Set-DbReaderConnection $DBConnectionObject

DbReaderCommand Get-AwProduct {
    [MagicDbInfo(
        FromClause = "
            Production.Product p
            LEFT JOIN Production.ProductSubcategory sc ON p.ProductSubcategoryID = sc.ProductSubcategoryID
            LEFT JOIN Production.ProductCategory c ON sc.ProductCategoryID = c.ProductCategoryID
            LEFT JOIN (
                SELECT 
                  tmpprod.ProductID,
                  SUM(tmppi.Quantity) AS TotalInventory
                FROM Production.Product tmpprod
                JOIN Production.ProductInventory tmppi ON tmppi.ProductID = tmpprod.ProductID
                GROUP BY tmpprod.ProductID
            ) quantity ON p.ProductID = quantity.ProductID
        ", 
        PSTypeName='AwProduct'
    )]
    param(
        [MagicDbProp(ColumnName='p.ProductID')]
        [int] $ProductID,
        [MagicDbProp(ColumnName='c.Name')]
        [MagicDbFormatTableColumn()]
        [string] $ProductCategory,
        [MagicDbProp(ColumnName='sc.Name')]
        [MagicDbFormatTableColumn()]
        [string] $ProductSubcategory,
        [MagicDbProp(ColumnName='p.Name')]
        [MagicDbFormatTableColumn()]
        [Alias('Name')]
        [string] $ProductName,
        [MagicDbProp(ColumnName='p.Color')]
        [MagicDbFormatTableColumn()]
        [Alias('Color')]
        [string] $ProductColor,
        [MagicDbProp(ColumnName='p.SafetyStockLevel')]
        [MagicDbComparisonSuffix()]
        [int] $SafetyStockLevel,
        [MagicDbProp(ColumnName='p.SellStartDate')]
        [MagicDbComparisonSuffix(GreaterThan='After', LessThan='Before')]
        [datetime] $SellStartDate,
        [MagicDbProp(ColumnName='p.Size')]
        $Size,
        [MagicDbProp(ColumnName='quantity.TotalInventory')]
        [MagicDbFormatTableColumn()]
        [MagicDbComparisonSuffix()]
        [int] $TotalInventory
    )
}

<#
Changes from previous version:
  * $Name changed to $ProductName, but an [Alias()] for 'Name' was added.
    Normal PS parameter attributes are valid :)
  * $ProductColor got an [Alias()] for 'Color'
  * FromClause got a temporary table added to compute the quantity
  * $TotalInventory added
#>

<# 
Examples:


Get-AwProduct -TotalInventoryLessThan 1

# This also shows $null
# NOTE: Not thrilled about the way this reads, but b/c of how query is
#       designed, this will create two separate conditions to test for
Get-AwProduct -TotalInventoryLessThan 1, $null

#>

<#
# Sanity check to make sure the quantities at least make sense:
$RawInventory = & (Get-Command Get-AwProduct).Module {
    $Connection = Get-DbReaderConnection
    InvokeReaderCommand -Connection $Connection -Query 'SELECT * FROM Production.ProductInventory'
}
$RawInventory | Measure-Object -Sum Quantity

Get-AwProductWithInventory -TotalInventory $null -Negate TotalInventory | Measure-Object -Sum TotalInventory
#>