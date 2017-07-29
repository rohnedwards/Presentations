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
  * FromClause now JOINs two new tables
  * param() block now has two new parameters (one column from each new table)
      -ProductCategory
      -ProductSubCategory
#>

<# 
Examples:

Get-AwProduct -ReturnSqlQuery

Get-AwProduct -GroupBy ProductCategory, ProductSubcategory -OrderBy ProductCategory, ProductSubcategory


# Show uncategorized products:
Get-AwProduct -ProductSubcategory $null

#>
