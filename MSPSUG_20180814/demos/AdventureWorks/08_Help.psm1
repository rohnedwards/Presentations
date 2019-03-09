# Load the DatabaseReporter engine:
. $PSScriptRoot\DatabaseReporter.devel.ps1

$DebugMode = $true  # This makes it so that -ReturnSqlQuery parameter is 
                    # available on all commands (which is great for demos
                    # and testing)

$DBConnectionString = 'server=(LocalDB)\v11.0;Database=AdventureWorks2012;MultipleActiveResultSets=True;'
$DBConnectionObject = [System.Data.SqlClient.SqlConnection]::new($DBConnectionString)
Set-DbReaderConnection $DBConnectionObject

DbReaderCommand Get-AwProduct {
<#
.SYNOPSIS
Gets products from the AdventureWorks2012 database

.DESCRIPTION
The Get-AwProduct command is a proof of concept created for a SQL Saturday
presentation given in Baton Rouge on July 29, 2017.

It is a demonstration of how you can build incredibly useful database reader
commands using nothing but PowerShell function metadata.

If the AdventureWorks database has been installed on your system, and if the
connection string defined in the module describes how to successfully connect
to it, then the command should return live results from the database.

Output from this command can be provided as input to the 
Get-AwProductTransactionHistory command.

.EXAMPLE
Get-AwProduct -TotalInventoryLessThan 1, $null

This command should return any products that have zero inventory left at the
locations that house the product (0), or that have zero inventory because there
are no locations that house the product ($null).

NOTE: This is an assumption based on viewing the schema of the AW DB, and it
may be incorrect.

.EXAMPLE
Get-AwProduct -GroupBy ProductCategory, ProductSubcategory -OrderBy ProductCategory, ProductSubcategory!

This returns a count of products grouped by category and subcategory. The
results are ordered by the ProductCategory in ascending alphabetical order
(which is the default order), and the ProductSubcategory in descending 
alphabetical order, which is denoted by the exclamation mark at the end of the
property name.

.EXAMPLE
Get-AwProduct -ProductSubcategory $null

This will return any products that do not have a subcategory assigned.

.EXAMPLE
Get-AwProduct -SellStartDateAfter 13.years.ago

This should return any products that started being sold within the last thirteen
years. If you're not seeing any output, you may need to change the relative
date (or provide a string like '7/1/2003')

.EXAMPLE
Get-AwProduct -ProductColor $null, @{Value='grey', 'white'; Negate=$true} -GroupBy ProductColor

This should return a count of products by color that don't have a color ($null), 
or that aren't white or grey (without using -Negate parameter).

It is a demonstration of how to pass advanced parameter options.

#>
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
    [MagicDbFormatTableInfo(GroupByPropertyName='ProductColor')]
    [MagicDbFormatTableInfo(View='AltView', GroupByLabel='ProductColor and Size', GroupByScriptBlock={'{0}; {1}' -f $_.ProductColor, $_.Size})]
    param(
        [MagicDbProp(ColumnName='p.ProductID')]
        # The primary key for the product in the database
        [int] $ProductID,
        [MagicDbProp(ColumnName='c.Name')]
        [MagicDbFormatTableColumn()]
        # The product's category
        [string] $ProductCategory,
        [MagicDbProp(ColumnName='sc.Name')]
        [MagicDbFormatTableColumn()]
        # The product's subcategory
        [string] $ProductSubcategory,
        [MagicDbProp(ColumnName='p.Name')]
        [MagicDbFormatTableColumn()]
        [MagicDbFormatTableColumn(View='AltView')]
        [Alias('Name')]
        # The name of the product
        [string] $ProductName,
        [MagicDbProp(ColumnName='p.Color')]
        [MagicDbFormatTableColumn(View='AltView')]
        [Alias('Color')]
        # The product's color
        [string] $ProductColor,
        [MagicDbProp(ColumnName='p.SafetyStockLevel')]
        [MagicDbComparisonSuffix()]
        # The safety stock level
        [int] $SafetyStockLevel,
        [MagicDbProp(ColumnName='p.SellStartDate')]
        [MagicDbComparisonSuffix(GreaterThan='After', LessThan='Before')]
        # The date the product started being sold
        [datetime] $SellStartDate,
        [MagicDbProp(ColumnName='p.Size')]
        # The product's size
        $Size,
        [MagicDbProp(ColumnName='quantity.TotalInventory')]
        [MagicDbFormatTableColumn()]
        [MagicDbComparisonSuffix()]
        # The product's total inventory, determined by adding the amount of product
        # inventory at all locations that carry it.
        [int] $TotalInventory,
        [string[]] $OrderBy = @('ProductColor', 'Name')
    )
}

DbReaderCommand Get-AwProductTransactionHistory {
<#
.SYNOPSIS
Gets transaction history for products in the AdventureWorks2012 database.

.EXAMPLE
Get-AwProduct -ProductColor White | Get-AwProductTransactionHistory

There are four products that are white, and two of those have transaction
history. This command would show the transaction history for those. You
could run this command to confirm the products that had transaction history
in the database:

PS> Get-AwProduct -ProductColor White | Get-AwProductTransactionHistory -GroupBy ProductName

#>
    [MagicDbInfo(
        FromClause = '
            Production.TransactionHistory th 
            LEFT JOIN Production.Product p ON p.ProductID = th.ProductID
        ',
        PSTypeName = 'AwProductTransactionHistory')]
    param(
        [MagicDbProp(ColumnName='th.TransactionId')]
        [int] $TransactionId,
        [MagicDbProp(ColumnName='th.ProductId')]
        [Parameter(ValueFromPipelineByPropertyName)]
        [int] $ProductId,
        [MagicDbProp(ColumnName='p.Name')]
        [MagicDbFormatTableColumn()]
        [string] $ProductName,
        [MagicDbProp(ColumnName='th.ReferenceOrderId')]
        [int] $ReferenceOrderId,
        [MagicDbProp(ColumnName='th.TransactionDate')]
        [MagicDbFormatTableColumn()]
        [datetime] $TransactionDate,
        [MagicDbProp(ColumnName='th.TransactionType')]
        [MagicDbFormatTableColumn()]
        [string] $TransactionType,
        [MagicDbProp(ColumnName='th.Quantity')]
        [MagicDbFormatTableColumn()]
        [int] $Quantity,
        [MagicDbProp(ColumnName='th.ActualCost')]
        [MagicDbFormatTableColumn()]
        [decimal] $ActualCost
    )
}

<#
Changes from previous version:
  * Some documentation was added--mostly to the Get-AwProduct
#>

<# 
Examples:

help Get-AwProduct -ShowWindow
#>
