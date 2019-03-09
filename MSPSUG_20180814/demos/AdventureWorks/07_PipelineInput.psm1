# Load the DatabaseReporter engine:
. $PSScriptRoot\DatabaseReporter.ps1

$DebugMode = $true  # This makes it so that -ReturnSqlQuery parameter is 
                    # available on all commands (which is great for demos
                    # and testing)

$DBConnectionString = 'server=(LocalDB)\v11.0;Database=AdventureWorks2012;MultipleActiveResultSets=True;'
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

DbReaderCommand Get-AwProductTransactionHistory {
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
  * DB Connection string got a new option added: MultipleActiveResultSets=True
    This is a SQL Server feature that allows a single open connection to run
    multiple commands. If we do pipelined input with a single connection, we
    need this. There are other ways to achieve pipelined input w/o this, though,
    and they will be documented later (hint: each command can have their own
    DbConnection object or string/types stored in their MagicDbInfo, and the
    module scoped DbReader will eventually support a string/type so a new
    connection can be created each time)
  * A new command was created: Get-AwProductTransactionHistory. This command's
    $ProductId parameter was configured to take pipeline input by property name,
    which means Get-AwProduct output can be sent straight to this command.
#>

<# 
Examples:

Get-AwProduct -ProductColor White | Get-AwProductTransactionHistory

Get-AwProduct -ProductColor White | Get-AwProductTransactionHistory -GroupBy ProductName

#>
