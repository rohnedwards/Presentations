<#
The DatabaseReporter.ps1 isn't a self-contained module. Instead, it is an addon
to another module. It is designed to be dot sourced early on in a module's
definition. When dot-sourcing, you need to know the location of the .ps1 file
relative to the module files. In these examples, the file will just sit in the
same folder and use the $PSScriptRoot automatic variable to reference it.
#>

# Load the DatabaseReporter engine:
. $PSScriptRoot\DatabaseReporter.ps1

$DebugMode = $true  # This makes it so that -ReturnSqlQuery parameter is 
                    # available on all commands (which is great for demos
                    # and testing)

# Step 1: We need to figure out how to connect to the database (along with 
#         authentication). My test system has the AdventureWorks2012 DB
#         installed, and it will use Windows Authentication, so the
#         connection string doesn't have to worry about username/password
$DBConnectionString = 'server=(LocalDB)\v11.0;Database=AdventureWorks2012'
$DBConnectionObject = [System.Data.SqlClient.SqlConnection]::new($DBConnectionString)
Set-DbReaderConnection $DBConnectionObject

# Step 2: Determine the query you want to execute. In this case, we're
#         sticking to a very simple one:
#                         SELECT * FROM Production.Product
#
# Step 3: Build the command with the DbReaderCommand "keyword" (not really
#         a keyword, but it is meant to behave as one)
DbReaderCommand Get-AwProduct {
    [MagicDbInfo(FromClause = "Production.Product")]
    param()
}

<#
Since there were no parameters defined, this command's usefulness is very
limited. See the next example module for how to extend this.
#>