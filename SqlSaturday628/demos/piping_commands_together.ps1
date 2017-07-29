$Module = New-Module -Name SimpleTest {

    # Load the DatabaseReporter engine:
    . $pwd\DatabaseReporter.ps1

    $DebugMode = $true  # This makes it so that -ReturnSqlQuery parameter is available on all commands

    Set-DbReaderConnection ([System.Data.SqlClient.SqlConnection]::new('server=(LocalDB)\v11.0;Database=AdventureWorks2012; MultipleActiveResultSets=True;'))

    DbReaderCommand Get-AwEmployee {
        [MagicDbInfo(
            FromClause = '
                HumanResources.Employee
                JOIN Person.Person ON Person.BusinessEntityID = Employee.BusinessEntityID    
            ',
            PSTypeName = 'AwEmployee'
        )]
        param(
            [MagicDbProp(ColumnName='Employee.BusinessEntityID')]
            [System.Int32] $BusinessEntityID,
            [MagicDbProp(ColumnName='Employee.NationalIDNumber')]
            [System.String] $NationalIDNumber,
            [MagicDbFormatTableColumn()]
            [MagicDbProp(ColumnName='Person.PersonType')]
            [char] $PersonType,
            [MagicDbProp(ColumnName='Person.Title')]
            [string] $Title,
            [MagicDbFormatTableColumn()]
            [MagicDbProp(ColumnName='Person.FirstName')]
            [string] $FirstName,
            [MagicDbFormatTableColumn()]
            [MagicDbProp(ColumnName='Person.LastName')]
            [string] $LastName,
            [MagicDbProp(ColumnName='Person.Suffix')]
            [string] $Suffix,
            [MagicDbFormatTableColumn()]
            [MagicDbProp(ColumnName='Employee.LoginID')]
            [System.String] $LoginID,
            [MagicDbProp(ColumnName='Employee.OrganizationLevel')]
            [System.Int16] $OrganizationLevel,
            [MagicDbProp(ColumnName='Employee.JobTitle')]
            [MagicDbFormatTableColumn()]
            [System.String] $JobTitle,
            [MagicDbProp(ColumnName='Employee.BirthDate')]
            [System.DateTime] $BirthDate,
            [MagicDbProp(ColumnName='Employee.MaritalStatus')]
            [System.String] $MaritalStatus,
            [MagicDbProp(ColumnName='Employee.Gender')]
            [System.String] $Gender,
            [MagicDbProp(ColumnName='Employee.HireDate')]
            [System.DateTime] $HireDate,
            [MagicDbProp(ColumnName='Employee.SalariedFlag')]
            [switch] $IsSalaried,
            [MagicDbProp(ColumnName='Employee.VacationHours')]
            [System.Int16] $VacationHours,
            [MagicDbProp(ColumnName='Employee.SickLeaveHours')]
            [System.Int16] $SickLeaveHours,
            [MagicDbProp(ColumnName='Employee.CurrentFlag')]
            [switch] $IsCurrent
        )
    }

    DbReaderCommand Get-AwEmployeeDepartmentHistory {
        [MagicDbInfo(
            FromClause = '
                HumanResources.EmployeeDepartmentHistory edh
                JOIN HumanResources.Employee e ON e.BusinessEntityID = edh.BusinessEntityID
                JOIN Person.Person p ON p.BusinessEntityID = edh.BusinessEntityID
                LEFT JOIN HumanResources.Shift s ON s.ShiftID = edh.ShiftID
                LEFT JOIN HumanResources.Department d ON d.DepartmentID = edh.DepartmentID
                ',
            PSTypeName = 'AwEmployeeDepartmentHistory'
        )]
        param(
            [MagicDbProp(ColumnName='edh.BusinessEntityID')]
            [Parameter(ValueFromPipelineByPropertyName)]
            [System.Int32] $BusinessEntityID,
            [MagicDbFormatTableColumn()]
            [MagicDbProp(ColumnName='p.FirstName')]
            [string] $FirstName,
            [MagicDbFormatTableColumn()]
            [MagicDbProp(ColumnName='p.LastName')]
            [string] $LastName,
            [MagicDbProp(ColumnName='e.LoginID')]
            [System.String] $LoginID,
            [MagicDbFormatTableColumn()]
            [MagicDbProp(ColumnName='edh.DepartmentID')]
            [System.Int16] $DepartmentID,
            [MagicDbFormatTableColumn()]
            [MagicDbProp(ColumnName='d.Name')]
            [string] $DepartmentName,
            [MagicDbProp(ColumnName='edh.ShiftID')]
            [System.Byte] $ShiftID,
            [MagicDbFormatTableColumn()]
            [MagicDbProp(ColumnName='s.Name')]
            [string] $ShiftName,
            [MagicDbProp(ColumnName='s.StartTime')]
            [datetime] $ShiftStart,
            [MagicDbProp(ColumnName='s.EndTime')]
            [datetime] $ShiftEnd,
            [MagicDbFormatTableColumn()]
            [MagicDbProp(ColumnName='edh.StartDate')]
            [System.DateTime] $StartDate,
            [MagicDbFormatTableColumn()]
            [MagicDbProp(ColumnName='edh.EndDate')]
            [System.DateTime] $EndDate
        )
    }
}
