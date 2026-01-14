<#
    .SYNOPSIS
    Retrieves possible inferior classes for an Active Directory schema class.

    .DESCRIPTION
    This script queries Active Directory schema to list all child classes that can be created
    under instances of a specified class. It uses the possibleInferiors attribute which is
    automatically calculated by Active Directory.

    .PARAMETER ClassName
    The ldapDisplayName of the class to query (e.g., 'user', 'organizationalUnit', 'container').

.EXAMPLE
    Get-ADSchemaClassPossibleChildren -ClassName 'user'

    Lists all classes that can be children of a user object.

.EXAMPLE
    Get-ADSchemaClassPossibleChildren -ClassName 'computer'

    Lists all classes that can be children of a computer object.
#>
function Get-ADSchemaClassPossibleChildren {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [String]$ClassName
    )

    Import-Module ActiveDirectory -ErrorAction Stop

    $schemaNC = (Get-ADRootDSE).schemaNamingContext
    $classObjectDn = "CN=$ClassName,$schemaNC"

    Get-ADObject -Identity $classObjectDn -Properties possibleInferiors |
        Select-Object -ExpandProperty possibleInferiors |
        Sort-Object
}
