<#
.SYNOPSIS
    Retrieves all attributes from a specified Active Directory class name.

.DESCRIPTION
    This script is a heavily modified version of a script originally found at 
    https://www.easy365manager.com/how-to-get-all-active-directory-user-object-attributes/
    
    It allows you to query Active Directory schema to list all attributes available for 
    a specified class name (like User, Group, Computer, etc.).

#>
function Get-ADAttributesFromClassName {
    param(
        [CmdletBinding()]
        [Parameter(Mandatory = $false)]
        [String]$ClassName
    )

    $schemaNC = (Get-ADRootDSE).SchemaNamingContext
    $schema = [System.DirectoryServices.ActiveDirectory.ActiveDirectorySchema]::GetCurrentSchema()

        
    $loop = $True
    [System.Collections.Generic.List[PSObject]]$classArray = @()
    [System.Collections.Generic.List[PSObject]]$attributesArray = @()
    
    if ($ClassName) {
        while ($loop) {
            $class = Get-ADObject -SearchBase $schemaNC -Filter { ldapDisplayName -eq $ClassName } -Properties AuxiliaryClass, SystemAuxiliaryClass, mayContain, mustContain, systemMayContain, systemMustContain, subClassOf, ldapDisplayName
        
            if ($class.ldapDisplayName -eq $class.subClassOf) {
                $loop = $False
            }
        
            $null = $classArray.Add($class)

            $ClassName = $class.subClassOf
        }
    
        # Loop through all the classes and get all auxiliary class attributes and direct attributes
        foreach ($class in $classArray) {

            # Get Auxiliary class attributes
            $auxiliaryClass = $class.AuxiliaryClass | ForEach-Object { 
                Get-ADObject -SearchBase $schemaNC -Filter { ldapDisplayName -eq $_ } -Properties mayContain, mustContain, systemMayContain, systemMustContain } | Select-Object @{Name = 'Attributes'; Expression = { $_.mayContain + $_.mustContain + $_.systemMaycontain + $_.systemMustContain } } | Select-Object -ExpandProperty Attributes

            # Get SystemAuxiliary class attributes
            if ($class.SystemAuxiliaryClass.Count -ge 1) {
                $SystemAuxiliaryClass = $class.SystemAuxiliaryClass | ForEach-Object {
                    Get-ADObject -ErrorAction SilentlyContinue -SearchBase $schemaNC -Filter { ldapDisplayName -like $_ } -Properties MayContain, SystemMayContain, systemMustContain } | Select-Object @{Name = 'Attributes'; Expression = { $_.maycontain + $_.systemmaycontain + $_.systemMustContain } } | Select-Object -ExpandProperty Attributes
            }

            # Create categorized lists of attributes
            [System.Collections.Generic.List[Object]]$directAttributes = @($class.mayContain + $class.mustContain + $class.systemMayContain + $class.systemMustContain)
            [System.Collections.Generic.List[Object]]$auxAttributes = @($auxiliaryClass)
            [System.Collections.Generic.List[Object]]$sysAuxAttributes = @($SystemAuxiliaryClass)

            # Process direct attributes
            foreach ($attribute in $directAttributes) {
                if ($attribute) {
                    $object = [PSCustomObject][ordered]@{
                        Attribute = $attribute
                        Class     = $class.ldapDisplayName
                        Type      = 'Direct'
                    }

                    $attributesArray.Add($object)
                }
            }

            # Process auxiliary attributes
            foreach ($attribute in $auxAttributes) {
                if ($attribute) {
                    $object = [PSCustomObject][ordered]@{
                        Attribute = $attribute
                        Class     = $class.ldapDisplayName
                        Type      = 'Auxiliary'
                    }

                    $attributesArray.Add($object)
                }
            }

            # Process system auxiliary attributes
            foreach ($attribute in $sysAuxAttributes) {
                if ($attribute) {
                    $object = [PSCustomObject][ordered]@{
                        Attribute = $attribute
                        Class     = $class.ldapDisplayName
                        Type      = 'SystemAuxiliary'
                    }

                    $attributesArray.Add($object)
                }
            }
        }
    }
    # If no ClassName provided, get all classes
    else {
        Write-Host -ForegroundColor Cyan 'No ClassName provided, retrieving all classes and their attributes...'
        $allClasses = (Get-ADObject -SearchBase $schemaNC -Filter { objectClass -eq 'classSchema' } -Properties ldapDisplayName).ldapDisplayName
        $i = 0
        foreach ($class in $allClasses) {
            Write-Host -ForegroundColor Green "Retrieving attributes for class: $class ($i of $($allClasses.Count))"
            $attributes = Get-ADAttributesFromClassName -ClassName $class
            
            $attributes | ForEach-Object {
                $object = [PSCustomObject][ordered]@{
                    Class     = $class
                    Attribute = $_.Attribute
                    Type      = $_.Type
                }

                $attributesArray.Add($object)
            }

            $i++
        }
    }

    return $attributesArray | Sort-Object Attribute
}