# Validate parameters
    if ($ClassName -and $AttributeName) {
        Write-Error "Cannot specify both ClassName and AttributeName parameters. Use one or the other."
        return
    }<#
.SYNOPSIS
    Retrieves all attributes from a specified Active Directory class name using native .NET classes.

.DESCRIPTION
    This script queries Active Directory schema to list all attributes available for 
    a specified class name (like User, Group, Computer, etc.) without requiring the 
    ActiveDirectory PowerShell module. It uses DirectoryEntry and DirectorySearcher
    .NET classes for direct LDAP queries.

.PARAMETER ClassName
    The LDAP display name of the class to query (e.g., 'user', 'group', 'computer')

.PARAMETER AttributeName
    The LDAP display name of the attribute to search for across all classes (e.g., 'mail', 'sAMAccountName').
    Supports wildcards: use * for multiple characters, ? for single character (e.g., 'mail*', 'sam*', '*Name')

.PARAMETER Server
    The domain controller to query. If not specified, uses the current domain.

.EXAMPLE
    Get-ADAttributeInfov2 -ClassName "user"
    
.EXAMPLE
    Get-ADAttributeInfov2 -ClassName "group" -Server "dc01.domain.com"

.EXAMPLE
    Get-ADAttributeInfov2 -AttributeName "mail"
    
.EXAMPLE
    Get-ADAttributeInfov2 -AttributeName "sAMAccountName" -Server "dc01.domain.com"

.EXAMPLE
    Get-ADAttributeInfov2 -AttributeName "mail*"
    
.EXAMPLE  
    Get-ADAttributeInfov2 -AttributeName "*Name"

#>
function Get-AttributeSourceType {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [String]$ClassName,
        
        [Parameter(Mandatory = $true)]
        [String]$AttributeName,
        
        [Parameter(Mandatory = $true)]
        [System.DirectoryServices.DirectoryEntry]$SchemaEntry,
        
        [Parameter(Mandatory = $true)]
        [String]$Required
    )
    
    try {
        # Get the class definition
        $classSearcher = New-Object DirectoryServices.DirectorySearcher
        $classSearcher.SearchRoot = $SchemaEntry
        $classSearcher.Filter = "(&(objectClass=classSchema)(ldapDisplayName=$ClassName))"
        $classSearcher.PropertiesToLoad.AddRange(@(
            'mayContain', 'mustContain', 'systemMayContain', 'systemMustContain',
            'auxiliaryClass', 'systemAuxiliaryClass'
        ))
        
        $classResult = $classSearcher.FindOne()
        if (-not $classResult) {
            $classSearcher.Dispose()
            return 'Unknown'
        }
        
        # Check if it's directly defined on this class
        $directAttributes = @()
        if ($Required -eq 'Mandatory') {
            $directAttributes += if ($classResult.Properties['mustcontain']) { $classResult.Properties['mustcontain'] } else { @() }
            $directAttributes += if ($classResult.Properties['systemmustcontain']) { $classResult.Properties['systemmustcontain'] } else { @() }
        } else {
            $directAttributes += if ($classResult.Properties['maycontain']) { $classResult.Properties['maycontain'] } else { @() }
            $directAttributes += if ($classResult.Properties['systemmaycontain']) { $classResult.Properties['systemmaycontain'] } else { @() }
        }
        
        if ($directAttributes -contains $AttributeName) {
            $classSearcher.Dispose()
            return 'Direct'
        }
        
        # Check auxiliary classes
        $auxiliaryClasses = if ($classResult.Properties['auxiliaryclass']) { $classResult.Properties['auxiliaryclass'] } else { @() }
        foreach ($auxClass in $auxiliaryClasses) {
            $auxSearcher = New-Object DirectoryServices.DirectorySearcher
            $auxSearcher.SearchRoot = $SchemaEntry
            $auxSearcher.Filter = "(&(objectClass=classSchema)(ldapDisplayName=$auxClass))"
            $auxSearcher.PropertiesToLoad.AddRange(@('mayContain', 'mustContain', 'systemMayContain', 'systemMustContain'))
            
            $auxResult = $auxSearcher.FindOne()
            if ($auxResult) {
                $auxAttributes = @()
                if ($Required -eq 'Mandatory') {
                    $auxAttributes += if ($auxResult.Properties['mustcontain']) { $auxResult.Properties['mustcontain'] } else { @() }
                    $auxAttributes += if ($auxResult.Properties['systemmustcontain']) { $auxResult.Properties['systemmustcontain'] } else { @() }
                } else {
                    $auxAttributes += if ($auxResult.Properties['maycontain']) { $auxResult.Properties['maycontain'] } else { @() }
                    $auxAttributes += if ($auxResult.Properties['systemmaycontain']) { $auxResult.Properties['systemmaycontain'] } else { @() }
                }
                
                if ($auxAttributes -contains $AttributeName) {
                    $auxSearcher.Dispose()
                    $classSearcher.Dispose()
                    return 'Auxiliary'
                }
            }
            $auxSearcher.Dispose()
        }
        
        # Check system auxiliary classes
        $systemAuxiliaryClasses = if ($classResult.Properties['systemauxiliaryclass']) { $classResult.Properties['systemauxiliaryclass'] } else { @() }
        foreach ($sysAuxClass in $systemAuxiliaryClasses) {
            $sysAuxSearcher = New-Object DirectoryServices.DirectorySearcher
            $sysAuxSearcher.SearchRoot = $SchemaEntry
            $sysAuxSearcher.Filter = "(&(objectClass=classSchema)(ldapDisplayName=$sysAuxClass))"
            $sysAuxSearcher.PropertiesToLoad.AddRange(@('mayContain', 'systemMayContain', 'systemMustContain'))
            
            $sysAuxResult = $sysAuxSearcher.FindOne()
            if ($sysAuxResult) {
                $sysAuxAttributes = @()
                if ($Required -eq 'Mandatory') {
                    $sysAuxAttributes += if ($sysAuxResult.Properties['systemmustcontain']) { $sysAuxResult.Properties['systemmustcontain'] } else { @() }
                } else {
                    $sysAuxAttributes += if ($sysAuxResult.Properties['maycontain']) { $sysAuxResult.Properties['maycontain'] } else { @() }
                    $sysAuxAttributes += if ($sysAuxResult.Properties['systemmaycontain']) { $sysAuxResult.Properties['systemmaycontain'] } else { @() }
                }
                
                if ($sysAuxAttributes -contains $AttributeName) {
                    $sysAuxSearcher.Dispose()
                    $classSearcher.Dispose()
                    return 'SystemAuxiliary'
                }
            }
            $sysAuxSearcher.Dispose()
        }
        
        $classSearcher.Dispose()
        
        # If not found directly or in auxiliary classes, it must be inherited
        return 'Inherited'
        
    } catch {
        Write-Warning "Error determining source type for attribute '$AttributeName' in class '$ClassName': $($_.Exception.Message)"
        return 'Unknown'
    }
}

function Get-ADAttributeInfov2 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [String]$ClassName,
        
        [Parameter(Mandatory = $false)]
        [String]$AttributeName,
        
        [Parameter(Mandatory = $false)]
        [String]$Server
    )

    try {
        # Validate parameters
        if ($ClassName -and $AttributeName) {
            Write-Error "Cannot specify both ClassName and AttributeName parameters. Use one or the other."
            return
        }

        # Get the root DSE to find schema naming context
        if ($Server) {
            $rootDSE = New-Object DirectoryServices.DirectoryEntry("LDAP://$Server/RootDSE")
        } else {
            $rootDSE = New-Object DirectoryServices.DirectoryEntry("LDAP://RootDSE")
        }
        
        $schemaNamingContext = $rootDSE.Properties["schemaNamingContext"][0]
        $rootDSE.Dispose()

        # Create connection to schema partition
        if ($Server) {
            $schemaEntry = New-Object DirectoryServices.DirectoryEntry("LDAP://$Server/$schemaNamingContext")
        } else {
            $schemaEntry = New-Object DirectoryServices.DirectoryEntry("LDAP://$schemaNamingContext")
        }

        $loop = $true
        [System.Collections.Generic.List[PSObject]]$classArray = @()
        [System.Collections.Generic.List[PSObject]]$attributesArray = @()

        if ($AttributeName) {
            # Search for all classes that contain the specified attribute using .NET schema
            Write-Host -ForegroundColor Cyan "Searching for attribute '$AttributeName' across all classes..."
            
            try {
                $schema = [System.DirectoryServices.ActiveDirectory.ActiveDirectorySchema]::GetCurrentSchema()
                $allClasses = $schema.FindAllClasses()
                
                Write-Host -ForegroundColor Yellow "Processing $($allClasses.Count) classes with resolved inheritance..."
                
                foreach ($class in $allClasses) {
                    Write-Verbose "Checking class: $($class.Name)"
                    
                    # Check if attribute is in mandatory properties
                    if ($class.MandatoryProperties.Name -contains $AttributeName) {
                        # Determine the real source of this attribute
                        $sourceType = Get-AttributeSourceType -ClassName $class.Name -AttributeName $AttributeName -SchemaEntry $schemaEntry -Required 'Mandatory'
                        
                        $attributesArray.Add([PSCustomObject][ordered]@{
                            Attribute = $AttributeName
                            Class     = $class.Name
                            Type      = $sourceType
                            Required  = 'Mandatory'
                        })
                    }
                    # Check if attribute is in optional properties
                    elseif ($class.OptionalProperties.Name -contains $AttributeName) {
                        # Determine the real source of this attribute
                        $sourceType = Get-AttributeSourceType -ClassName $class.Name -AttributeName $AttributeName -SchemaEntry $schemaEntry -Required 'Optional'
                        
                        $attributesArray.Add([PSCustomObject][ordered]@{
                            Attribute = $AttributeName
                            Class     = $class.Name
                            Type      = $sourceType
                            Required  = 'Optional'
                        })
                    }
                }
                
                Write-Host -ForegroundColor Green "Found $($attributesArray.Count) matches for attribute '$AttributeName'"
            }
            catch {
                Write-Error "Error accessing schema via ActiveDirectorySchema: $($_.Exception.Message)"
                Write-Warning "Falling back to direct LDAP queries..."
                
                # Fallback to the previous method if ActiveDirectorySchema fails
                # Get all class schema objects that might contain this attribute
                $classSearcher = New-Object DirectoryServices.DirectorySearcher
                $classSearcher.SearchRoot = $schemaEntry
                $classSearcher.Filter = "(&(objectClass=classSchema)(|(mayContain=$AttributeName)(mustContain=$AttributeName)(systemMayContain=$AttributeName)(systemMustContain=$AttributeName)))"
                $classSearcher.PropertiesToLoad.AddRange(@(
                    'ldapDisplayName', 'mayContain', 'mustContain', 'systemMayContain', 'systemMustContain'
                ))
                $classSearcher.PageSize = 1000
                
                $directClassResults = $classSearcher.FindAll()
                
                foreach ($result in $directClassResults) {
                    $className = $result.Properties['ldapdisplayname'][0]
                    $required = 'Optional'
                    
                    if ($result.Properties['mustcontain'] -contains $AttributeName -or 
                        $result.Properties['systemmustcontain'] -contains $AttributeName) {
                        $required = 'Mandatory'
                    }
                    
                    $attributesArray.Add([PSCustomObject][ordered]@{
                        Attribute = $AttributeName
                        Class     = $className
                        Type      = 'Direct'
                        Required  = $required
                    })
                }
                
                $classSearcher.Dispose()
                $directClassResults.Dispose()
            }
        }
        elseif ($ClassName) {
            while ($loop) {
                # Search for the class schema object
                $searcher = New-Object DirectoryServices.DirectorySearcher
                $searcher.SearchRoot = $schemaEntry
                $searcher.Filter = "(&(objectClass=classSchema)(ldapDisplayName=$ClassName))"
                $searcher.PropertiesToLoad.AddRange(@(
                    'ldapDisplayName', 'subClassOf', 'auxiliaryClass', 'systemAuxiliaryClass',
                    'mayContain', 'mustContain', 'systemMayContain', 'systemMustContain'
                ))

                $result = $searcher.FindOne()
                if (-not $result) {
                    Write-Warning "Class '$ClassName' not found in schema"
                    break
                }

                # Create class object with properties
                $classObj = [PSCustomObject]@{
                    ldapDisplayName = if ($result.Properties['ldapdisplayname']) { $result.Properties['ldapdisplayname'][0] } else { $null }
                    subClassOf = if ($result.Properties['subclassof']) { $result.Properties['subclassof'][0] } else { $null }
                    auxiliaryClass = if ($result.Properties['auxiliaryclass']) { $result.Properties['auxiliaryclass'] } else { @() }
                    systemAuxiliaryClass = if ($result.Properties['systemauxiliaryclass']) { $result.Properties['systemauxiliaryclass'] } else { @() }
                    mayContain = if ($result.Properties['maycontain']) { $result.Properties['maycontain'] } else { @() }
                    mustContain = if ($result.Properties['mustcontain']) { $result.Properties['mustcontain'] } else { @() }
                    systemMayContain = if ($result.Properties['systemmaycontain']) { $result.Properties['systemmaycontain'] } else { @() }
                    systemMustContain = if ($result.Properties['systemmustcontain']) { $result.Properties['systemmustcontain'] } else { @() }
                }

                if ($classObj.ldapDisplayName -eq $classObj.subClassOf) {
                    $loop = $false
                }

                $classArray.Add($classObj)
                $ClassName = $classObj.subClassOf
                
                $searcher.Dispose()
            }

            # Process each class to get attributes
            foreach ($class in $classArray) {
                Write-Verbose "Processing class: $($class.ldapDisplayName)"

                # Get auxiliary class attributes with requirement info
                $auxiliaryMandatoryAttributes = @()
                $auxiliaryOptionalAttributes = @()
                foreach ($auxClass in $class.auxiliaryClass) {
                    if ($auxClass) {
                        $auxSearcher = New-Object DirectoryServices.DirectorySearcher
                        $auxSearcher.SearchRoot = $schemaEntry
                        $auxSearcher.Filter = "(&(objectClass=classSchema)(ldapDisplayName=$auxClass))"
                        $auxSearcher.PropertiesToLoad.AddRange(@('mayContain', 'mustContain', 'systemMayContain', 'systemMustContain'))
                        
                        $auxResult = $auxSearcher.FindOne()
                        if ($auxResult) {
                            # Mandatory auxiliary attributes
                            $auxiliaryMandatoryAttributes += if ($auxResult.Properties['mustcontain']) { $auxResult.Properties['mustcontain'] } else { @() }
                            $auxiliaryMandatoryAttributes += if ($auxResult.Properties['systemmustcontain']) { $auxResult.Properties['systemmustcontain'] } else { @() }
                            
                            # Optional auxiliary attributes
                            $auxiliaryOptionalAttributes += if ($auxResult.Properties['maycontain']) { $auxResult.Properties['maycontain'] } else { @() }
                            $auxiliaryOptionalAttributes += if ($auxResult.Properties['systemmaycontain']) { $auxResult.Properties['systemmaycontain'] } else { @() }
                        }
                        $auxSearcher.Dispose()
                    }
                }

                # Get system auxiliary class attributes with requirement info
                $sysAuxiliaryMandatoryAttributes = @()
                $sysAuxiliaryOptionalAttributes = @()
                foreach ($sysAuxClass in $class.systemAuxiliaryClass) {
                    if ($sysAuxClass) {
                        $sysAuxSearcher = New-Object DirectoryServices.DirectorySearcher
                        $sysAuxSearcher.SearchRoot = $schemaEntry
                        $sysAuxSearcher.Filter = "(&(objectClass=classSchema)(ldapDisplayName=$sysAuxClass))"
                        $sysAuxSearcher.PropertiesToLoad.AddRange(@('mayContain', 'systemMayContain', 'systemMustContain'))
                        
                        $sysAuxResult = $sysAuxSearcher.FindOne()
                        if ($sysAuxResult) {
                            # Mandatory system auxiliary attributes
                            $sysAuxiliaryMandatoryAttributes += if ($sysAuxResult.Properties['systemmustcontain']) { $sysAuxResult.Properties['systemmustcontain'] } else { @() }
                            
                            # Optional system auxiliary attributes
                            $sysAuxiliaryOptionalAttributes += if ($sysAuxResult.Properties['maycontain']) { $sysAuxResult.Properties['maycontain'] } else { @() }
                            $sysAuxiliaryOptionalAttributes += if ($sysAuxResult.Properties['systemmaycontain']) { $sysAuxResult.Properties['systemmaycontain'] } else { @() }
                        }
                        $sysAuxSearcher.Dispose()
                    }
                }

                # Process direct attributes - Mandatory
                foreach ($attribute in $class.mustContain) {
                    if ($attribute -and $attribute -ne "") {
                        $attributesArray.Add([PSCustomObject][ordered]@{
                            Attribute = $attribute
                            Class     = $class.ldapDisplayName
                            Type      = 'Direct'
                            Required  = 'Mandatory'
                        })
                    }
                }

                foreach ($attribute in $class.systemMustContain) {
                    if ($attribute -and $attribute -ne "") {
                        $attributesArray.Add([PSCustomObject][ordered]@{
                            Attribute = $attribute
                            Class     = $class.ldapDisplayName
                            Type      = 'Direct'
                            Required  = 'Mandatory'
                        })
                    }
                }

                # Process direct attributes - Optional
                foreach ($attribute in $class.mayContain) {
                    if ($attribute -and $attribute -ne "") {
                        $attributesArray.Add([PSCustomObject][ordered]@{
                            Attribute = $attribute
                            Class     = $class.ldapDisplayName
                            Type      = 'Direct'
                            Required  = 'Optional'
                        })
                    }
                }

                foreach ($attribute in $class.systemMayContain) {
                    if ($attribute -and $attribute -ne "") {
                        $attributesArray.Add([PSCustomObject][ordered]@{
                            Attribute = $attribute
                            Class     = $class.ldapDisplayName
                            Type      = 'Direct'
                            Required  = 'Optional'
                        })
                    }
                }

                # Process auxiliary attributes - Mandatory
                foreach ($attribute in $auxiliaryMandatoryAttributes) {
                    if ($attribute -and $attribute -ne "") {
                        $attributesArray.Add([PSCustomObject][ordered]@{
                            Attribute = $attribute
                            Class     = $class.ldapDisplayName
                            Type      = 'Auxiliary'
                            Required  = 'Mandatory'
                        })
                    }
                }

                # Process auxiliary attributes - Optional
                foreach ($attribute in $auxiliaryOptionalAttributes) {
                    if ($attribute -and $attribute -ne "") {
                        $attributesArray.Add([PSCustomObject][ordered]@{
                            Attribute = $attribute
                            Class     = $class.ldapDisplayName
                            Type      = 'Auxiliary'
                            Required  = 'Optional'
                        })
                    }
                }

                # Process system auxiliary attributes - Mandatory
                foreach ($attribute in $sysAuxiliaryMandatoryAttributes) {
                    if ($attribute -and $attribute -ne "") {
                        $attributesArray.Add([PSCustomObject][ordered]@{
                            Attribute = $attribute
                            Class     = $class.ldapDisplayName
                            Type      = 'SystemAuxiliary'
                            Required  = 'Mandatory'
                        })
                    }
                }

                # Process system auxiliary attributes - Optional
                foreach ($attribute in $sysAuxiliaryOptionalAttributes) {
                    if ($attribute -and $attribute -ne "") {
                        $attributesArray.Add([PSCustomObject][ordered]@{
                            Attribute = $attribute
                            Class     = $class.ldapDisplayName
                            Type      = 'SystemAuxiliary'
                            Required  = 'Optional'
                        })
                    }
                }
            }
        }
        # If neither ClassName nor AttributeName provided, get all classes
        else {
            Write-Host -ForegroundColor Cyan 'No ClassName or AttributeName provided, retrieving all classes and their attributes...'
            
            # Get all class schema objects
            $allClassSearcher = New-Object DirectoryServices.DirectorySearcher
            $allClassSearcher.SearchRoot = $schemaEntry
            $allClassSearcher.Filter = "(objectClass=classSchema)"
            $allClassSearcher.PropertiesToLoad.Add('ldapDisplayName')
            $allClassSearcher.PageSize = 1000
            
            $allClassResults = $allClassSearcher.FindAll()
            $allClasses = @()
            foreach ($result in $allClassResults) {
                if ($result.Properties['ldapdisplayname']) {
                    $allClasses += $result.Properties['ldapdisplayname'][0]
                }
            }
            $allClassSearcher.Dispose()
            $allClassResults.Dispose()

            $i = 0
            foreach ($class in $allClasses) {
                Write-Host -ForegroundColor Green "Retrieving attributes for class: $class ($i of $($allClasses.Count))"
                
                try {
                    $attributes = Get-ADAttributeInfov2 -ClassName $class -Server $Server
                    
                    foreach ($attr in $attributes) {
                        $attributesArray.Add([PSCustomObject][ordered]@{
                            Class     = $class
                            Attribute = $attr.Attribute
                            Type      = $attr.Type
                            Required  = $attr.Required
                        })
                    }
                } catch {
                    Write-Warning "Error processing class '$class': $($_.Exception.Message)"
                }

                $i++
            }
        }

        $schemaEntry.Dispose()
        
        # Remove duplicates and sort results
        $uniqueResults = $attributesArray | Sort-Object Attribute, Class -Unique
        return $uniqueResults

    } catch {
        Write-Error "Error accessing Active Directory schema: $($_.Exception.Message)"
        if ($schemaEntry) { $schemaEntry.Dispose() }
        return $null
    }
}