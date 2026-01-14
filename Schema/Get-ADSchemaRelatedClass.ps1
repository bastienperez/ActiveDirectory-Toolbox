# modified version of https://www.neroblanco.co.uk/2017/09/get-possible-ad-attributes-user-group/

Function Get-ADSchemaRelatedClass {
  Param(
    [CmdletBinding()]
    [Parameter(Mandatory = $true)]
    [String]$ClassName
)

  $Classes = @($ClassName)
  
  $SubClass = Get-ADObject -SearchBase "$((Get-ADRootDSE).SchemaNamingContext)" -Filter {lDAPDisplayName -eq $ClassName} -properties subClassOf | Select-Object -ExpandProperty subClassOf
  
  if( $Subclass -and $SubClass -ne $ClassName ) {
    $Classes += Get-RelatedClass $SubClass
  }
  
  $auxiliaryClasses = Get-ADObject -SearchBase "$((Get-ADRootDSE).SchemaNamingContext)" -Filter {lDAPDisplayName -eq $ClassName} -properties auxiliaryClass | Select-Object -ExpandProperty auxiliaryClass
  
  foreach( $auxiliaryClass in $auxiliaryClasses ) {
    $Classes += Get-RelatedClass $auxiliaryClass
  }

  return $Classes
}