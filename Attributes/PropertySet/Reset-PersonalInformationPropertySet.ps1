$attributes = @(
    "assistant",
    "c",
    "facsimileTelephoneNumber",
    "homePhone",
    "homePostalAddress",
    "info",
    "internationalISDNNumber",
    "ipPhone",
    "l",
    "mobile",
    "msDS-FailedInteractiveLogonCount",
    "msDS-FailedInteractiveLogonCountAtLastSuccessfulLogon",
    "msDS-HostServiceAccount",
    "msDS-LastFailedInteractiveLogonTime",
    "msDS-LastSuccessfulInteractiveLogonTime",
    "msDS-SupportedEncryptionTypes",
    "mSMQDigests",
    "mSMQSignCertificates",
    "otherFacsimileTelephoneNumber",
    "otherHomePhone",
    "otherIpPhone",
    "otherMobile",
    "otherPager",
    "otherTelephone",
    "pager",
    "personalTitle",
    "physicalDeliveryOfficeName",
    "postalAddress",
    "postalCode",
    "postOfficeBox",
    "preferredDeliveryMethod",
    "primaryInternationalISDNNumber",
    "primaryTelexNumber",
    "registeredAddress",
    "st",
    "street",
    "streetAddress",
    "telephoneNumber",
    "teletexTerminalIdentifier",
    "telexNumber",
    "thumbnailPhoto",
    "userCert",
    "userCertificate",
    "userSharedFolder",
    "userSharedFolderOther",
    "userSMIMECertificate",
    "x121Address",
    "msDS-cloudExtensionAttribute1",
    "msDS-cloudExtensionAttribute10",
    "msDS-cloudExtensionAttribute11",
    "msDS-cloudExtensionAttribute12",
    "msDS-cloudExtensionAttribute13",
    "msDS-cloudExtensionAttribute14",
    "msDS-cloudExtensionAttribute15",
    "msDS-cloudExtensionAttribute16",
    "msDS-cloudExtensionAttribute17",
    "msDS-cloudExtensionAttribute18",
    "msDS-cloudExtensionAttribute19",
    "msDS-cloudExtensionAttribute2",
    "msDS-cloudExtensionAttribute20",
    "msDS-cloudExtensionAttribute3",
    "msDS-cloudExtensionAttribute4",
    "msDS-cloudExtensionAttribute5",
    "msDS-cloudExtensionAttribute6",
    "msDS-cloudExtensionAttribute7",
    "msDS-cloudExtensionAttribute8",
    "msDS-cloudExtensionAttribute9",
    "msDS-GeoCoordinatesAltitude",
    "msDS-GeoCoordinatesLatitude",
    "msDS-GeoCoordinatesLongitude",
    "msDS-ExternalDirectoryObjectId"
)

$propertySetGuid = "77B5B886-944A-11d1-AEBD-0000F80367C1"

$rootDSE = Get-ADRootDSE
$schemaNamingContext = $rootDSE.schemaNamingContext

foreach ($attr in $attributes) {
    $attrDN = "CN=$attr,$schemaNamingContext"
    
    try {
        Set-ADObject -Identity $attrDN -Add @{attributeSecurityGUID = $propertySetGuid}
        Write-Host "Ajouté: $attr"
    }
    catch {
        Write-Host "Erreur pour $attr : $_"
    }
}
