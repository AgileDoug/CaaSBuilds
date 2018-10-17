<#
 .SYNOPSIS
    Deploys a CaaS regional node (SF(LB,VSS,VM) through ARM after provisioning required infra

 .DESCRIPTION
    Deploys KeyVault then builds required secrets/objects and stores in KeyVault/Secrets and adds them to the param_hash for SF_ARM
    Deploys a standard ContainerRegistry (this could move into ARM since it's stand-alone for SF build)
    Builds param_hash and feeds into ARM as object

 .PARAMETER subscriptionId
    The subscription id where the template will be deployed.

 .PARAMETER resourceGroupName
    The resource group where the template will be deployed. Can be the name of an existing or a new resource group.

 .PARAMETER resourceGroupLocation
    Optional, a resource group location. If specified, will try to create a new resource group in this location. If not specified, assumes resource group is existing.

 .PARAMETER sfClusterName
    Required, the name of the Service Fabric cluster you want created

 .PARAMETER keyVaultName
    KeyVault Name - Will create if not found 

  .PARAMETER containerRegName
    The name of the Container Registry - Will create if not found 

  .PARAMETER deploymentName
    The deployment name, hardcoded for 'Caasbase'

 .PARAMETER templateFilePath
    Optional, path to the template file. Defaults to template.json.


#>
param(
[Parameter(Mandatory=$True)]
 [string]
 $subscriptionId,
 
[Parameter(Mandatory=$True)]
 [string]
 $resourceGroupName,

[Parameter(Mandatory=$True)]
 [string]
 $resourceGroupLocation,

[Parameter(Mandatory=$True)]
 [string]
 $sfClusterName,

 [Parameter(Mandatory=$True)]
 [string]
 $keyVaultName,

 [Parameter(Mandatory=$True)]
 [string]
 $containerRegName,

 [string]
 $vmInstances = 3,

 [string]
 $vmUserName,

 [string]
 $vmUserPwd,

 [string]
 $deploymentName = "CaasBase",

 [string]
 $templateFilePath = "SFDeployTemplate.json",
)

<#
.SYNOPSIS
    Basic functions to generate a 32 char randomized password with all 4 char sets
#>
function Generate-SecureRandomPwd() {
    $init_pwd = Get-RandomCharacters -length 10 -characters 'abcdefghiklmnoprstuvwxyz'
    $init_pwd += Get-RandomCharacters -length 10 -characters 'ABCDEFGHKLMNOPRSTUVWXYZ'
    $init_pwd += Get-RandomCharacters -length 10 -characters '1234567890'
    $init_pwd += Get-RandomCharacters -length 2 -characters '!"§$%&/()=?}][{@#*+'
    $init_pwd = Scramble-String $init_pwd
    $secure_pwd = ConvertTo-SecureString -String $init_pwd -AsPlainText -Force
    return $secure_pwd
}
function Get-RandomCharacters($length, $characters) {
    $random = 1..$length | ForEach-Object { Get-Random -Maximum $characters.length }
    $private:ofs=""
    return [String]$characters[$random]
}
 
function Scramble-String([string]$inputString){     
    $characterArray = $inputString.ToCharArray()   
    $scrambledStringArray = $characterArray | Get-Random -Count $characterArray.Length     
    $outputString = -join $scrambledStringArray
    return $outputString 
}

#******************************************************************************
# Script body
# Execution begins here
#******************************************************************************
$ErrorActionPreference = "Stop"

# sign in
Write-Host "Logging in..."
Login-AzureRmAccount

# select subscription
Write-Host "Selecting subscription '$subscriptionId'"
Select-AzureRmSubscription -SubscriptionID $subscriptionId

#Create or check for existing resource group
$resourceGroup = Get-AzureRmResourceGroup -Name $resourceGroupName -ErrorAction SilentlyContinue
if(!$resourceGroup)
{
    Write-Host "Resource group '$resourceGroupName' does not exist. To create a new resource group, please enter a location."
    if(!$resourceGroupLocation) {
        $resourceGroupLocation = Read-Host "resourceGroupLocation"
    }
    Write-Host "Creating resource group '$resourceGroupName' in location '$resourceGroupLocation'"
    New-AzureRmResourceGroup -Name $resourceGroupName -Location $resourceGroupLocation
}
else{
    Write-Host "Using existing resource group '$resourceGroupName'"
}

#Check for or create a Container Registry instance - This will create a 'standard' instance. Geo Replication will require upgrade to Premium manually
$contReg = Get-AzureRmContainerRegistry -ResourceGroupName $resourceGroupName
#$contReg = Get-AzureRmContainerRegistry -ResourceGroupName $resourceGroupName -Name $containerRegName

if(!$contReg)
{
    Write-Host "Container Registry '$containerRegName' does not exist in '$resourceGroupName'. Creating it now...'";
    New-AzureRmContainerRegistry -ResourceGroupName $resourceGroupName -Location $resourceGroupLocation -Name $containerRegName -Sku Standard -EnableAdminUser;
    #need to check if this was successful and error our if not
}
else{
    Write-Host "Valid Container Registry found. Continuing pre-processing...";
}

#Check for or create a KeyVault instance and then propegate it with VM Username/Pwd and then the cluster certs needed for SF
$keyVault = Get-AzureRMKeyVault -VaultName $KeyVaultName
if(!$keyVault)
{
    Write-Host "Key Vault '$keyVaultName' does not exist in '$resourceGroupName'. Creating it now...'"
    $keyVault = New-AzureRmKeyVault -VaultName $keyVaultName -ResourceGroupName $resourceGroupName -Location $resourceGroupLocation -EnabledForDeployment
}
else{
    Write-Host "Valid Key Vault found."
}

#check for existance and if not present, create and inject SF Cetificate into KeyVault Secret Blade
$CertDNSName = $sfClusterName + "DNS"
$sfCert = Get-AzureKeyVaultCertificate -VaultName $keyVaultName -Name $CertDNSName

#Get this secured from file into SecureObject (v2)
if(!$sfCert)
{
    ### Replace that with this code to create a certificate object
    $CertDNSName = $sfClusterName + "DNS"
    $NewCert = New-SelfSignedCertificate -CertStoreLocation Cert:\CurrentUser\My -DnsName $CertDNSName 
    $CertCollection = new-object System.Security.Cryptography.X509Certificates.X509CertificateCollection($NewCert)
    $sfCert = Import-AzureKeyVaultCertificate -VaultName $KeyVaultName -Name $CertDNSName -CertificateCollection $CertCollection -Verbose
    Write-Host "Source Vault Resource Id: "$(Get-AzureRmKeyVault -VaultName $KeyVaultName).ResourceId
    Write-Host "Certificate URL : "$sfCert.Id
    Write-Host "Certificate Thumbprint : "$sfCert.Thumbprint
    # Note that I changed your cert obj name from $NewSecret to $NewCertificate so change the name or your references to match.
}
else{
    Write-Host "Service Fabric Certificate Obtained."
}

$sfSecret = Get-AzureKeyVaultSecret -VaultName $keyVaultName -Name $CertDNSName

#inject VM User Name and Password into KeyVault Secret
if(!$vmUserName)
{
    $vmUserName = $sfClusterName + "user"
}

$vmSecret = Get-AzureKeyVaultSecret -VaultName $keyVaultName -Name $vmUserName

if(!$vmSecret)
{
    #v2 get this password from file into SecureObject
    #$sec_Password = concat('P', uniqueString(resourceGroup().id, deployment().name, '224F5A8B-51DB-46A3-A7C8-59B0DD584A41'), 'x', '!') | 
    Write-Host "Target Keyvault Secret not found. Generating new random Secure Password for VMs"
    $sec_Password = Generate-SecureRandomPwd
    $vmSecret = Set-AzureKeyVaultSecret -VaultName $keyVaultName -Name $vmUserName -SecretValue $sec_Password
}
else{
    Write-Host "KeyVault VM Secret located. Proceeding..."
}

#build parameter has table dynamically to feed to arm template call
#$arm_object | Add-Member -NotePropertyName "name" -NotePropertyValue "value"
$param_hash =@{}

$param_hash.Add("clusterName",$sfClusterName)
$param_hash.Add("clusterLocation",$resourceGroupLocation)
$param_hash.Add("certificateThumbprint",$sfCert.Thumbprint)
$param_hash.Add("certificateUrlValue",$sfSecret.Id)
$param_hash.Add("sourceVaultValue",$keyVault.ResourceId)
$param_hash.Add("adminUserName",$vmUserName)
$param_hash.Add("adminPassword",$vmSecret.SecretValueText)

# Start the deployment
Write-Host "Starting deployment..."
New-AzureRmResourceGroupDeployment -ResourceGroupName $resourceGroupName -TemplateFile $templateFilePath -TemplateParameterObject $param_hash
Write-Host "Script Finished."