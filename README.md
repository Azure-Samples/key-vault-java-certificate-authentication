**Java Azure Key Vault Deploy Certificates to Vault and Certificate based Authenication**  
This Sample describes how to create a vault, and put keys and secrets in the vault. It then shows how to inject into a VM at deployment a pfx file from the vault using a template. The sample also shows signing and verification of signature with both Java Security and Azure Key Vault REST used for verfiying the signature. The code calls the vault for the keys and secrets and writes these values to console. This sample also shows how to authenicate using a pfx file.

**Step 1)**
Create vault and store keys and secrets in vault this can be done through powerShell, Azure CLI or Java (Vault management sdk which is different from Key Vault client sdk), or using the Azure Portal.

Azure CLI and PowerShell (PSH) commands for **step 2** are below:

* Login to account: 

    CLI 1.0: ```azure login```

    CLI 2.0: ```az login```

    PSH: ```Login-AzureRmAccount```

* Create new resource group:

    CLI 1.0: ```azure group create 'ContosoResourceGroup' 'East Asia'```

    CLI 2.0: ```az group create --name "ContosoResourceGroup" --location "East Asia"```

    PSH: ```New-AzureRmResourceGroup –Name 'ContosoResourceGroup' –Location 'East Asia'```

* Register Key Vault resource provider, if error "The subscription is not registered to use namespace 'Microsoft.KeyVault'":

    CLI 1.0: ```azure provider register Microsoft.KeyVault```

    CLI 2.0: ```az provider register --namespace Microsoft.KeyVault```

    PSH: ```Register-AzureRmResourceProvider -ProviderNamespace "Microsoft.KeyVault"```

* Create a key vault:

    CLI 1.0: ```azure keyvault create --vault-name 'ContosoKeyVault' --resource-group 'ContosoResourceGroup' --location 'East Asia'```

    CLI 2.0: ```az keyvault create --name "ContosoKeyVault" --resource-group "ContosoResourceGroup" --location "East Asia"```

    PSH: ```New-AzureRmKeyVault -VaultName 'ContosoKeyVault' -ResourceGroupName 'ContosoResourceGroup' -Location 'East Asia'```

* Add key to key vault:

    CLI 1.0: ```azure keyvault key create --vault-name 'ContosoKeyVault' --key-name 'ContosoFirstKey' --destination software```

    CLI 2.0: ```az keyvault key create --vault-name "ContosoKeyVault" --name "ContosoFirstKey" --protection software```

    PSH: ```$key = Add-AzureKeyVaultKey -VaultName 'ContosoKeyVault' -Name 'ContosoFirstKey' -Destination 'Software'```

* Add a secret to key vault:

    CLI 1.0: ```azure keyvault secret set --vault-name 'ContosoKeyVault' --secret-name 'SQLPassword' --value 'Pa$$w0rd'```

    CLI 2.0: ```az keyvault secret set --vault-name "ContosoKeyVault" --name "SQLPassword" --value "Pa$$w0rd"```

    PSH: ```$secretvalue = ConvertTo-SecureString 'Pa$$w0rd' -AsPlainText -Force```    
         ```$secret = Set-AzureKeyVaultSecret -VaultName 'ContosoKeyVault' -Name 'SQLPassword' -SecretValue $secretvalue```

Example using Java:
<https://github.com/Azure-Samples/key-vault-java-manage-key-vaults/blob/master/src/main/java/com/microsoft/azure/management/keyvault/samples/ManageKeyVault.java>

Example using Azure CLI:
<https://docs.microsoft.com/en-us/azure/key-vault/key-vault-manage-with-cli>

Example using PowerShell:
<https://docs.microsoft.com/en-us/azure/key-vault/key-vault-get-started>


**Step 2)**
Application registration and refresh scenario (applicationId is clientId). This can be done through PowerShell, Azure CLI 2.0 or the portal. If your vault name is ContosoKeyVault and the application you want to authorize has a client ID of 8f8c4bbd-485b-45fd-98f7-ec6300b7b4ed.

* Azure CLI and PowerShell (PSH) commands are below:

    CLI 1.0: ```azure keyvault set-policy --vault-name 'ContosoKeyVault' --spn 8f8c4bbd-485b-45fd-98f7-ec6300b7b4ed --perms-to-keys '[\"decrypt\",\"sign\"]'```

    CLI 2.0: ```az keyvault set-policy --name 'ContosoKeyVault' --spn 8f8c4bbd-485b-45fd-98f7-ec6300b7b4ed --key-permissions decrypt sign```

    PSH: ```Set-AzureRmKeyVaultAccessPolicy -VaultName 'ContosoKeyVault' -ServicePrincipalName 8f8c4bbd-485b-45fd-98f7-ec6300b7b4ed -PermissionsToKeys decrypt,sign```

* If you want to authorize that same application to read secrets in your vault, run the following:

    CLI 1.0: ```azure keyvault set-policy --vault-name 'ContosoKeyVault' --spn 8f8c4bbd-485b-45fd-98f7-ec6300b7b4ed --perms-to-secrets '[\"get\"]'```

    CLI 2.0: ```az keyvault set-policy --name 'ContosoKeyVault' --spn 8f8c4bbd-485b-45fd-98f7-ec6300b7b4ed --secret-permissions get```

    PSH: ```Set-AzureRmKeyVaultAccessPolicy -VaultName 'ContosoKeyVault' -ServicePrincipalName 8f8c4bbd-485b-45fd-98f7-ec6300b7b4ed -PermissionsToSecrets Get```

Note: Permissions for listing keys or secrets would require including: ```\"list\"``` in CLI 1.0 and ``` list ``` in CLI 2.0. 

See section on registering application with Azure Active Directory using PowerShell:
<https://docs.microsoft.com/en-us/azure/key-vault/key-vault-get-started>

See section on registering application with Azure Active Directory using Azure CLI:
<https://docs.microsoft.com/en-us/azure/key-vault/key-vault-manage-with-cli>

See section on registering application with Azure Active Directory using Azure CLI 2.0:
<https://docs.microsoft.com/en-us/azure/key-vault/key-vault-manage-with-cli2>

More information on application registration:
<https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-integrating-applications>

**Step 3)**
Create a self-signed certificate and pfx file (make sure key is exportable) with powerShell script and upload to vault via portal or powerShell (problem with powerShell upload)

PowerShell commands are below for creating self-signed certificate:

```$certificateName = "certforvm"```

```$thumbprint = (New-SelfSignedCertificate -DnsName $certificateName -CertStoreLocation Cert:\CurrentUser\My -KeySpec KeyExchange).Thumbprint```

```$cert = (Get-ChildItem -Path cert:\CurrentUser\My\$thumbprint)```

```$password = Read-Host -Prompt "Please enter the certificate password." -AsSecureString```

```Export-PfxCertificate -Cert $cert -FilePath ".\$certificateName.pfx" -Password $password```

Example using PowerShell:
<https://blogs.technet.microsoft.com/kv/2016/09/14/updated-deploy-certificates-to-vms-from-customer-managed-key-vault/>

**Step 4)**
Inject pfx file at deployment into windows VM and then use certmgr to extract pfx from certificate in LOCAL machine using the steps **Step 3**.

**Step 5)**
Java program with clientId and certificate authenication (need to specify path to pfx file)
Java code for making both synchronous and asynchronous calls to Key Vault, as well as creating keys and secrets. It is recommended that certificate based authentication is used instead of client Id and client secret Id authentication. Please refer to sample code.


