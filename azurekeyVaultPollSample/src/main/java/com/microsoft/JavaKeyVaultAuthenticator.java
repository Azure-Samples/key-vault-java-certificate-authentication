package com.microsoft;

import com.azure.core.credential.TokenCredential;
import com.azure.core.management.AzureEnvironment;
import com.azure.core.management.profile.AzureProfile;
import com.azure.identity.ClientCertificateCredentialBuilder;
import com.azure.resourcemanager.keyvault.KeyVaultManager;
import com.azure.resourcemanager.keyvault.models.Vault;

import java.util.Optional;

public class JavaKeyVaultAuthenticator {

    /**
     * Do certificate based authentication using pfx file
     *
     * @param clientId
     *            also known as applicationId which is received after app
     * @param tenantId
     *            also known as directoryId which is received after app
     * @param pathPfx
     *            to pfx file
     * @param pfxPassword
     *            the password to the pfx file, this can be empty if thats the value
     *            given when it was created
     */
    public TokenCredential getTokenCredential(String clientId, String tenantId, String pathPfx, String pfxPassword) {

        TokenCredential credential = new ClientCertificateCredentialBuilder()
                .clientId(clientId)
                .tenantId(tenantId)
                .pfxCertificate(pathPfx, pfxPassword)
                .build();

        return credential;
    }

    /**
     * Find the vault you want to operate by keyVaultName
     * @param credential
     *            Authorized to get keyVaultManager
     * @param resourceGroupName
     *            Use resourceGroupName to find Vaults
     * @param vaultBaseUrl
     *            Use vaultBaseUrl to find the vault to be operated in Vaults
     * @return
     */
    public Vault getVault(TokenCredential credential, String resourceGroupName, String vaultBaseUrl) {

        AzureProfile profile = new AzureProfile(AzureEnvironment.AZURE);
        KeyVaultManager manager = KeyVaultManager.authenticate(credential, profile);

        Optional<Vault> optional = manager.vaults().listByResourceGroup(resourceGroupName).stream().filter(vault -> vaultBaseUrl.equals(vault.vaultUri())).findFirst();
        if (optional.isPresent()) {
            return optional.get();
        }
        return null;
    }
}


