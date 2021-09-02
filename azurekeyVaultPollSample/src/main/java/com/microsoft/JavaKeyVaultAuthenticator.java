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
     * Do certificate based authentication using your PFX file.
     *
     * @param clientId
     *            Also known as applicationId which is received as a part of the app creation process.
     * @param tenantId
     *            Also known as directoryId which is received as a part of the app creation process.
     * @param pathPfx
     *            Path to your PFX certificate.
     * @param pfxPassword
     *            Password to your PFX certificate, this can be empty if that's the value given when it was created.
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
     * Find the vault you want to operate on by keyVaultName.
     *
     * @param credential
     *            Credential to authenticate a {@link KeyVaultManager} with.
     * @param resourceGroupName
     *            The name of the resource group your Key Vault is a part of.
     * @param vaultBaseUrl
     *            The URL that identifies your Key Vault.
     * @return A {@link Vault} object representing your Key Vault.
     */
    public Vault getVault(TokenCredential credential, String resourceGroupName, String vaultBaseUrl) {

        AzureProfile profile = new AzureProfile(AzureEnvironment.AZURE);
        KeyVaultManager manager = KeyVaultManager.authenticate(credential, profile);

        Optional<Vault> optional = manager
                .vaults()
                .listByResourceGroup(resourceGroupName)
                .stream()
                .filter(vault -> vaultBaseUrl.equals(vault.vaultUri()))
                .findFirst();
        if (optional.isPresent()) {
            return optional.get();
        }
        return null;
    }
}


