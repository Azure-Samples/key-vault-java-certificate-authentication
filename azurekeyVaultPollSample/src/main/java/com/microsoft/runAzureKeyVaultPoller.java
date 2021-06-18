package com.microsoft;


import com.azure.core.credential.TokenCredential;
import com.azure.identity.DefaultAzureCredentialBuilder;
import com.azure.resourcemanager.keyvault.models.Vault;
import com.azure.security.keyvault.keys.KeyClient;
import com.azure.security.keyvault.keys.KeyClientBuilder;
import com.azure.security.keyvault.keys.cryptography.CryptographyAsyncClient;
import com.azure.security.keyvault.keys.cryptography.CryptographyClientBuilder;
import com.azure.security.keyvault.keys.models.KeyType;
import com.azure.security.keyvault.keys.models.KeyVaultKey;
import com.azure.security.keyvault.secrets.SecretAsyncClient;
import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.security.keyvault.secrets.SecretClientBuilder;
import com.azure.security.keyvault.secrets.models.KeyVaultSecret;
import org.springframework.beans.factory.annotation.Autowired;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.util.Properties;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;


/**
 * Azure key Vault example,
 * load authentication at runtime,
 * create a key vault and keys and secrets in vault.
 * Continuously poll key vault for keys.
 *
 * Note: It is also possible to do authenication using:
 * TokenCredential credential = new ClientCertificateCredentialBuilder()
 *                 .clientId(clientId).tenantId(tenantId).pfxCertificate(pathPfx, pfxPassword).build();
 *
 * However in this sample we need to use the asymmetric authentication method because
 * we want to do certificate based authentication
 *
 * Also please note that OCT and EC types for keys are not supported yet
 *
 * In addition, the the field pfxPassword can be empty string if that was the way you created the certificate
 */

public class runAzureKeyVaultPoller
{
    @Autowired
    public static SignVerifySamplesKeyVault azureSignVerifier;

    public static void main( String[] args )
    {
        try{
            final String clientId;
            final String tenantId;
            final String pathPfx;
            final String pfxPassword;
            final String resourceGroupName;
            final String vaultBaseUrl;

            Properties props = new Properties();
            props.load(Thread.currentThread().getContextClassLoader().getResourceAsStream("azure.properties"));

            clientId = props.getProperty("clientId");
            tenantId = props.getProperty("tenantId");
            pathPfx = props.getProperty("pathPfx");
            pfxPassword = props.getProperty("pfxPassword");
            resourceGroupName = props.getProperty("resourceGroupName");
            vaultBaseUrl = props.getProperty("vaultBaseUrl");

            JavaKeyVaultAuthenticator authenticator = new JavaKeyVaultAuthenticator();
            TokenCredential tokenCredential = authenticator.getTokenCredential(clientId, tenantId, pathPfx, pfxPassword);
            Vault vault = authenticator.getVault(tokenCredential, resourceGroupName, vaultBaseUrl);

            runSample(tokenCredential, vaultBaseUrl,vault);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Run the polling of Key Vault, and sign and verify operations
     * @param tokenCredential Use it to build KeyClient,secretClient
     * @param vaultBaseUrl the url of the vault where the secret and keys are stored
     */
    public static void runSample(TokenCredential tokenCredential,String vaultBaseUrl, Vault vault) throws InterruptedException {

        KeyClient keyClient = new KeyClientBuilder().credential(tokenCredential).vaultUrl(vaultBaseUrl).buildClient();
        SecretClient secretClient = new SecretClientBuilder().credential(tokenCredential).vaultUrl(vaultBaseUrl).buildClient();
        SecretAsyncClient secretAsyncClient = vault.secretClient();

        //Example of how to create a key using keyClient, in the specified vault
        KeyVaultKey savedKey = keyClient.createKey("keyRSA", KeyType.RSA);
        System.out.println("The key Id is: " + savedKey.getId());

        //Example: Async example of creating secret in specified vault, null passed for callback
        secretAsyncClient.setSecret("secretNameInVault", "secretValue").subscribe(keyVaultSecret -> {
            System.out.println("The secret value is: " + keyVaultSecret.getValue());
        });

        Thread.sleep(10000);

        System.out.println("Now listing keys and secrets in Azure Key Vault.");

        keyClient.listPropertiesOfKeys().stream().forEach(keyProperty -> {
            System.out.printf("key attributes : enabled is %s, notBefore is %s, expires is %s, created is %s, updated is %s \n",
                    keyProperty.isEnabled(), keyProperty.getNotBefore(), keyProperty.getExpiresOn(), keyProperty.getCreatedOn(), keyProperty.getUpdatedOn());
            System.out.println("key tag is: " + keyProperty.getTags());
            System.out.println("key id: " + keyProperty.getId());
            KeyVaultKey key = keyClient.getKey(keyProperty.getName());
            String keyName = keyProperty.getName();
            try {
                runSigning(key.getId(), vault, keyName, keyProperty.getId());
            } catch (Exception e) {
                e.printStackTrace();
            }

            System.out.println("Key in Key Vault: " + key.getId());
        });

       secretClient.listPropertiesOfSecrets().stream().forEach(secretProperty -> {
            System.out.printf("secret attributes : enabled is %s, notBefore is %s, expires is %s, created is %s, updated is %s \n",
                    secretProperty.isEnabled(), secretProperty.getNotBefore(), secretProperty.getExpiresOn(), secretProperty.getCreatedOn(), secretProperty.getUpdatedOn());
            String secret_url = secretProperty.getId();
            System.out.println("secret value: " + secret_url);

            KeyVaultSecret keyVaultSecret = secretClient.getSecret(secretProperty.getName());
            String savedSecretValue = keyVaultSecret.getValue();
            System.out.println("Secret in Key Vault Value: " + savedSecretValue);
        });

        //asynchronous call to key vault with null passed for callback to list secrets in vault
        secretAsyncClient.listPropertiesOfSecrets().subscribe(secretProperty -> {
            System.out.printf("secret attributes : enabled is %s, notBefore is %s, expires is %s, created is %s, updated is %s \n",
                    secretProperty.isEnabled(), secretProperty.getNotBefore(), secretProperty.getExpiresOn(), secretProperty.getCreatedOn(), secretProperty.getUpdatedOn());
            String secret_url = secretProperty.getId();
            System.out.println("secret value: " + secret_url);
            secretAsyncClient.getSecret(secretProperty.getName()).subscribe(secret -> {
                System.out.println("Secret in Key Vault Value: " + secret.getValue());
            });
        });
        Thread.sleep(15000);
    }

    /**
     * Run the sign and verify operations.
     * This would be useful in a case where you want to create signature for
     * some digital data and then verify that this signature is authentic.
     * @param key_url the url of the key also known as Key Identifier
     */
    public static void runSigning(String key_url, Vault vault, String keyName, String keyId) throws NoSuchAlgorithmException, ExecutionException, InterruptedException, SignatureException, InvalidKeyException, NoSuchProviderException {

        CryptographyAsyncClient cryptographyAsyncClient = new CryptographyClientBuilder()
                .credential(new DefaultAzureCredentialBuilder().build())
                .keyIdentifier(key_url)
                .buildAsyncClient();

        digestSignResult digestSignResult = azureSignVerifier.KeyVaultSign(cryptographyAsyncClient, "SHA-256", keyId);

        Future<Boolean> verified256 = azureSignVerifier.KeyVaultVerify(vault, keyName, digestSignResult);
        System.out.println("Verified SHA 256: " + verified256.get().toString());

        Future<Boolean> verifiedREST256 = azureSignVerifier.KeyVaultVerifyREST(cryptographyAsyncClient, digestSignResult);
        System.out.println("Verified SHA 256 with REST verify: " + verifiedREST256.get().toString());
    }
}

