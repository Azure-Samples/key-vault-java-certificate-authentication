package com.microsoft;

import com.azure.core.credential.TokenCredential;
import com.azure.identity.DefaultAzureCredentialBuilder;
import com.azure.resourcemanager.keyvault.models.Vault;
import com.azure.security.keyvault.keys.KeyClient;
import com.azure.security.keyvault.keys.KeyClientBuilder;
import com.azure.security.keyvault.keys.cryptography.CryptographyAsyncClient;
import com.azure.security.keyvault.keys.cryptography.CryptographyClientBuilder;
import com.azure.security.keyvault.keys.cryptography.models.VerifyResult;
import com.azure.security.keyvault.keys.models.KeyType;
import com.azure.security.keyvault.keys.models.KeyVaultKey;
import com.azure.security.keyvault.secrets.SecretAsyncClient;
import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.security.keyvault.secrets.SecretClientBuilder;
import com.azure.security.keyvault.secrets.models.KeyVaultSecret;
import org.springframework.beans.factory.annotation.Autowired;
import reactor.core.publisher.Mono;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.util.Properties;
import java.util.concurrent.ExecutionException;


/**
 * A class that exemplifies the following:
 * <ul>
 * <li>How to load authentication at runtime.</li>
 * <li>How to create a key vault.</li>
 * <li>How to create keys and secrets in vault<li>
 * <li>How to list said keys and secrets.</li>
 * <li>How to sign and verify data using a given key.</li>
 * </ul>
 *
 * Note: It is also possible to do authenication using:
 * TokenCredential credential = new ClientCertificateCredentialBuilder()
 *     .clientId(clientId).tenantId(tenantId).pfxCertificate(pathPfx, pfxPassword).build();
 *
 * However, in this sample we need to use the asymmetric authentication method because
 * we want to do certificate based authentication.
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
            Properties props = new Properties();
            props.load(Thread.currentThread().getContextClassLoader().getResourceAsStream("azure.properties"));

            final String clientId = props.getProperty("clientId");
            final String tenantId = props.getProperty("tenantId");
            final String pathPfx = props.getProperty("pathPfx");
            final String pfxPassword = props.getProperty("pfxPassword");
            final String resourceGroupName = props.getProperty("resourceGroupName");
            final String vaultBaseUrl = props.getProperty("vaultBaseUrl");

            JavaKeyVaultAuthenticator authenticator = new JavaKeyVaultAuthenticator();
            TokenCredential tokenCredential = authenticator.getTokenCredential(clientId, tenantId, pathPfx, pfxPassword);
            Vault vault = authenticator.getVault(tokenCredential, resourceGroupName, vaultBaseUrl);

            runSample(tokenCredential, vaultBaseUrl, vault);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Performs basic Key Vault operations such as creating and listing keys and secrets. Additionally, it performs the sign and verify operations on some data using a key created beforehand.
     * @param tokenCredential Credential used to build clients such as {@link KeyClient} and a {@link SecretClient}.
     * @param vaultBaseUrl the url of the vault where the secret and keys are stored
     */
    public static void runSample(TokenCredential tokenCredential, String vaultBaseUrl, Vault vault) throws InterruptedException {

        KeyClient keyClient = new KeyClientBuilder()
                .credential(tokenCredential)
                .vaultUrl(vaultBaseUrl)
                .buildClient();
        SecretClient secretClient = new SecretClientBuilder()
                .credential(tokenCredential)
                .vaultUrl(vaultBaseUrl).buildClient();
        SecretAsyncClient secretAsyncClient = vault.secretClient();

        // Example: Using the KeyClient, create a key synchronously in the specified vault.
        KeyVaultKey savedKey = keyClient.createKey("keyRSA", KeyType.RSA);
        System.out.println("The key Id is: " + savedKey.getId());

        // Example: Using the SecretClient, create a secret synchronously in the specified vault.
        secretAsyncClient.setSecret("secretNameInVault", "secretValue")
                .subscribe(keyVaultSecret -> {
                    System.out.println("The secret value is: " + keyVaultSecret.getValue());
                });

        Thread.sleep(10000);

        System.out.println("Now listing keys and secrets in Azure Key Vault.");

        // Now let's list the existing keys in the vault and use them for signing data and verifying the signature.
        keyClient.listPropertiesOfKeys().stream().forEach(keyProperties -> {
            System.out.printf("Key attributes: EnabledOn:%s, NotBeforeOn:%s, ExpiresOn:%s, CreatedOn:%s, UpdatedOn:%s%n",
                    keyProperties.isEnabled(), keyProperties.getNotBefore(), keyProperties.getExpiresOn(), keyProperties.getCreatedOn(), keyProperties.getUpdatedOn());
            System.out.println("Key tags are: " + keyProperties.getTags());
            System.out.println("Key ID: " + keyProperties.getId());

            KeyVaultKey key = keyClient.getKey(keyProperties.getName());
            String keyName = keyProperties.getName();
            // Let's sign data using the
            try {
                signAndVerify(key);
            } catch (Exception e) {
                e.printStackTrace();
            }
        });

        // Similar to above, let's list the existing secrets in the vault.
        secretClient.listPropertiesOfSecrets().stream().forEach(secretProperties -> {
            System.out.printf("Secret attributes: EnabledOn %s, NotBeforeOn %s, ExpiresOn %s, CreatedOn %s, UpdatedOn %s%n",
                    secretProperties.isEnabled(), secretProperties.getNotBefore(), secretProperties.getExpiresOn(), secretProperties.getCreatedOn(), secretProperties.getUpdatedOn());
            System.out.println("Secret ID: " + secretProperties.getId());
            KeyVaultSecret keyVaultSecret = secretClient.getSecret(secretProperties.getName());
            String secretValue = keyVaultSecret.getValue();
            System.out.println("Secret value: " + secretValue);
        });

        // It is also possible to perform these operations asynchronously.
        secretAsyncClient.listPropertiesOfSecrets().subscribe(secretProperties -> {
            System.out.printf("Secret attributes: EnabledOn %s, NotBeforeOn %s, ExpiresOn %s, CreatedOn %s, UpdatedOn %s%n",
                    secretProperties.isEnabled(), secretProperties.getNotBefore(), secretProperties.getExpiresOn(), secretProperties.getCreatedOn(), secretProperties.getUpdatedOn());
            System.out.println("Secret ID: " + secretProperties.getId());
            secretAsyncClient.getSecret(secretProperties.getName()).subscribe(secret ->
                    System.out.println("Secret value: " + secret.getValue()));
        });
        Thread.sleep(15000);
    }

    /**
     * Performs the data sign and verify operations.
     * This is useful in case you want to create a signature for some data and then verify that said signature is authentic.
     * @param key The key to use for signing and verifying the data.
     */
    public static void signAndVerify(KeyVaultKey key) throws NoSuchAlgorithmException, ExecutionException, InterruptedException, SignatureException, InvalidKeyException, NoSuchProviderException {
        String keyId = key.getId();
        CryptographyAsyncClient cryptographyAsyncClient = new CryptographyClientBuilder()
                .credential(new DefaultAzureCredentialBuilder().build())
                .keyIdentifier(keyId)
                .buildAsyncClient();

        DigestSignResult digestSignResult = azureSignVerifier.keyVaultSign(cryptographyAsyncClient, "SHA-256", keyId);

        Boolean verified256 = azureSignVerifier.keyVaultVerify(key, digestSignResult);
        System.out.println("Verified SHA 256: " + verified256);

        Mono<VerifyResult> verifiedREST256 = azureSignVerifier.keyVaultVerifyREST(cryptographyAsyncClient, digestSignResult);
        System.out.println("Verified SHA 256 with REST verify: " + verifiedREST256.block().isValid());
    }
}

