package com.microsoft;


import com.microsoft.aad.adal4j.AsymmetricKeyCredential;
import com.microsoft.aad.adal4j.AuthenticationContext;
import com.microsoft.aad.adal4j.AuthenticationResult;
import com.microsoft.azure.keyvault.KeyVaultClient;
import com.microsoft.azure.keyvault.authentication.KeyVaultCredentials;
import com.microsoft.azure.keyvault.models.*;
import com.microsoft.azure.keyvault.requests.CreateKeyRequest;
import com.microsoft.azure.keyvault.requests.SetSecretRequest;
import com.microsoft.azure.keyvault.webkey.JsonWebKeySignatureAlgorithm;
import com.microsoft.azure.keyvault.webkey.JsonWebKeyType;
import com.microsoft.rest.ServiceFuture;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Configurable;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

/**
 * Azure key Vault example,
 * load authentication at runtime,
 * create a key vault and keys and secrets in vault.
 * Continuously poll key vault for keys.
 *
 * Note: It is also possible to do authenication using:
 * ClientCredential credentials = new ClientCredential(clientId, clientSecret);
 * AuthenticationResult result = context.acquireToken(resource, credentials, null).get();
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
            Properties props = new Properties();
            props.load(Thread.currentThread().getContextClassLoader().getResourceAsStream("azure.properties"));

            final String clientId = props.getProperty("clientId");
            final String pfxPassword = props.getProperty("pfxPassword");
            final String path = props.getProperty("pathPfx");
            final String vaultUrl = props.getProperty("vaultBaseUrl");

            JavaKeyVaultAuthenticator authenticator = new JavaKeyVaultAuthenticator();

            KeyVaultClient kvClient = authenticator.getAuthentication(path, pfxPassword, clientId);

            runSample(kvClient, vaultUrl);
        }
        catch(Exception e){
            e.printStackTrace();
        }
}

    /**
     * Run the polling of Key Vault, and sign and verify operations
     * Async operations are also demonstrated
     * @param kvClient instance of Azure KeyVaultClient
     * @param vaultBaseUrl the url of the vault where the secret and keys are stored
     */
    public static void runSample(KeyVaultClient kvClient, String vaultBaseUrl){

        try {

            //Example of how to create a key using KV client, in the specified vault
            KeyBundle keyRSA = kvClient.createKey(new CreateKeyRequest.Builder(vaultBaseUrl,"keyRSA", JsonWebKeyType.RSA).build());
            System.out.println("The key Id is: " + keyRSA.key().kid());

            //Example: Async example of creating secret in specified vault, null passed for callback
            ServiceFuture<SecretBundle> secretAsync = kvClient.setSecretAsync(new SetSecretRequest.Builder(vaultBaseUrl,"secretNameInVault","secretValue").build(),null);
            System.out.println("The secret value is: " + secretAsync.get().value());

            System.out.println("Now listing keys and secrets in Azure Key Vault.");

            for(KeyItem ki: kvClient.listKeys(vaultBaseUrl,10)){ //list keys in vault up to a maximum of 10 records
                System.out.println("key tag is: " + ki.tags());
                System.out.println("key attributes: " + ki.attributes());
                String key_url = ki.kid();
                System.out.println("key id: " + key_url);

                runSigning(kvClient,key_url);

                KeyBundle keyBundle = kvClient.getKey(key_url);
                String kid = keyBundle.key().kid(); // get the key identifier
                System.out.println("Key in Key Vault: " + kid);
            }

            List<SecretItem> secretItems = kvClient.listSecrets(vaultBaseUrl,10);

            secretItems.stream().forEach(si -> {
                System.out.println("secret attributes: " + si.attributes());
                String secret_url = si.id();
                System.out.println("secret value: " + secret_url);

                SecretBundle secretBundle = kvClient.getSecret(secret_url);
                String secretValue = secretBundle.value();
                System.out.println("Secret in Key Vault Value: " + secretValue);
            });

            //asynchronous call to key vault with null passed for callback to list secrets in vault up to a maximum of 10 records
            ServiceFuture<List<SecretItem>> futSecrets = kvClient.listSecretsAsync(vaultBaseUrl,10,null);

            List<SecretItem> listSecrets = futSecrets.get();

            for(SecretItem sf: listSecrets){
                System.out.println("secret attributes: " + sf.attributes());
                String secret_url = sf.id();
                System.out.println("secret value: " + secret_url);

                ServiceFuture<SecretBundle> secretBundle = kvClient.getSecretAsync(secret_url, null);
                String secretValue = secretBundle.get().value();
                System.out.println("Secret in Key Vault Value: " + secretValue);
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Run the sign and verify operations.
     * This would be useful in a case where you want to create signature for
     * some digital data and then verify that this signature is authentic.
     * @param kvClient instance of Azure KeyVaultClient
     * @param key_url the url of the key also known as Key Identifier
     */
    public static void runSigning( KeyVaultClient kvClient, String key_url) throws InterruptedException, ExecutionException, NoSuchAlgorithmException,
            SignatureException, NoSuchProviderException, InvalidKeyException {

        digestSignResult resultSign = azureSignVerifier.KeyVaultSign(kvClient,key_url,"SHA-256", JsonWebKeySignatureAlgorithm.RSNULL);

        Future<Boolean> verified256 = azureSignVerifier.KeyVaultVerify(kvClient,key_url,resultSign.getDigestInfo(),resultSign.getResultSign());
        System.out.println("Verified SHA 256: " + verified256.get().toString());

        Future<Boolean> verifiedREST256 = azureSignVerifier.KeyVaultVerifyREST(kvClient,key_url,JsonWebKeySignatureAlgorithm.RS256,resultSign.getResultSign(),resultSign.getDigestInfo());
        System.out.println("Verified SHA 256 with REST verify: " + verifiedREST256.get().toString());
    }

}

