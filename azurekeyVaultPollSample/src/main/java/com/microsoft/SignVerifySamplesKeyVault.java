package com.microsoft;

import com.microsoft.azure.keyvault.KeyVaultClient;
import com.microsoft.azure.keyvault.models.KeyOperationResult;
import com.microsoft.azure.keyvault.models.KeyVerifyResult;
import com.microsoft.azure.keyvault.webkey.JsonWebKeySignatureAlgorithm;
import com.microsoft.rest.ServiceFuture;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.AsyncResult;
import org.springframework.stereotype.Component;

import java.security.*;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;

@Component
public class SignVerifySamplesKeyVault {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Use KeyVaultClient to sign data
     * Get the public key, and use it to validate the signature
     * @param kvClient instance of Azure KeyVaultClient
     * @param keyIdentifier the url of the key
     * @param shaType the SHA type to use
     * @param keySignatureAlgorithm the signing algorithm to use
     */
    @Async
    public static digestSignResult KeyVaultSign(KeyVaultClient kvClient, String keyIdentifier, String shaType, JsonWebKeySignatureAlgorithm keySignatureAlgorithm) throws
                                                    NoSuchAlgorithmException, InterruptedException, ExecutionException, InvalidKeyException, SignatureException, NoSuchProviderException {

        MessageDigest hash = MessageDigest.getInstance(shaType, BouncyCastleProvider.PROVIDER_NAME);

        String key = keyIdentifier.substring(keyIdentifier.lastIndexOf('/') + 1);
        System.out.println("The key is: " + key);
        byte[] keyBytes = key.getBytes();

        hash.update(keyBytes);
        byte[] digestInfo = hash.digest();

        //use KeyVaultClient to to asynchronous signing passing in the uri of the key, type of algorithm to use, digest and null for callback function to handle responses
        ServiceFuture<KeyOperationResult> result = kvClient.signAsync(keyIdentifier, keySignatureAlgorithm, digestInfo, null);

        return new digestSignResult(digestInfo, result);
    }

    /**
     * Use Java Security to verify
     * Get the public key, and use it to validate the signature
     * @param kvClient instance of Azure KeyVaultClient
     * @param keyIdentifier the url of the key
     * @param digestInfo the digest from completing the hash
     * @param result the result of the signing using asynchronous call using KeyVaultClient
     */
    @Async
    public static Future<Boolean> KeyVaultVerify(KeyVaultClient kvClient, String keyIdentifier, byte[] digestInfo,
                                                 ServiceFuture<KeyOperationResult> result) throws NoSuchAlgorithmException, ExecutionException, InvalidKeyException,
                                                                                                    InterruptedException, NoSuchProviderException, SignatureException {

        //asynchronous call to key vault with null passed for callback for handling successful and failed responses
        KeyPair rsaKey = kvClient.getKeyAsync(keyIdentifier,null).get().key().toRSA();
        PublicKey publicKey = rsaKey.getPublic();

        Signature sig = Signature.getInstance("NONEwithRSA", BouncyCastleProvider.PROVIDER_NAME);
        sig.initVerify(publicKey);
        sig.update(digestInfo);
        Boolean verifies = sig.verify(result.get().result());

        return new AsyncResult<Boolean>(verifies);
    }

    /**
     * Use REST to verify SHA256
     * Get the public key, and use it to validate the signature
     * Using REST client also assumes that verify policy is allowed on the vault, if not enabled then please enable
     * @param kvClient instance of Azure KeyVaultClient
     * @param keyIdentifier the url of the key
     * @param keySignatureAlgorithm the signing algorithm that was used
     * @param result the result of using KeyVaultClient for signing the data
     * @param digestInfo the digest from the hashing
     */
    @Async
    public static Future<Boolean> KeyVaultVerifyREST(KeyVaultClient kvClient, String keyIdentifier, JsonWebKeySignatureAlgorithm keySignatureAlgorithm,
                                                     ServiceFuture<KeyOperationResult> result, byte[] digestInfo) throws InterruptedException, ExecutionException {

        //verify using asynchronous call passing in uri of the key, type of algorithm to use, digest, result of signing and null for callback function to handle responses
        ServiceFuture<KeyVerifyResult> b = kvClient.verifyAsync(keyIdentifier, keySignatureAlgorithm, digestInfo, result.get().result(),null);

        return new AsyncResult<Boolean>(b.get().value());
    }

}

class digestSignResult{
    byte[] digestInfo;
    ServiceFuture<KeyOperationResult> resultSign;

    public digestSignResult(byte[] digestInfo, ServiceFuture<KeyOperationResult> resultSign) {
        this.digestInfo = digestInfo;
        this.resultSign = resultSign;
    }

    public byte[] getDigestInfo() {
        return digestInfo;
    }

    public void setDigestInfo(byte[] digestInfo) {
        this.digestInfo = digestInfo;
    }

    public ServiceFuture<KeyOperationResult> getResultSign() {
        return resultSign;
    }

    public void setResultSign(ServiceFuture<KeyOperationResult> resultSign) {
        this.resultSign = resultSign;
    }
}
