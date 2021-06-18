package com.microsoft;

import com.azure.resourcemanager.keyvault.models.Vault;
import com.azure.security.keyvault.keys.cryptography.CryptographyAsyncClient;
import com.azure.security.keyvault.keys.cryptography.models.SignResult;

import com.azure.security.keyvault.keys.cryptography.models.SignatureAlgorithm;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.AsyncResult;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.Security;
import java.security.Signature;
import java.security.PublicKey;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicReference;

@Component
public class SignVerifySamplesKeyVault {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Use cryptographyAsyncClient to sign data
     * Get the public key, and use it to validate the signature
     * @param cryptographyAsyncClient Use cryptographyAsyncClient to sign data
     * @param shaType the SHA type to use
     * @param keyIdentifier the url of the key
     */
    @Async
    public static digestSignResult KeyVaultSign(CryptographyAsyncClient cryptographyAsyncClient, String shaType, String keyIdentifier) throws
            NoSuchAlgorithmException, NoSuchProviderException {

        MessageDigest md = MessageDigest.getInstance(shaType, BouncyCastleProvider.PROVIDER_NAME);

        String key = keyIdentifier.substring(keyIdentifier.lastIndexOf('/') + 1);
        System.out.println("The key is: " + key);

        md.update(key.getBytes());
        byte[] digest = md.digest();
        digestSignResult digestSignResult = new digestSignResult();
        SignatureAlgorithm rsnull = SignatureAlgorithm.fromString("RSNULL");

        //use cryptographyClient to to asynchronous signing passing in the uri of the key, type of algorithm to use, digest and null for callback function to handle responses
        return  cryptographyAsyncClient.sign(rsnull, digest).flatMap(signResult -> {
            digestSignResult.setResultSign(signResult);
            digestSignResult.setDigestInfo(digest);
            return Mono.just(digestSignResult);
        }).block();
    }

    /**
     * Use Java Security to verify
     * Get the public key, and use it to validate the signature
     * @param vault Use vault to find key
     * @param keyName Find key by keyName
     * @param digestSignResult
     *            digestInfo the digest from completing the hash
     *            signResult the result of the signing using asynchronous call using cryptographyAsyncClient
     */
    @Async
    public static Future<Boolean> KeyVaultVerify(Vault vault, String keyName, digestSignResult digestSignResult) throws InvalidKeyException, SignatureException, NoSuchAlgorithmException, NoSuchProviderException {

        KeyPair keyPair = vault.keys().getByNameAndVersion(keyName, null).getJsonWebKey().toRsa();
        PublicKey publicKey = keyPair.getPublic();

        Signature sig = Signature.getInstance("NONEwithRSA", BouncyCastleProvider.PROVIDER_NAME);
        sig.initVerify(publicKey);
        sig.update(digestSignResult.digestInfo);
        Boolean verifies = sig.verify(digestSignResult.getSignResult().getSignature());
        return new AsyncResult<Boolean>(verifies);
    }

    /**
     * Use REST to verify SHA256
     * Get the public key, and use it to validate the signature
     * Using REST client also assumes that verify policy is allowed on the vault, if not enabled then please enable
     * @param cryptographyAsyncClient
     *            Use cryptographyAsyncClient to verify
     * @param digestSignResult
     *            signResult:the result of using cryptographyAsyncClient for signing the data
     *            digestInfo:the digest from the hashing
     */
    @Async
    public static Future<Boolean> KeyVaultVerifyREST(CryptographyAsyncClient cryptographyAsyncClient, digestSignResult digestSignResult) throws InterruptedException, ExecutionException {
        AtomicReference<AsyncResult<Boolean>> booleanAsyncResult = new AtomicReference<>(new AsyncResult<>(null));

        //verify using asynchronous call passing in uri of the key, type of algorithm to use, digest, result of signing and null for callback function to handle responses
        return  cryptographyAsyncClient
                .verify(SignatureAlgorithm.RS256, digestSignResult.getDigestInfo(), digestSignResult.getSignResult().getSignature())
                .flatMap(verifyResult -> {
                    booleanAsyncResult.set(new AsyncResult<>(verifyResult.isValid()));
                    return Mono.just(booleanAsyncResult.get());
                }).block();
    }
}

class digestSignResult{
    byte[] digestInfo;
    SignResult signResult;
    public digestSignResult() {

    }

    public byte[] getDigestInfo() {
        return digestInfo;
    }

    public void setDigestInfo(byte[] digestInfo) {
        this.digestInfo = digestInfo;
    }

    public SignResult getSignResult() {
        return signResult;
    }

    public void setResultSign(SignResult signResult) {
        this.signResult = signResult;
    }
}
