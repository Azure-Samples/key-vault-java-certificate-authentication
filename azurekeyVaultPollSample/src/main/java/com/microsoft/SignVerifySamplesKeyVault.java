package com.microsoft;

import com.azure.security.keyvault.keys.cryptography.CryptographyAsyncClient;
import com.azure.security.keyvault.keys.cryptography.models.SignResult;
import com.azure.security.keyvault.keys.cryptography.models.SignatureAlgorithm;
import com.azure.security.keyvault.keys.cryptography.models.VerifyResult;
import com.azure.security.keyvault.keys.models.KeyVaultKey;
import com.azure.security.keyvault.keys.models.KeyVaultKeyIdentifier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.scheduling.annotation.Async;
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

@Component
public class SignVerifySamplesKeyVault {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Use a {@link CryptographyAsyncClient} to sign data.
     * The public part of a cryptographic key is required to sign the data.
     * @param cryptographyAsyncClient The {@link CryptographyAsyncClient} used to perform the data signing operation.
     * @param digestAlgorithm The name of digest algorithm to use for signing the data.
     * @param keyIdentifier The Key Vault identifier for key to use for signing the data.
     */
    @Async
    public static DigestSignResult keyVaultSign(CryptographyAsyncClient cryptographyAsyncClient, String digestAlgorithm, String keyIdentifier) throws
            NoSuchAlgorithmException {

        MessageDigest md = MessageDigest.getInstance(digestAlgorithm);

        String keyName = new KeyVaultKeyIdentifier(keyIdentifier).getName();
        System.out.println("The key is: " + keyName);

        md.update(keyName.getBytes());
        byte[] digest = md.digest();
        DigestSignResult digestSignResult = new DigestSignResult();
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.fromString("RSNULL");
        // Use the CryptographyAsyncClient to asynchronously signing the data by providing the signing algorithm to use and the digest.
        return cryptographyAsyncClient.sign(signatureAlgorithm, digest)
                .flatMap(signResult -> {
                    digestSignResult.setSignResult(signResult);
                    digestSignResult.setDigestInfo(digest);
                    return Mono.just(digestSignResult);
                }).block();
    }

    /**
     * Uses Java Security to verify the contents of a given signature.
     * The public part of a cryptographic key is required to perform this operation.
     * @param keyVaultKey The key that will be used to verify the contents of the provided signature.
     * @param digestSignResult An object containing the digest from completing the hash of the data and the SignResult
     * obtained by using a {@link CryptographyAsyncClient} for signing it.
     */
    @Async
    public static Boolean keyVaultVerify(KeyVaultKey keyVaultKey, DigestSignResult digestSignResult) throws InvalidKeyException, SignatureException, NoSuchAlgorithmException, NoSuchProviderException {

        KeyPair keyPair = keyVaultKey.getKey().toRsa();
        PublicKey publicKey = keyPair.getPublic();

        Signature sig = Signature.getInstance("NONEwithRSA", BouncyCastleProvider.PROVIDER_NAME);
        sig.initVerify(publicKey);
        sig.update(digestSignResult.digestInfo);
        return sig.verify(digestSignResult.getSignResult().getSignature());
    }

    /**
     * Uses Java Security to verify the contents of a given signature.
     * The public part of a cryptographic key is required to perform this operation.
     * Use a {@link CryptographyAsyncClient} to verify the data using the SHA-256 algorithm via the Key Vault service.
     * The public part of a cryptographic key is required to perform this operation.
     * Using this client also requires the key it was created with to have the verify permission on the vault. Please, make sure it is enabled.
     * @param cryptographyAsyncClient The {@link CryptographyAsyncClient} used to perform the verify operation.
     * @param digestSignResult An object containing the digest from completing the hash of the data and the SignResult
     * obtained by using a {@link CryptographyAsyncClient} for signing it.
     */
    @Async
    public static Mono<VerifyResult> keyVaultVerifyREST(CryptographyAsyncClient cryptographyAsyncClient, DigestSignResult digestSignResult) {
        // Use the CryptographyAsyncClient to asynchronously verify the signature by providing signing algorithm to use, digest and the signature itself.
        return cryptographyAsyncClient.verify(SignatureAlgorithm.RS256, digestSignResult.getDigestInfo(),
                digestSignResult.getSignResult().getSignature());
    }
}

class DigestSignResult{
    byte[] digestInfo;
    SignResult signResult;
    public DigestSignResult() {

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

    public void setSignResult(SignResult signResult) {
        this.signResult = signResult;
    }
}
