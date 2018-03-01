package com.microsoft;

import com.microsoft.aad.adal4j.AsymmetricKeyCredential;
import com.microsoft.aad.adal4j.AuthenticationContext;
import com.microsoft.aad.adal4j.AuthenticationResult;
import com.microsoft.azure.keyvault.KeyVaultClient;
import com.microsoft.azure.keyvault.authentication.KeyVaultCredentials;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Properties;
import java.util.concurrent.Executors;

public class JavaKeyVaultAuthenticator {

	/**
	 * Do certificate based authentication using pfx file
	 * 
	 * @param path
	 *            to pfx file
	 * @param pfxPassword
	 *            the password to the pfx file, this can be empty if thats the value
	 *            given when it was created
	 * @param clientId
	 *            also known as applicationId which is received after app
	 *            registration
	 */
	public KeyVaultClient getAuthentication(String path, String pfxPassword, String clientId)
			throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException,
			NoSuchProviderException, IOException {

		KeyCert certificateKey = readPfx(path, pfxPassword);

		PrivateKey privateKey = certificateKey.getKey();

		// Do certificate based authentication
		KeyVaultClient keyVaultClient = new KeyVaultClient(new KeyVaultCredentials() {

			@Override
			public String doAuthenticate(String authorization, String resource, String scope) {

				AuthenticationContext context;
				try {
					context = new AuthenticationContext(authorization, false, Executors.newFixedThreadPool(1));
					AsymmetricKeyCredential asymmetricKeyCredential = AsymmetricKeyCredential.create(clientId,
							privateKey, certificateKey.getCertificate());
					// pass null value for optional callback function and acquire access token
					AuthenticationResult result = context.acquireToken(resource, asymmetricKeyCredential, null).get();

					return result.getAccessToken();
				} catch (Exception e) {
					e.printStackTrace();
				}
				return "";
			}
		});
		return keyVaultClient;
	}

	/**
	 * Read pfx file and get privateKey
	 * 
	 * @param path
	 *            pfx file path
	 * @param password
	 *            the password to the pfx file
	 */
	public static KeyCert readPfx(String path, String password) throws NoSuchProviderException, KeyStoreException,
			IOException, NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException {

		try (FileInputStream stream = new FileInputStream(path)) {
			KeyCert keyCert = new KeyCert(null, null);

			boolean isAliasWithPrivateKey = false;

			// Access Java keystore
			final KeyStore store = KeyStore.getInstance("pkcs12", "SunJSSE");

			// Load Java Keystore with password for access
			store.load((InputStream) stream, password.toCharArray());

			// Iterate over all aliases to find the private key
			Enumeration<String> aliases = store.aliases();
			String alias = "";
			while (aliases.hasMoreElements()) {
				alias = aliases.nextElement();
				System.out.println(alias);
				// Break if alias refers to a private key because we want to use that
				// certificate
				if (isAliasWithPrivateKey = store.isKeyEntry(alias)) {
					break;
				}
			}

			if (isAliasWithPrivateKey) {
				// Retrieves the certificate from the Java keystore
				X509Certificate certificate = (X509Certificate) store.getCertificate(alias);
				System.out.println("the alias is: " + alias);

				// Retrieves the private key from the Java keystore
				PrivateKey key = (PrivateKey) store.getKey(alias, password.toCharArray());

				keyCert.setCertificate(certificate);
				keyCert.setKey(key);

				System.out.println("key in primary encoding format is: " + key.getEncoded());
			}
			return keyCert;
		}
	}

}

@Component
class KeyCert {

	X509Certificate certificate;
	PrivateKey key;

	public KeyCert(X509Certificate certificate, PrivateKey key) {
		this.certificate = certificate;
		this.key = key;
	}

	public X509Certificate getCertificate() {
		return certificate;
	}

	public void setCertificate(X509Certificate certificate) {
		this.certificate = certificate;
	}

	public PrivateKey getKey() {
		return key;
	}

	public void setKey(PrivateKey key) {
		this.key = key;
	}
}
