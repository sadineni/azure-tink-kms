package org.apache.tink.azurekms.crypto.certs;

import com.azure.security.keyvault.certificates.CertificateClient;
import com.azure.security.keyvault.secrets.SecretClient;
import com.google.crypto.tink.Aead;
import org.apache.commons.collections4.map.PassiveExpiringMap;

import javax.crypto.Cipher;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * A {@link Aead} that forwards encryption/decryption requests to certificate <a
 * href="https://azure.microsoft.com/en-us/services/key-vault/">AZURE KMS</a>.
 *
 * Caches keys based on TTL defined for cache expiration.
 */
public final class AzureKmsWithCertificateAead implements Aead {

    private static final String ALGORITHM = "RSA";
    private final CertificateClient certificateClient;
    private final SecretClient secretClient;
    private String certificateName;
    private final PassiveExpiringMap<CertificateKeyType, Key> keyCache;

    /**
     * Constructor
     *
     * @param certificateClient - kms certificate client
     * @param secretClient      - kms secret client
     * @param certificateName   - certificate name
     * @param keyCacheTTL       - TTL for key cache.
     */
    public AzureKmsWithCertificateAead(CertificateClient certificateClient, SecretClient secretClient, String certificateName, long keyCacheTTL) throws Exception {
        this.certificateClient = certificateClient;
        this.secretClient = secretClient;
        this.certificateName = certificateName;
        this.keyCache = new PassiveExpiringMap<>(keyCacheTTL);
    }

    /**
     * Look up private key by certificate name.
     *
     * @param certificateName - certificate name
     * @return
     * @throws Exception
     */
    private PrivateKey lookupPrivateKey(String certificateName)  throws Exception {
        if(keyCache.containsKey(CertificateKeyType.PRIVATE_KEY)) {
            return (PrivateKey) keyCache.get(CertificateKeyType.PRIVATE_KEY);
        }
        byte[] keyInfo = secretClient.getSecret(certificateName).getValue().getBytes(StandardCharsets.UTF_8);
        KeyStore store = KeyStore.getInstance("PKCS12");
        store.load(new ByteArrayInputStream(Base64.getDecoder().decode(keyInfo)), "".toCharArray());
        byte[] key = store.getKey(store.aliases().nextElement(), "".toCharArray()).getEncoded();
        keyCache.put(CertificateKeyType.PRIVATE_KEY, KeyFactory.getInstance(ALGORITHM).generatePrivate(new PKCS8EncodedKeySpec(key)));
        return (PrivateKey) keyCache.get(CertificateKeyType.PRIVATE_KEY);
    }

    /**
     * Look up public key by certificate name.
     *
     * @param certificateName   - name of certificate.
     * @return public key
     * @throws Exception
     */
    private PublicKey lookupPublicKey(String certificateName) throws Exception {
        if(keyCache.containsKey(CertificateKeyType.PUBLIC_KEY)) {
            return (PublicKey) keyCache.get(CertificateKeyType.PUBLIC_KEY);
        }
        byte[] cerContent = certificateClient.getCertificate(certificateName).getCer();
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(cerContent));
        byte[] keyBytes = cert.getPublicKey().getEncoded();
        keyCache.put(CertificateKeyType.PUBLIC_KEY, KeyFactory.getInstance(ALGORITHM).generatePublic(new X509EncodedKeySpec(keyBytes)));
        return (PublicKey) keyCache.get(CertificateKeyType.PUBLIC_KEY);
    }

    @Override
    public byte[] encrypt(final byte[] plaintext, final byte[] associatedData) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        try {
            cipher.init(Cipher.ENCRYPT_MODE, lookupPublicKey(certificateName));
        } catch (Exception e) {
            throw new GeneralSecurityException(e);
        }
        byte[] encryptedBytes = cipher.doFinal(plaintext);
        return encryptedBytes;
    }

    @Override
    public byte[] decrypt(final byte[] ciphertext, final byte[] associatedData) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        try {
            cipher.init(Cipher.DECRYPT_MODE, lookupPrivateKey(certificateName));
        } catch (Exception e) {
            throw new GeneralSecurityException(e);
        }
        byte[] decryptedBytes = cipher.doFinal(ciphertext);
        return decryptedBytes;
    }

    enum CertificateKeyType {
        PRIVATE_KEY, PUBLIC_KEY;
    }
}
