package org.apache.tink.azurekms.crypto.keys;

import com.azure.security.keyvault.keys.cryptography.CryptographyClient;
import com.azure.security.keyvault.keys.cryptography.models.EncryptionAlgorithm;
import com.google.crypto.tink.Aead;

import java.security.GeneralSecurityException;

/**
 * A {@link Aead} that forwards encryption/decryption requests to a key in <a
 * href="https://azure.microsoft.com/en-us/services/key-vault/">AZURE KMS</a>.
 */
public final class AzureKmsWithKeyAead implements Aead {

    /** Azure crypto client */
    private final CryptographyClient kmsClient;

    /** Encryption algorithm */
    private final EncryptionAlgorithm algorithm;

    /**
     * Constructor
     *
     * @param kmsClient -  kms client
     * @param algorithm - algorithm
     */
    public AzureKmsWithKeyAead(CryptographyClient kmsClient, EncryptionAlgorithm algorithm) {
        this.kmsClient = kmsClient;
        this.algorithm = algorithm;
    }

    @Override
    public byte[] encrypt(final byte[] plaintext, final byte[] associatedData) throws GeneralSecurityException {
        return kmsClient.encrypt(this.algorithm, plaintext).getCipherText();
    }

    @Override
    public byte[] decrypt(final byte[] ciphertext, final byte[] associatedData)
            throws GeneralSecurityException {
        return kmsClient.decrypt(this.algorithm, ciphertext).getPlainText();
    }
}
