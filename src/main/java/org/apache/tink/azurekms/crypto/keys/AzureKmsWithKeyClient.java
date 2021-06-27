
package org.apache.tink.azurekms.crypto.keys;

import com.azure.core.credential.TokenCredential;
import com.azure.core.http.HttpPipeline;
import com.azure.core.http.HttpPipelineBuilder;
import com.azure.core.http.policy.ExponentialBackoff;
import com.azure.core.http.policy.RetryPolicy;
import com.azure.identity.ClientSecretCredentialBuilder;
import com.azure.identity.DefaultAzureCredentialBuilder;
import com.azure.security.keyvault.keys.cryptography.CryptographyClient;
import com.azure.security.keyvault.keys.cryptography.CryptographyClientBuilder;
import com.azure.security.keyvault.keys.cryptography.models.EncryptionAlgorithm;
import com.azure.security.keyvault.keys.implementation.KeyVaultCredentialPolicy;
import com.google.auto.service.AutoService;
import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KmsClient;
import com.google.crypto.tink.KmsClients;
import com.google.crypto.tink.subtle.Validators;
import org.apache.commons.lang3.Validate;

import java.security.GeneralSecurityException;
import java.time.Duration;
import java.util.Optional;

/**
 * An implementation of {@link KmsClient} for <a href="https://azure.microsoft.com/en-us/services/key-vault/">AZURE KMS</a>.
 */
@AutoService(KmsClient.class)
public final class AzureKmsWithKeyClient implements KmsClient {
    public static final String PREFIX = "azure-kms://";
    private String keyUri;
    private TokenCredential provider;
    private static final EncryptionAlgorithm DEFAULT_ENCRYPTION_ALGORITHM = EncryptionAlgorithm.RSA_OAEP_256;
    private EncryptionAlgorithm algorithm = DEFAULT_ENCRYPTION_ALGORITHM;

    /**
     * Constructs a specific AzureKmsClient that is bound to a single key identified by {@code uri}.
     */

    public AzureKmsWithKeyClient(String uri) {
        this(uri, DEFAULT_ENCRYPTION_ALGORITHM);
    }

    /**
     * Constructs a specific AzureKmsClient that is bound to a single key identified by {@code uri} and specified {@code EncryptionAlgorithm}.
     *
     * @param uri
     * @param algorithm
     */
    public AzureKmsWithKeyClient(String uri, EncryptionAlgorithm algorithm) {
        Validate.notBlank(uri, "uri can't be blank or null");
        Validate.notNull(algorithm, "EncryptionAlgorithm can't be null");
        if (!uri.toLowerCase().startsWith(PREFIX)) {
            throw new IllegalArgumentException("key URI must starts with " + PREFIX);
        }
        this.keyUri = uri;
        this.algorithm = algorithm;
    }

    /**
     * @return @return true either if this client is a generic one and uri starts with {@link
     * AzureKmsWithKeyClient#PREFIX}, or the client is a specific one that is bound to the key identified
     * by {@code uri}.
     */
    @Override
    public boolean doesSupport(String uri) {
        if (this.keyUri != null && this.keyUri.equals(uri)) {
            return true;
        }
        return this.keyUri == null && uri.toLowerCase().startsWith(PREFIX);
    }

    /**
     * Loads AZURE credentials from a properties file. Not supported yet.
     */

    @Override
    public KmsClient withCredentials(String credentialPath) throws GeneralSecurityException {
        throw new UnsupportedOperationException("Not supported yet");
    }

    /**
     * Loads credentials using {@code DefaultAzureCredentialBuilder}
     * Creates default DefaultAzureCredential instance. Uses AZURE_CLIENT_ID,
     * AZURE_CLIENT_SECRET, and AZURE_TENANT_ID environment variables to create a ClientSecretCredential.
     * If these environment variables are not available, then this will use the Shared MSAL token cache.
     *
     * @return KmsClient object
     * @throws GeneralSecurityException
     */
    @Override
    public KmsClient withDefaultCredentials() throws GeneralSecurityException {
        return withCredentialsProvider(new DefaultAzureCredentialBuilder().build());
    }

    /**
     * loads credentials using provided {@code TokenCredential}
     *
     * @return KmsClient object
     * @throws GeneralSecurityException
     */
    public KmsClient withCredentialsProvider(TokenCredential provider) throws GeneralSecurityException {
        this.provider = provider;
        return this;
    }

    /**
     * Returns {@code AzureKmsAead} for the url provided.
     *
     * @param uri - azure keyvault key uri
     * @return Aead
     * @throws GeneralSecurityException
     */
    @Override
    public Aead getAead(String uri) throws GeneralSecurityException {
        if (this.keyUri != null && !this.keyUri.equals(uri)) {
            throw new GeneralSecurityException(
                    String.format(
                            "this client is bound to %s, cannot load keys bound to %s", this.keyUri, uri));
        }
        String keyUri = Validators.validateKmsKeyUriAndRemovePrefix(PREFIX, uri);
        // retry policy defined as per guidelines from MS
        // https://docs.microsoft.com/en-us/azure/key-vault/general/overview-throttling#recommended-client-side-throttling-method
        HttpPipeline pipeline = new HttpPipelineBuilder()
                .policies(new KeyVaultCredentialPolicy(provider == null
                                ? new DefaultAzureCredentialBuilder().build() : provider),
                        new RetryPolicy(new ExponentialBackoff(5, Duration.ofSeconds(1), Duration.ofSeconds(16))))
                .build();
        CryptographyClient client = new CryptographyClientBuilder()
                .pipeline(pipeline)
                .keyIdentifier(keyUri)
                .buildClient();
        return new AzureKmsWithKeyAead(client, this.algorithm);
    }

    /**
     * Creates and registers a {@link #AzureKmsWithKeyClient} with the Tink runtime.
     * <p>
     * Utilize {@link #AzureKmsWithKeyClient(String)} to create client. loads credentials using
     * {@link DefaultAzureCredentialBuilder} which expects credentials to provided as environment variables.
     *
     * @throws GeneralSecurityException if keyUrl is missing
     */
    public static void register(Optional<String> keyUri) throws GeneralSecurityException {
        AzureKmsWithKeyClient client;
        if (keyUri.isPresent()) {
            client = new AzureKmsWithKeyClient(keyUri.get());
        } else {
            throw new GeneralSecurityException("key url missing while registering KmsClient");
        }
        client.withDefaultCredentials();
        KmsClients.add(client);
    }

    /**
     * Creates and registers a {@link #AzureKmsWithKeyClient} with the Tink runtime.
     *
     * @param keyUri       - azure keyvault key uri
     * @param tenantId     - keyvault  tenantId
     * @param clientId     - keyvault  clientId
     * @param clientSecret - keyvault  clientSecret
     * @throws GeneralSecurityException if keyUrl is missing
     */
    public static void register(Optional<String> keyUri, Optional<String> tenantId, Optional<String> clientId, Optional<String> clientSecret) throws GeneralSecurityException {

        Validate.notBlank(tenantId.get());
        Validate.notBlank(clientId.get());
        Validate.notBlank(clientSecret.get());

        AzureKmsWithKeyClient client;
        if (keyUri.isPresent()) {
            client = new AzureKmsWithKeyClient(keyUri.get());
        } else {
            throw new GeneralSecurityException("key url missing while registering KmsClient");
        }
        client.withCredentialsProvider(new ClientSecretCredentialBuilder()
                .clientId(clientId.get())
                .tenantId(tenantId.get())
                .clientSecret(clientSecret.get()).build());
        KmsClients.add(client);
    }
}
