package uk.gov.di.ipv.cri.passport.library.service;

import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.ssm.SsmClient;
import software.amazon.lambda.powertools.parameters.ParamManager;
import software.amazon.lambda.powertools.parameters.SSMProvider;
import uk.gov.di.ipv.cri.passport.library.domain.Thumbprints;

import java.io.ByteArrayInputStream;
import java.net.URI;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Optional;

public class ConfigurationService {

    public static final int LOCALHOST_PORT = 4567;
    private static final String LOCALHOST_URI = "http://localhost:" + LOCALHOST_PORT;
    private static final long DEFAULT_BEARER_TOKEN_TTL_IN_SECS = 3600L;
    private static final String IS_LOCAL = "IS_LOCAL";

    private final SSMProvider ssmProvider;

    public ConfigurationService(SSMProvider ssmProvider) {
        this.ssmProvider = ssmProvider;
    }

    public ConfigurationService() {
        if (isRunningLocally()) {
            this.ssmProvider =
                    ParamManager.getSsmProvider(
                            SsmClient.builder()
                                    .endpointOverride(URI.create(LOCALHOST_URI))
                                    .httpClient(UrlConnectionHttpClient.create())
                                    .region(Region.EU_WEST_2)
                                    .build());
        } else {
            this.ssmProvider = ParamManager.getSsmProvider();
        }
    }

    public SSMProvider getSsmProvider() {
        return ssmProvider;
    }

    public boolean isRunningLocally() {
        return Boolean.parseBoolean(System.getenv(IS_LOCAL));
    }

    public String getDcsResponseTableName() {
        return System.getenv("DCS_RESPONSE_TABLE_NAME");
    }

    public String getAuthCodesTableName() {
        return System.getenv("CRI_PASSPORT_AUTH_CODES_TABLE_NAME");
    }

    public String getAccessTokensTableName() {
        return System.getenv("CRI_PASSPORT_ACCESS_TOKENS_TABLE_NAME");
    }

    private String getParameterFromStoreUsingEnv(String environmentVariable) {
        return ssmProvider.get(System.getenv(environmentVariable));
    }

    private String getParameterFromStore(String parameterName) {
        return ssmProvider.get(parameterName);
    }

    private String getDecryptedParameterFromStoreUsingEnv(String environmentVariable) {
        return ssmProvider.withDecryption().get(System.getenv(environmentVariable));
    }

    private Certificate getCertificateFromStoreUsingEnv(String environmentVariable)
            throws CertificateException {
        byte[] binaryCertificate =
                Base64.getDecoder().decode(getParameterFromStoreUsingEnv(environmentVariable));
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        return factory.generateCertificate(new ByteArrayInputStream(binaryCertificate));
    }

    private Certificate getCertificateFromStore(String parameteraName)
            throws CertificateException {
        byte[] binaryCertificate =
                Base64.getDecoder().decode(getParameterFromStore(parameteraName));
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        return factory.generateCertificate(new ByteArrayInputStream(binaryCertificate));
    }

    private PrivateKey getKeyFromStoreUsingEnv(String environmentVariable)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] binaryKey =
                Base64.getDecoder()
                        .decode(getDecryptedParameterFromStoreUsingEnv(environmentVariable));
        KeyFactory factory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(binaryKey);
        return factory.generatePrivate(privateKeySpec);
    }

    public Certificate getDcsEncryptionCert() throws CertificateException {
        return getCertificateFromStoreUsingEnv("DCS_ENCRYPTION_CERT_PARAM");
    }

    public Certificate getDcsSigningCert() throws CertificateException {
        return getCertificateFromStoreUsingEnv("DCS_SIGNING_CERT_PARAM");
    }

    public PrivateKey getPassportCriPrivateKey()
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        return getKeyFromStoreUsingEnv("PASSPORT_CRI_ENCRYPTION_KEY_PARAM");
    }

    public Certificate getPassportCriEncryptionCert() throws CertificateException {
        return getCertificateFromStoreUsingEnv("PASSPORT_CRI_ENCRYPTION_CERT_PARAM");
    }

    public PrivateKey getPassportCriSigningKey()
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        return getKeyFromStoreUsingEnv("PASSPORT_CRI_SIGNING_KEY_PARAM");
    }

    public PrivateKey getPassportCriTlsKey()
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        return getKeyFromStoreUsingEnv("PASSPORT_CRI_TLS_KEY_PARAM");
    }

    public Certificate getPassportCriSigningCert() throws CertificateException {
        return getCertificateFromStoreUsingEnv("PASSPORT_CRI_SIGNING_CERT_PARAM");
    }

    public Certificate getPassportCriTlsCert() throws CertificateException {
        return getCertificateFromStoreUsingEnv("PASSPORT_CRI_TLS_CERT_PARAM");
    }

    public Certificate[] getDcsTlsCertChain() throws CertificateException {
        return new Certificate[] {
            getCertificateFromStoreUsingEnv("DCS_TLS_ROOT_CERT_PARAM"),
            getCertificateFromStoreUsingEnv("DCS_TLS_INTERMEDIATE_CERT_PARAM")
        };
    }

    public PrivateKey getStubDcsSigningKey()
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        return getKeyFromStoreUsingEnv("STUB_DCS_SIGNING_KEY_PARAM");
    }

    public PrivateKey getStubDcsEncryptionKey()
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        return getKeyFromStoreUsingEnv("STUB_DCS_ENCRYPTION_KEY_PARAM");
    }

    public String getDCSPostUrl() {
        return getParameterFromStoreUsingEnv("DCS_POST_URL_PARAM");
    }

    public Thumbprints makeThumbprints() throws CertificateException, NoSuchAlgorithmException {
        var cert = getPassportCriSigningCert();
        return new Thumbprints(
                getThumbprint((X509Certificate) cert, "SHA-1"),
                getThumbprint((X509Certificate) cert, "SHA-256"));
    }

    public String getThumbprint(X509Certificate cert, String hashAlg)
            throws NoSuchAlgorithmException, CertificateEncodingException {
        MessageDigest md = MessageDigest.getInstance(hashAlg);
        byte[] der = cert.getEncoded();
        md.update(der);
        byte[] digest = md.digest();
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }

    public long getBearerAccessTokenTtl() {
        return Optional.ofNullable(System.getenv("BEARER_TOKEN_TTL"))
                .map(Long::valueOf)
                .orElse(DEFAULT_BEARER_TOKEN_TTL_IN_SECS);
    }

    public URI getDynamoDbEndpointOverride() {
        String dynamoDbEndpointOverride = System.getenv("DYNAMODB_ENDPOINT_OVERRIDE");
        if (dynamoDbEndpointOverride != null && !dynamoDbEndpointOverride.isEmpty()) {
            return URI.create(System.getenv("DYNAMODB_ENDPOINT_OVERRIDE"));
        }
        return null;
    }

    public Certificate getClientCert(String clientId) throws CertificateException {
        return getCertificateFromStore(String.format("/%s/cri/passport/config/%s/signing_cert",
                System.getenv("ENVIRONMENT"), clientId));
    }

}
