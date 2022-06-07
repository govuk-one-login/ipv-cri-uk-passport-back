package uk.gov.di.ipv.cri.passport.library.service;

import com.nimbusds.jose.jwk.ECKey;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.ssm.SsmClient;
import software.amazon.awssdk.services.ssm.model.ParameterNotFoundException;
import software.amazon.lambda.powertools.parameters.ParamManager;
import software.amazon.lambda.powertools.parameters.SSMProvider;
import uk.gov.di.ipv.cri.passport.library.domain.Thumbprints;
import uk.gov.di.ipv.cri.passport.library.exceptions.UnknownClientException;

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
import java.text.ParseException;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

public class ConfigurationService {

    public static final int LOCALHOST_PORT = 4567;
    private static final String LOCALHOST_URI = "http://localhost:" + LOCALHOST_PORT;
    private static final long DEFAULT_BEARER_TOKEN_TTL_IN_SECS = 3600L;
    private static final String IS_LOCAL = "IS_LOCAL";
    private static final String CLIENT_REDIRECT_URL_SEPARATOR = ",";
    public static final String CREDENTIAL_ISSUERS_CONFIG_PARAM_PREFIX =
            "CREDENTIAL_ISSUERS_CONFIG_PARAM_PREFIX";

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

    public String getSqsAuditEventQueueUrl() {
        return System.getenv("SQS_AUDIT_EVENT_QUEUE_URL");
    }

    private String getParameterFromStoreUsingEnv(String environmentVariable) {
        return ssmProvider.get(System.getenv(environmentVariable));
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

    public Certificate getJARSigningCert() throws CertificateException {
        return getCertificateFromStoreUsingEnv("JAR_SIGNING_CERT_PARAM");
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

    public ECKey getClientSigningPublicJwk(String clientId) throws ParseException {
        return ECKey.parse(
                ssmProvider.get(
                        String.format(
                                "%s/%s/signingPublicJwk",
                                System.getenv(CREDENTIAL_ISSUERS_CONFIG_PARAM_PREFIX), clientId)));
    }

    public List<String> getClientRedirectUrls(String clientId) throws UnknownClientException {
        String redirectUrlStrings =
                ssmProvider.get(
                        String.format(
                                "%s/%s/jwtAuthentication/validRedirectUrls",
                                System.getenv(CREDENTIAL_ISSUERS_CONFIG_PARAM_PREFIX), clientId));

        return Arrays.asList(redirectUrlStrings.split(CLIENT_REDIRECT_URL_SEPARATOR));
    }

    public String getClientIssuer(String clientId) throws UnknownClientException {
        return ssmProvider.get(
                String.format(
                        "%s/%s/jwtAuthentication/issuer",
                        System.getenv(CREDENTIAL_ISSUERS_CONFIG_PARAM_PREFIX), clientId));
    }

    public String getAudienceForClients() {
        return getParameterFromStoreUsingEnv("PASSPORT_CRI_CLIENT_AUDIENCE");
    }

    public String getClientAuthenticationMethod(String clientId) throws ParameterNotFoundException {
        return ssmProvider.get(
                String.format(
                        "%s/%s/jwtAuthentication/authenticationMethod",
                        System.getenv(CREDENTIAL_ISSUERS_CONFIG_PARAM_PREFIX), clientId));
    }

    public String getVerifiableCredentialIssuer() {
        return getParameterFromStoreUsingEnv("VERIFIABLE_CREDENTIAL_ISSUER_PARAM");
    }

    public String getMaxClientAuthTokenTtl() {
        return getParameterFromStoreUsingEnv("PASSPORT_CRI_CLIENT_AUTH_MAX_TTL");
    }

    public String getVerifiableCredentialKmsSigningKeyId() {
        return ssmProvider.get(System.getenv("VERIFIABLE_CREDENTIAL_SIGNING_KEY_ID_PARAM"));
    }

    public String getJarKmsEncryptionKeyId() {
        return ssmProvider.get(System.getenv("JAR_ENCRYPTION_KEY_ID_PARAM"));
    }

    public String getJarKmsPublickKey() {
        return ssmProvider.get(System.getenv("JAR_KMS_PUBLIC_KEY_PARAM"));
    }

    public long maxJwtTtl() {
        return Long.parseLong(ssmProvider.get(System.getenv("MAX_JWT_TTL")));
    }

    public long getBackendSessionTtl() {
        return Long.parseLong(
                ssmProvider.get(
                        String.format(
                                "/%s/credentialIssuers/ukPassport/self/backendSessionTtl",
                                System.getenv("ENVIRONMENT"))));
    }
}
