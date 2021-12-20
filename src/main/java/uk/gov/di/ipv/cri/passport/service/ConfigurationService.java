package uk.gov.di.ipv.cri.passport.service;

import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClientBuilder;
import com.amazonaws.services.kms.model.GetPublicKeyRequest;
import com.amazonaws.services.kms.model.GetPublicKeyResult;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.ssm.SsmClient;
import software.amazon.lambda.powertools.parameters.ParamManager;
import software.amazon.lambda.powertools.parameters.SSMProvider;
import uk.gov.di.ipv.cri.passport.domain.Thumbprints;

import java.io.ByteArrayInputStream;
import java.net.URI;
import java.security.Key;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public class ConfigurationService {

    public static final int LOCALHOST_PORT = 4569;
    private static final String LOCALHOST_URI = "http://localhost:" + LOCALHOST_PORT;
    private static final String IS_LOCAL = "IS_LOCAL";
    public static final String KEY_ID = "5b32227e-b835-4b4a-a15d-4c050ca01af4";
    public static final String PASSPORT_POST_URI = "/checks/passport";

    private final SSMProvider ssmProvider;
    private final AWSKMS kmsClient = AWSKMSClientBuilder.defaultClient();

    public ConfigurationService(SSMProvider ssmProvider) {
        this.ssmProvider = ssmProvider;
    }

    public ConfigurationService() {
        if (isRunningLocally()) {
            this.ssmProvider =
                ParamManager.getSsmProvider(
                    SsmClient.builder()
                        .endpointOverride(URI.create(LOCALHOST_URI))
                        .region(Region.EU_WEST_2)
                        .build());
        } else {
            this.ssmProvider = ParamManager.getSsmProvider();
        }
    }

    private String getParameterFromStoreUsingEnv(String environmentVariable) {
        return ssmProvider.get(System.getenv(environmentVariable));
    }

    private Certificate getCertificateUsingEnv(String environmentVariable)
        throws CertificateException {
        var value = ssmProvider.get(System.getenv(environmentVariable));
        var decoded = Base64.getDecoder().decode(value);
        var factory = CertificateFactory.getInstance("X.509");
        return factory.generateCertificate(new ByteArrayInputStream(decoded));
    }

    private Key getKeyUsingEnv(String environmentVariable)
        throws NoSuchAlgorithmException, InvalidKeySpecException {
        var factory = KeyFactory.getInstance("RSA");
        var value = ssmProvider.get(System.getenv(environmentVariable));
        var decoded = Base64.getDecoder().decode(value);
        var privKeySpec = new PKCS8EncodedKeySpec(decoded);
        return factory.generatePrivate(privKeySpec);
    }


    public SSMProvider getSsmProvider() {
        return ssmProvider;
    }

    public boolean isRunningLocally() {
        return Boolean.parseBoolean(System.getenv(IS_LOCAL));
    }

    public Certificate getDcsIntegrationEncryptionCert() throws CertificateException {
        return getCertificateUsingEnv("DCS_INTEGRATION_ENCRYPTION_CERT_PARAM");
    }

    public Certificate getDcsEncryptionCert() throws CertificateException {
        return getCertificateUsingEnv("DCS_ENCRYPTION_CERT_PARAM");
    }

    public String getDcsEncryptionKey() {
        return getParameterFromStoreUsingEnv("DCS_ENCRYPTION_KEY_PARAM");
    }

    public Certificate getDcsSigningCert() throws CertificateException {
        return getCertificateUsingEnv("DCS_SIGNING_CERT_PARAM");
    }

    public GetPublicKeyResult getDcsSigningKey()
        throws NoSuchAlgorithmException, InvalidKeySpecException {
        return kmsClient.getPublicKey(new GetPublicKeyRequest().withKeyId(KEY_ID));
    }

    public Certificate getDcsTlsCert() throws CertificateException {
        return getCertificateUsingEnv("DCS_TLS_CERT_PARAM");
    }

    public String getPassportPostUri() {
        return PASSPORT_POST_URI;
    }

    public String getDcsTlsKey() {
        return getParameterFromStoreUsingEnv("DCS_TLS_KEY_PARAM");
    }

    public Thumbprints makeThumbprints() throws CertificateException, NoSuchAlgorithmException {
        var cert = getDcsSigningCert();
        return new Thumbprints(
            getThumbprint((X509Certificate) cert, "SHA-1"),
            getThumbprint((X509Certificate) cert, "SHA-256")
        );
    }

    public String getThumbprint(X509Certificate cert, String hashAlg)
        throws NoSuchAlgorithmException, CertificateEncodingException {
        MessageDigest md = MessageDigest.getInstance(hashAlg);
        byte[] der = cert.getEncoded();
        md.update(der);
        byte[] digest = md.digest();
        return Base64.getUrlEncoder().encodeToString(digest).replaceAll("=", "");
    }

    public String getDcsSigningKeyId() {
        return ssmProvider.get(System.getenv("DCS_SIGNING_KEY_ID"));
    }
}
