package uk.gov.di.ipv.cri.passport.service;

import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.ssm.SsmClient;
import software.amazon.lambda.powertools.parameters.ParamManager;
import software.amazon.lambda.powertools.parameters.SSMProvider;

import java.io.ByteArrayInputStream;
import java.net.URI;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public class ConfigurationService {

    public static final int LOCALHOST_PORT = 4569;
    private static final String LOCALHOST_URI = "http://localhost:" + LOCALHOST_PORT;
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

    private String getParameterFromStoreUsingEnv(String environmentVariable) {
        return ssmProvider.get(System.getenv(environmentVariable));
    }

    private Certificate getCertificateFromStoreUsingEnv(String environmentVariable)
            throws CertificateException {
        byte[] binaryCertificate =
                Base64.getDecoder().decode(getParameterFromStoreUsingEnv(environmentVariable));
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        return factory.generateCertificate(new ByteArrayInputStream(binaryCertificate));
    }

    private Key getKeyFromStoreUsingEnv(String environmentVariable)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] binaryKey =
                Base64.getDecoder().decode(getParameterFromStoreUsingEnv(environmentVariable));
        KeyFactory factory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(binaryKey);
        return factory.generatePrivate(privateKeySpec);
    }

    public Certificate getDcsEncryptionCert() throws CertificateException {
        return getCertificateFromStoreUsingEnv("DCS_ENCRYPTION_CERT_PARAM");
    }

    public Key getPassportCriEncryptionKey()
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        return getKeyFromStoreUsingEnv("PASSPORT_CRI_ENCRYPTION_KEY_PARAM");
    }

    public Key getPassportCriSigningKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
        return getKeyFromStoreUsingEnv("PASSPORT_CRI_SIGNING_KEY_PARAM");
    }

    public Key getPassportCriTlsKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
        return getKeyFromStoreUsingEnv("PASSPORT_CRI_TLS_KEY_PARAM");
    }

    public Certificate getPassportCriSigningCert() throws CertificateException {
        return getCertificateFromStoreUsingEnv("PASSPORT_CRI_SIGNING_CERT_PARAM");
    }

    public Certificate getPassportCriEncryptionCert() throws CertificateException {
        return getCertificateFromStoreUsingEnv("PASSPORT_CRI_SIGNING_CERT_PARAM");
    }

    public Certificate getPassportCriTlsCert() throws CertificateException {
        return getCertificateFromStoreUsingEnv("PASSPORT_CRI_TLS_CERT_PARAM");
    }

    public String getDCSPostUrl() {
        return getParameterFromStoreUsingEnv("DCS_POST_URL_PARAM");
    }
}
