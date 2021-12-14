package uk.gov.di.ipv.cri.passport.service;

import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.ssm.SsmClient;
import software.amazon.lambda.powertools.parameters.ParamManager;
import software.amazon.lambda.powertools.parameters.SSMProvider;

import java.net.URI;

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

    private String getParameterFromStoreUsingEnv(String environmentVariable) {
        return ssmProvider.get(System.getenv(environmentVariable));
    }

    public SSMProvider getSsmProvider() {
        return ssmProvider;
    }

    public boolean isRunningLocally() {
        return Boolean.parseBoolean(System.getenv(IS_LOCAL));
    }

    public String getDcsIntegrationEncryptionCert() {
        return getParameterFromStoreUsingEnv("DCS_INTEGRATION_ENCRYPTION_CERT_PARAM");
    }

    public String getDcsEncryptionCert() {
        return getParameterFromStoreUsingEnv("DCS_ENCRYPTION_CERT_PARAM");
    }

    public String getDcsEncryptionKey() {
        return getParameterFromStoreUsingEnv("DCS_ENCRYPTION_KEY_PARAM");
    }

    public String getDcsSigningCert() {
        return getParameterFromStoreUsingEnv("DCS_SIGNING_CERT_PARAM");
    }

    public String getDcsSigningKey() {
        return getParameterFromStoreUsingEnv("DCS_SIGNING_KEY_PARAM");
    }

    public String getDcsTlsCert() {
        return getParameterFromStoreUsingEnv("DCS_TLS_CERT_PARAM");
    }

    public String getDcsTlsKey() {
        return getParameterFromStoreUsingEnv("DCS_TLS_KEY_PARAM");
    }
}
