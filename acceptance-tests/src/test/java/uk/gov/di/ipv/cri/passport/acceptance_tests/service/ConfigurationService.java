package uk.gov.di.ipv.cri.passport.acceptance_tests.service;

import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ConfigurationService {

    private static final Logger LOGGER = LogManager.getLogger();

    private final String publicApiBaseUrl;
    private final String coreStubEndpoint;
    private final String coreStubUsername;
    private final String coreStubPassword;
    private final String orchestratorStubUrl;
    private final String privateApiGatewayId;
    private final String environment;
    private final String publicApiGatewayId;
    private final String publicApiGatewayKey;

    public ConfigurationService(String env) {

        if (StringUtils.isBlank(env)) {
            throw new IllegalArgumentException("env must be specified");
        }

        this.publicApiBaseUrl = getParameter("apiBaseUrl");
        this.coreStubEndpoint = getParameter("coreStubUrl");
        this.coreStubUsername = getParameter("coreStubUsername");
        this.coreStubPassword = getParameter("coreStubPassword");
        this.orchestratorStubUrl = getParameter("orchestratorStubUrl");
        this.privateApiGatewayId = getParameter("API_GATEWAY_ID_PRIVATE");
        this.publicApiGatewayId = getParameter("API_GATEWAY_ID_PUBLIC");
        this.publicApiGatewayKey = getParameter("API_GATEWAY_KEY");
        this.environment = env;
    }

    private String getParameter(String paramName) {
        String parameterValue = System.getenv(paramName);
        return parameterValue;
    }

    public String getPublicApiBaseUrl() {
        return publicApiBaseUrl;
    }

    public String getCoreStubEndpoint() {
        return coreStubEndpoint;
    }

    public String getCoreStubUsername() {
        return coreStubUsername;
    }

    public String getCoreStubPassword() {
        return coreStubPassword;
    }

    public String getOrchestratorStubUrl() {
        return orchestratorStubUrl;
    }

    public String getPublicApiGatewayKey() {
        return publicApiGatewayKey;
    }

    public String getCoreStubUrl(boolean withAuth) {
        String coreStubUsername = this.getCoreStubUsername();
        String coreStubPassword = this.getCoreStubPassword();
        String coreStubUrl = this.getCoreStubEndpoint();

        if (null != coreStubUsername && null != coreStubPassword && withAuth) {
            return "https://" + coreStubUsername + ":" + coreStubPassword + "@" + coreStubUrl;
        } else {
            if (!this.environment.equals("local")) {
                return "https://" + coreStubUrl;
            }
            return "http://" + coreStubUrl;
        }
    }

    public String getPrivateAPIEndpoint() {
        String privateGatewayId = this.privateApiGatewayId;
        if (privateGatewayId == null) {
            throw new IllegalArgumentException(
                    "Environment variable PRIVATE API endpoint is not set");
        }
        String stage =
                this.environment.equals("local") || this.environment.equals("shared-dev")
                        ? "dev"
                        : this.environment;
        LOGGER.info("privateGatewayId =>" + privateGatewayId);
        return "https://" + privateGatewayId + ".execute-api.eu-west-2.amazonaws.com/" + stage;
    }

    public String getPassportCRITestEnvironment() {
        String passportCRITestEnvironment = this.environment;
        if (passportCRITestEnvironment == null) {
            throw new IllegalArgumentException("Environment variable ENVIRONMENT is not set");
        }
        return passportCRITestEnvironment;
    }

    public String getPublicAPIEndpoint() {
        String publicGatewayId = this.publicApiGatewayId;
        if (publicGatewayId == null) {
            throw new IllegalArgumentException(
                    "Environment variable PUBLIC API endpoint is not set");
        }
        String stage =
                this.environment.equals("local") || this.environment.equals("shared-dev")
                        ? "dev"
                        : this.environment;
        LOGGER.info("publicGatewayId =>" + publicGatewayId);
        return "https://" + publicGatewayId + ".execute-api.eu-west-2.amazonaws.com/" + stage;
    }
}
