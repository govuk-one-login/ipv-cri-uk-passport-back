package uk.gov.di.ipv.cri.passport.library.config;

public enum ConfigurationVariable {
    AUTH_CODE_EXPIRY_CODE_SECONDS("/%s/AuthCodeExpirySeconds"),
    SESSION_TTL("/%s/SessionTtl"),
    DCS_POST_URL_PARAM("/%s/credentialIssuers/ukpassport/DCS/PostUrl"),
    DCS_ENCRYPTION_CERT("/%s/credentialIssuers/ukpassport/DCS/EncryptionCertForPassportToEncrypt"),
    DCS_SIGNING_CERT("/%s/credentialIssuers/ukpassport/DCS/SigningCertForPassportToVerify"),
    DCS_TLS_INTERMEDIATE_CERT("/%s/credentialIssuers/ukpassport/DCS/TLSIntermediateCertificate"),
    DCS_TLS_ROOT_CERT("/%s/credentialIssuers/ukpassport/DCS/TLSRootCertificate"),
    JAR_ENCRYPTION_KEY_ID("/%s/AuthRequestKmsEncryptionKeyId"),
    JAR_KMS_PUBLIC_KEY("/%s/credentialIssuers/ukPassport/JarKmsEncryptionPublicKey"),
    MAX_JWT_TTL("/%s/MaxJwtTtl"),
    MAXIMUM_ATTEMPT_COUNT("/%s/MaximumAttemptCount"),
    PASSPORT_CRI_CLIENT_AUDIENCE("/%s/PassportCriAudience"),
    PASSPORT_CRI_ENCRYPTION_KEY(
            "/%s/credentialIssuers/ukpassport/DCS/EncryptionKeyForPassportToDecrypt"),
    PASSPORT_CRI_SIGNING_CERT("/%s/credentialIssuers/ukpassport/DCS/SigningCertForDcsToVerify"),
    PASSPORT_CRI_SIGNING_KEY("/%s/credentialIssuers/ukpassport/DCS/SigningKeyForPassportToSign"),
    HTTPCLIENT_TLS_CERT("/%s/credentialIssuers/ukpassport/HttpClient/TLSCert"),
    HTTPCLIENT_TLS_KEY("/%s/credentialIssuers/ukpassport/HttpClient/TLSKey"),
    VERIFIABLE_CREDENTIAL_ISSUER("/%s/verifiable-credential/issuer"),
    VERIFIABLE_CREDENTIAL_SIGNING_KEY_ID("/%s/verifiableCredentialKmsSigningKeyId");

    private final String value;

    ConfigurationVariable(String value) {

        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
