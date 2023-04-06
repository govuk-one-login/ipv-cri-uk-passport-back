package uk.gov.di.ipv.cri.passport.library.config;

public enum ConfigurationVariable {
    AUTH_CODE_EXPIRY_CODE_SECONDS("/%s/credentialIssuers/ukPassport/self/authCodeExpirySeconds"),
    BACKEND_SESSION_TTL("/%s/credentialIssuers/ukPassport/self/backendSessionTtl"),
    DCS_POST_URL_PARAM("/%s/credentialIssuers/ukPassport/dcs/postUrl"),
    DCS_ENCRYPTION_CERT("/%s/credentialIssuers/ukPassport/dcs/encryptionCertForPassportToEncrypt"),
    DCS_SIGNING_CERT("/%s/credentialIssuers/ukPassport/dcs/signingCertForPassportToVerify"),
    DCS_TLS_INTERMEDIATE_CERT("/%s/credentialIssuers/ukPassport/dcs/tlsIntermediateCertificate"),
    DCS_TLS_ROOT_CERT("/%s/credentialIssuers/ukPassport/dcs/tlsRootCertificate"),
    JAR_ENCRYPTION_KEY_ID("/%s/credentialIssuers/ukPassport/self/jarKmsEncryptionKeyId"),
    JAR_KMS_PUBLIC_KEY("/%s/credentialIssuers/ukPassport/self/jarKmsEncryptionPublicKey"),
    MAX_JWT_TTL("/%s/credentialIssuers/ukPassport/self/maxJwtTtl"),
    MAXIMUM_ATTEMPT_COUNT("/%s/credentialIssuers/ukPassport/self/maximumAttemptCount"),
    PASSPORT_CRI_CLIENT_AUDIENCE("/%s/credentialIssuers/ukPassport/self/audienceForClients"),
    PASSPORT_CRI_CLIENT_AUTH_MAX_TTL("/%s/credentialIssuers/ukPassport/self/maxJwtTtl"),
    PASSPORT_CRI_CLIENT_VC_MAX_TTL("/%s/credentialIssuers/ukPassport/self/MaxVCJwtTtlMapping"),
    PASSPORT_CRI_CLIENT_TTL_UNIT("/%s/credentialIssuers/ukPassport/self/JwtTtlUnit"),
    PASSPORT_CRI_RELEASE_FLAG_EXCLUDE_EXPIRY(
            "/%s/credentialIssuers/ukPassport/self/release-flags/vc-expiry-removed"),
    PASSPORT_CRI_ENCRYPTION_KEY(
            "/%s/credentialIssuers/ukPassport/self/encryptionKeyForPassportToDecrypt-2023-02-17"),
    PASSPORT_CRI_SIGNING_CERT(
            "/%s/credentialIssuers/ukPassport/self/signingCertForDcsToVerify-2023-02-17"),
    PASSPORT_CRI_SIGNING_KEY(
            "/%s/credentialIssuers/ukPassport/self/signingKeyForPassportToSign-2023-02-17"),
    PASSPORT_CRI_TLS_CERT("/%s/credentialIssuers/ukPassport/self/tlsCert-2023-02-17"),
    PASSPORT_CRI_TLS_KEY("/%s/credentialIssuers/ukPassport/self/tlsKey-2023-02-17"),
    VERIFIABLE_CREDENTIAL_ISSUER(
            "/%s/credentialIssuers/ukPassport/self/verifiableCredentialIssuer"),
    VERIFIABLE_CREDENTIAL_SIGNING_KEY_ID(
            "/%s/credentialIssuers/ukPassport/self/verifiableCredentialKmsSigningKeyId");

    private final String value;

    ConfigurationVariable(String value) {

        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
