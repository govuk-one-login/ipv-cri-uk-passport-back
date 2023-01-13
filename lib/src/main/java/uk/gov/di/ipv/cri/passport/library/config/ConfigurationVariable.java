package uk.gov.di.ipv.cri.passport.library.config;

public enum ConfigurationVariable {
    AUTH_CODE_EXPIRY_CODE_SECONDS("/%s/AuthCodeExpirySeconds"),
    SESSION_TTL("/%s/SessionTtl"),
    DCS_POST_URL_PARAM("/%s/DCS/PostUrl"),
    HTTPCLIENT_TLS_CERT("/%s/DCS/HttpClient/TLSCert"),
    HTTPCLIENT_TLS_KEY("/%s/DCS/HttpClient/TLSKey"),
    HTTPCLIENT_TLS_INTERMEDIATE_CERT("/%s/DCS/HttpClient/TLSIntermediateCertificate"),
    HTTPCLIENT_TLS_ROOT_CERT("/%s/DCS/HttpClient/TLSRootCertificate"),
    PASSPORT_CRI_SIGNING_CERT(
            "/%s/DCS/JWS/SigningCertForDcsToVerify"), // JWS SHA-1 Certificate Thumbprint (Header)
    PASSPORT_CRI_SIGNING_KEY("/%s/DCS/JWS/SigningKeyForPassportToSign"), // JWS RSA Signing Key
    DCS_ENCRYPTION_CERT("/%s/DCS/JWE/EncryptionCertForPassportToEncrypt"), // JWE (Public Key)
    DCS_SIGNING_CERT("/%s/DCS/JWE/SigningCertForPassportToVerify"), // DCS JWS (Reply Signature)
    PASSPORT_CRI_ENCRYPTION_KEY(
            "/%s/DCS/JWE/EncryptionKeyForPassportToDecrypt"), // DCS JWE (Private Key Reply Decrypt)
    JAR_ENCRYPTION_KEY_ID("/%s/AuthRequestKmsEncryptionKeyId"),
    JAR_KMS_PUBLIC_KEY("/%s/JarKmsEncryptionPublicKey"),
    MAX_JWT_TTL("/%s/MaxJwtTtl"),
    PASSPORT_CRI_CLIENT_VC_MAX_TTL("/%s/MaxVCJwtTtlMapping"),
    PASSPORT_CRI_CLIENT_TTL_UNIT("/%s/JwtTtlUnit"),
    MAXIMUM_ATTEMPT_COUNT("/%s/MaximumAttemptCount"),
    PASSPORT_CRI_CLIENT_AUDIENCE("/%s/PassportCriAudience"),
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
