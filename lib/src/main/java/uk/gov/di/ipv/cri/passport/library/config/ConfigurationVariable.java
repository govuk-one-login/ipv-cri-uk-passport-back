package uk.gov.di.ipv.cri.passport.library.config;

public enum ConfigurationVariable {
    AUTH_CODE_EXPIRY_CODE_SECONDS("/%s/credentialIssuers/ukPassport/self/authCodeExpirySeconds"),

    DCS_ENCRYPTION_CERT_PARAM(
            "/%s/credentialIssuers/ukPassport/dcs/encryptionCertForPassportToEncrypt"),
    DCS_SIGNING_CERT_PARAM("/%s/credentialIssuers/ukPassport/dcs/signingCertForPassportToVerify"),
    DCS_TLS_INTERMEDIATE_CERT_PARAM(
            "/%s/credentialIssuers/ukPassport/dcs/tlsIntermediateCertificate"),
    DCS_TLS_ROOT_CERT_PARAM("/%s/credentialIssuers/ukPassport/dcs/tlsRootCertificate"),

    PASSPORT_CRI_ENCRYPTION_KEY_PARAM(
            "/%s/credentialIssuers/ukPassport/self/encryptionKeyForPassportToDecrypt"),
    PASSPORT_CRI_SIGNING_CERT_PARAM(
            "/%s/credentialIssuers/ukPassport/self/signingCertForDcsToVerify"),
    PASSPORT_CRI_SIGNING_KEY_PARAM(
            "/%s/credentialIssuers/ukPassport/self/signingKeyForPassportToSign"),
    PASSPORT_CRI_TLS_CERT_PARAM("/%s/credentialIssuers/ukPassport/self/tlsCert"),
    PASSPORT_CRI_TLS_KEY_PARAM("/%s/credentialIssuers/ukPassport/self/tlsKey");

    private final String value;

    ConfigurationVariable(String value) {

        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
