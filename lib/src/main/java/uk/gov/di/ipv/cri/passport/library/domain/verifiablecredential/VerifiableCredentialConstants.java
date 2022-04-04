package uk.gov.di.ipv.cri.passport.library.domain.verifiablecredential;

public class VerifiableCredentialConstants {
    public static String VC_CONTEXT = "@context";
    public static String W3_BASE_CONTEXT = "https://www.w3.org/2018/credentials/v1";
    public static String DI_CONTEXT =
            "https://vocab.london.cloudapps.digital/contexts/identity-v1.jsonld";
    public static String VC_TYPE = "type";
    public static String VERIFIABLE_CREDENTIAL_TYPE = "VerifiableCredential";
    public static String IDENTITY_CHECK_CREDENTIAL_TYPE = "IdentityCheckCredential";
    public static String CREDENTIAL_SUBJECT_NAME = "name";
    public static String CREDENTIAL_SUBJECT_BIRTH_DATE = "birthDate";
    public static String CREDENTIAL_SUBJECT_ADDRESS = "address";
    public static String VC_CREDENTIAL_SUBJECT = "credentialSubject";
    public static String VC_EVIDENCE = "evidence";
    public static String VC_CLAIM = "vc";

    private VerifiableCredentialConstants() {}
}
