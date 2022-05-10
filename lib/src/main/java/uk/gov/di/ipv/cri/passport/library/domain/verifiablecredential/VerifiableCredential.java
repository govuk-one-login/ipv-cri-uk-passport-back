package uk.gov.di.ipv.cri.passport.library.domain.verifiablecredential;

import com.fasterxml.jackson.annotation.JsonProperty;
import uk.gov.di.ipv.cri.passport.library.persistence.item.PassportCheckDao;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static uk.gov.di.ipv.cri.passport.library.domain.verifiablecredential.VerifiableCredentialConstants.IDENTITY_CHECK_CREDENTIAL_TYPE;
import static uk.gov.di.ipv.cri.passport.library.domain.verifiablecredential.VerifiableCredentialConstants.VERIFIABLE_CREDENTIAL_TYPE;

public class VerifiableCredential {

    private final List<String> type =
            List.of(VERIFIABLE_CREDENTIAL_TYPE, IDENTITY_CHECK_CREDENTIAL_TYPE);
    private final CredentialSubject credentialSubject;
    private final List<Evidence> evidence;

    public VerifiableCredential(
            @JsonProperty("credentialSubject") CredentialSubject credentialSubject,
            @JsonProperty("evidence") List<Evidence> evidence) {
        this.credentialSubject = credentialSubject;
        this.evidence = evidence;
    }

    public static VerifiableCredential fromPassportCheckDao(PassportCheckDao passportCheck) {
        List<NameParts> nameParts = new ArrayList<>();

        // Add Forenames to NameParts
        passportCheck
                .getDcsPayload()
                .getForenames()
                .forEach(
                        givenName ->
                                nameParts.add(
                                        new NameParts(
                                                NamePartType.GIVEN_NAME.getName(), givenName)));

        // Add Surname to NameParts
        nameParts.add(
                new NameParts(
                        NamePartType.FAMILY_NAME.getName(),
                        passportCheck.getDcsPayload().getSurname()));

        CredentialSubject credentialSubject =
                new CredentialSubject(
                        List.of(new Name(nameParts)),
                        List.of(
                                new BirthDate(
                                        passportCheck.getDcsPayload().getDateOfBirth().toString())),
                        List.of(
                                new Passport(
                                        passportCheck.getDcsPayload().getPassportNumber(),
                                        passportCheck.getDcsPayload().getExpiryDate().toString())));

        return new VerifiableCredential(
                credentialSubject, Collections.singletonList(passportCheck.getEvidence()));
    }

    public List<String> getType() {
        return type;
    }

    public CredentialSubject getCredentialSubject() {
        return credentialSubject;
    }

    public List<Evidence> getEvidence() {
        return evidence;
    }
}
