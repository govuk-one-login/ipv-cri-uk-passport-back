package uk.gov.di.ipv.cri.passport.library.domain.verifiablecredential;

import com.fasterxml.jackson.annotation.JsonProperty;
import uk.gov.di.ipv.cri.passport.library.persistence.item.PassportCheckDao;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class VerifiableCredential {

    @JsonProperty private CredentialSubject credentialSubject;
    @JsonProperty private List<Evidence> evidence;

    public VerifiableCredential() {}

    public VerifiableCredential(CredentialSubject credentialSubject, List<Evidence> evidence) {
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
                new CredentialSubject.Builder()
                        .setName(new Name(nameParts))
                        .setPassportNumber(passportCheck.getDcsPayload().getPassportNumber())
                        .setBirthDate(
                                new BirthDate(
                                        passportCheck.getDcsPayload().getDateOfBirth().toString()))
                        .setExpiryDate(passportCheck.getDcsPayload().getExpiryDate().toString())
                        .setRequestId(passportCheck.getDcsPayload().getRequestId().toString())
                        .setCorrelationId(
                                passportCheck.getDcsPayload().getCorrelationId().toString())
                        .setDcsResponse(passportCheck.getDcsPayload().getDcsResponse())
                        .build();

        return new VerifiableCredential(
                credentialSubject, Collections.singletonList(passportCheck.getGpg45Score()));
    }

    public CredentialSubject getCredentialSubject() {
        return credentialSubject;
    }

    public List<Evidence> getEvidence() {
        return evidence;
    }
}
