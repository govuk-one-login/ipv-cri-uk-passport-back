package uk.gov.di.ipv.cri.passport.library.domain.verifiablecredential;

import com.fasterxml.jackson.annotation.JsonProperty;
import uk.gov.di.ipv.cri.passport.library.persistence.item.PassportCheckDao;

import java.util.ArrayList;
import java.util.List;

public class VerifiableCredential {

    @JsonProperty private CredentialSubject credentialSubject;
    @JsonProperty private Evidence evidence;

    public VerifiableCredential() {}

    public VerifiableCredential(CredentialSubject credentialSubject, Evidence evidence) {
        this.credentialSubject = credentialSubject;
        this.evidence = evidence;
    }

    public static VerifiableCredential fromPassportCheckDao(PassportCheckDao passportCheck) {
        List<NameParts> nameParts = new ArrayList<>();

        // Add Forenames to NameParts
        passportCheck
                .getAttributes()
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
                        passportCheck.getAttributes().getSurname()));

        CredentialSubject credentialSubject =
                new CredentialSubject.Builder()
                        .setName(new Name(nameParts))
                        .setPassportNumber(passportCheck.getAttributes().getPassportNumber())
                        .setBirthDate(
                                new BirthDate(
                                        passportCheck.getAttributes().getDateOfBirth().toString()))
                        .setExpiryDate(passportCheck.getAttributes().getExpiryDate().toString())
                        .setRequestId(passportCheck.getAttributes().getRequestId())
                        .setCorrelationId(passportCheck.getAttributes().getCorrelationId())
                        .setDcsResponse(passportCheck.getAttributes().getDcsResponse())
                        .build();

        return new VerifiableCredential(credentialSubject, passportCheck.getGpg45Score());
    }

    public CredentialSubject getCredentialSubject() {
        return credentialSubject;
    }

    public Evidence getEvidence() {
        return evidence;
    }
}
