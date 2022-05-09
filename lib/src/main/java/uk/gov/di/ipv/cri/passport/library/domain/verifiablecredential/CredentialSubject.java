package uk.gov.di.ipv.cri.passport.library.domain.verifiablecredential;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonProperty;

public class CredentialSubject {

    private final Name name;

    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd")
    private final BirthDate birthDate;

    private final Passport passport;

    public CredentialSubject(
            @JsonProperty(value = "name", required = true) Name name,
            @JsonProperty(value = "birthDate", required = true) BirthDate birthDate,
            @JsonProperty(value = "passport", required = true) Passport passport) {
        this.name = name;
        this.birthDate = birthDate;
        this.passport = passport;
    }

    public Name getName() {
        return name;
    }

    public BirthDate getBirthDate() {
        return birthDate;
    }

    public Passport getPassport() {
        return passport;
    }
}
