package uk.gov.di.ipv.cri.passport.library.auditing;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonProperty;
import uk.gov.di.ipv.cri.passport.library.domain.verifiablecredential.BirthDate;
import uk.gov.di.ipv.cri.passport.library.domain.verifiablecredential.Name;
import uk.gov.di.ipv.cri.passport.library.domain.verifiablecredential.Passport;

import java.util.List;

public class AuditRestrictedVcCredentialSubject implements AuditRestricted {

    private final List<Name> name;

    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd")
    private final List<BirthDate> birthDate;

    private final List<Passport> passport;

    public AuditRestrictedVcCredentialSubject(
            @JsonProperty(value = "name", required = true) List<Name> name,
            @JsonProperty(value = "birthDate", required = true) List<BirthDate> birthDate,
            @JsonProperty(value = "passport", required = true) List<Passport> passport) {
        this.name = name;
        this.birthDate = birthDate;
        this.passport = passport;
    }

    public List<Name> getName() {
        return name;
    }

    public List<BirthDate> getBirthDate() {
        return birthDate;
    }

    public List<Passport> getPassport() {
        return passport;
    }
}
