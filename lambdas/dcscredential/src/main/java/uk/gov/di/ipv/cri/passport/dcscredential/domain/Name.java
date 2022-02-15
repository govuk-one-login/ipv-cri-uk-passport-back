package uk.gov.di.ipv.cri.passport.dcscredential.domain;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public class Name {
    @JsonProperty private final String familyName;
    @JsonProperty private final List<String> givenNames;

    @JsonCreator
    public Name(
            @JsonProperty(value = "familyName", required = true) String familyName,
            @JsonProperty(value = "givenNames", required = true) List<String> givenNames) {
        this.familyName = familyName;
        this.givenNames = givenNames;
    }

    public String getFamilyName() {
        return familyName;
    }

    public List<String> getGivenNames() {
        return givenNames;
    }
}
