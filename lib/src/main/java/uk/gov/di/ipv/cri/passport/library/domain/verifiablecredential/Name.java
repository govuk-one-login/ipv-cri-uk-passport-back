package uk.gov.di.ipv.cri.passport.library.domain.verifiablecredential;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public class Name {
    @JsonProperty("nameParts")
    private final List<NameParts> nameParts;

    public Name(@JsonProperty(value = "nameParts", required = true) List<NameParts> nameParts) {
        this.nameParts = nameParts;
    }

    public List<NameParts> getNameParts() {
        return nameParts;
    }
}
