package uk.gov.di.ipv.cri.passport.library.domain.verifiablecredential;

public enum NamePartType {
    GIVEN_NAME("GivenName"),
    FAMILY_NAME("FamilyName");

    private final String name;

    NamePartType(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }

    @Override
    public String toString() {
        return name;
    }
}
