package uk.gov.di.ipv.cri.passport.acceptance_tests.utilities;

public interface TestInput {

    public String getPassportNumber();

    public String getLastName();

    public String getFirstName();

    public String getMiddleNames();

    public String getBirthDay();

    public String getBirthMonth();

    public String getBirthYear();

    public String getValidToDay();

    public String getValidToMonth();

    public String getValidToYear();
}
