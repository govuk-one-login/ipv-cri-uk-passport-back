package uk.gov.di.ipv.cri.passport.acceptance_tests.POJOFromIpvCoreRepo;

public class Attributes {

    private Names names;
    private String passportNumber;
    private String dateOfBirth;
    private String expiryDate;
    private String requestId;
    private String correlationId;
    private DcsResponse dcsResponse;

    @Override
    public String toString() {
        return "Attributes{"
                + "names="
                + names
                + ", passportNumber='"
                + passportNumber
                + '\''
                + ", dateOfBirth='"
                + dateOfBirth
                + '\''
                + ", expiryDate='"
                + expiryDate
                + '\''
                + ", requestId='"
                + requestId
                + '\''
                + ", correlationId='"
                + correlationId
                + '\''
                + ", dcsResponse="
                + dcsResponse
                + '}';
    }
}
