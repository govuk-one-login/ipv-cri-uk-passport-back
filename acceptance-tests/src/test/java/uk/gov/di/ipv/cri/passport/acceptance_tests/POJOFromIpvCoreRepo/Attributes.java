package uk.gov.di.ipv.cri.passport.acceptance_tests.POJOFromIpvCoreRepo;

public class Attributes {

    private Names names;
    private String passportNumber;
    private String dateOfBirth;
    private String expiryDate;
    private String requestId;
    private String correlationId;
    private DcsResponse dcsResponse;
//
//    public Attributes() {}
//
//    public Attributes(
//            Names names,
//            String passportNumber,
//            String dateOfBirth,
//            String expiryDate,
//            String requestId,
//            String correlationId,
//            DcsResponse dcsResponse) {
//        this.names = names;
//        this.passportNumber = passportNumber;
//        this.dateOfBirth = dateOfBirth;
//        this.expiryDate = expiryDate;
//        this.requestId = requestId;
//        this.correlationId = correlationId;
//        this.dcsResponse = dcsResponse;
//    }
//
//    public Names getNames() {
//        return names;
//    }
//
//    public void setNames(Names names) {
//        this.names = names;
//    }
//
//    public String getPassportNumber() {
//        return passportNumber;
//    }
//
//    public void setPassportNumber(String passportNumber) {
//        this.passportNumber = passportNumber;
//    }
//
//    public String getDateOfBirth() {
//        return dateOfBirth;
//    }
//
//    public void setDateOfBirth(String dateOfBirth) {
//        this.dateOfBirth = dateOfBirth;
//    }
//
//    public String getExpiryDate() {
//        return expiryDate;
//    }
//
//    public void setExpiryDate(String expiryDate) {
//        this.expiryDate = expiryDate;
//    }
//
//    public String getRequestId() {
//        return requestId;
//    }
//
//    public void setRequestId(String requestId) {
//        this.requestId = requestId;
//    }
//
//    public String getCorrelationId() {
//        return correlationId;
//    }
//
//    public void setCorrelationId(String correlationId) {
//        this.correlationId = correlationId;
//    }
//
//    public DcsResponse getDcsResponse() {
//        return dcsResponse;
//    }
//
//    public void setDcsResponse(DcsResponse dcsResponse) {
//        this.dcsResponse = dcsResponse;
//    }

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
