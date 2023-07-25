package uk.gov.di.ipv.cri.passport.acceptance_tests.POJOFromIpvCoreRepo;

public class DcsResponse {

    private String correlationId;
    private String requestId;
    private boolean error;
    private boolean valid;
    private Object errorMessage;

    public boolean isError() {
        return error;
    }

    public void setError(boolean error) {
        this.error = error;
    }

    public boolean isValid() {
        return valid;
    }

    public void setValid(boolean valid) {
        this.valid = valid;
    }

    @Override
    public String toString() {
        return "DcsResponse{"
                + "correlationId='"
                + correlationId
                + '\''
                + ", requestId='"
                + requestId
                + '\''
                + ", error="
                + error
                + ", valid="
                + valid
                + ", errorMessage="
                + errorMessage
                + '}';
    }
}
