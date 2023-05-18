package uk.gov.di.ipv.cri.passport.acceptance_tests.POJOFromIpvCoreRepo;

public class DcsResponse {

    private String correlationId;
    private String requestId;
    private boolean error;
    private boolean valid;
    private Object errorMessage;

    public DcsResponse() {}

    public DcsResponse(
            String correlationId,
            String requestId,
            boolean error,
            boolean valid,
            Object errorMessage) {
        this.correlationId = correlationId;
        this.requestId = requestId;
        this.error = error;
        this.valid = valid;
        this.errorMessage = errorMessage;
    }

    public String getCorrelationId() {
        return correlationId;
    }

    public void setCorrelationId(String correlationId) {
        this.correlationId = correlationId;
    }

    public String getRequestId() {
        return requestId;
    }

    public void setRequestId(String requestId) {
        this.requestId = requestId;
    }

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

    public Object getErrorMessage() {
        return errorMessage;
    }

    public void setErrorMessage(Object errorMessage) {
        this.errorMessage = errorMessage;
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
