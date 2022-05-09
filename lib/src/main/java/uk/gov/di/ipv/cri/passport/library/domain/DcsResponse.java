package uk.gov.di.ipv.cri.passport.library.domain;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import uk.gov.di.ipv.cri.passport.library.annotations.ExcludeFromGeneratedCoverageReport;

import java.util.List;

@DynamoDbBean
@ExcludeFromGeneratedCoverageReport
public class DcsResponse {
    private String correlationId;
    private String requestId;
    private boolean error;
    private boolean valid;
    private List<String> errorMessage;

    public DcsResponse() {}

    @JsonCreator
    public DcsResponse(
            @JsonProperty(value = "correlationId", required = true) String correlationId,
            @JsonProperty(value = "requestId", required = true) String requestId,
            @JsonProperty(value = "error") boolean error,
            @JsonProperty(value = "valid") boolean valid,
            @JsonProperty(value = "errorMessage") List<String> errorMessage) {
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

    public void setValid(Boolean valid) {
        this.valid = valid;
    }

    public List<String> getErrorMessage() {
        return errorMessage;
    }

    public void setErrorMessage(List<String> errorMessage) {
        this.errorMessage = errorMessage;
    }

    @Override
    public String toString() {
        return "DcsResponse{"
                + "correlationId="
                + correlationId
                + ", requestId="
                + requestId
                + ", error="
                + error
                + ", valid="
                + valid
                + ", errorMessage="
                + errorMessage
                + '}';
    }
}
