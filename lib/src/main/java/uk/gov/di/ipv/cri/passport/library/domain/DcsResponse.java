package uk.gov.di.ipv.cri.passport.library.domain;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import uk.gov.di.ipv.cri.passport.library.annotations.ExcludeFromGeneratedCoverageReport;

import java.util.List;
import java.util.UUID;

@DynamoDbBean
@ExcludeFromGeneratedCoverageReport
public class DcsResponse {
    private UUID correlationId;
    private UUID requestId;
    private boolean error;
    private boolean valid;
    private List<String> errorMessage;

    public DcsResponse() {}

    @JsonCreator
    public DcsResponse(
            @JsonProperty(value = "correlationId", required = true) UUID correlationId,
            @JsonProperty(value = "requestId", required = true) UUID requestId,
            @JsonProperty(value = "error", required = false) boolean error,
            @JsonProperty(value = "valid", required = false) boolean valid,
            @JsonProperty(value = "errorMessage", required = false) List<String> errorMessage) {
        this.correlationId = correlationId;
        this.requestId = requestId;
        this.error = error;
        this.valid = valid;
        this.errorMessage = errorMessage;
    }

    public UUID getCorrelationId() {
        return correlationId;
    }

    public void setCorrelationId(UUID correlationId) {
        this.correlationId = correlationId;
    }

    public UUID getRequestId() {
        return requestId;
    }

    public void setRequestId(UUID requestId) {
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

    public List<String> getErrorMessage() {
        return errorMessage;
    }

    public void setErrorMessage(List<String> errorMessage) {
        this.errorMessage = errorMessage;
    }
}
