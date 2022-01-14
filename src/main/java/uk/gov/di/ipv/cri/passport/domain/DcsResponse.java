package uk.gov.di.ipv.cri.passport.domain;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import uk.gov.di.ipv.cri.passport.annotations.ExcludeFromGeneratedCoverageReport;

import java.util.UUID;

@ExcludeFromGeneratedCoverageReport
@DynamoDbBean
public class DcsResponse {

    private UUID correlationId;
    private UUID requestId;
    private boolean error;
    private boolean valid;
    private String[] errorMessage;

    public DcsResponse() {}

    @JsonCreator
    public DcsResponse(
            @JsonProperty(value = "correlationId", required = true) UUID correlationId,
            @JsonProperty(value = "requestId", required = true) UUID requestId,
            @JsonProperty(value = "error", required = false) boolean error,
            @JsonProperty(value = "valid", required = false) boolean valid,
            @JsonProperty(value = "errorMessage", required = false) String[] errorMessage) {
        this.correlationId = correlationId;
        this.requestId = requestId;
        this.error = error;
        this.valid = valid;
        this.errorMessage = errorMessage;
    }

    public UUID getCorrelationId() {
        return correlationId;
    }

    public UUID getRequestId() {
        return requestId;
    }

    public boolean isError() {
        return error;
    }

    public boolean isValid() {
        return valid;
    }

    public String[] getErrorMessage() {
        return errorMessage;
    }
}
