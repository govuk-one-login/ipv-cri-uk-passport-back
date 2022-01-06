package uk.gov.di.ipv.cri.passport.domain;

import uk.gov.di.ipv.cri.passport.annotations.ExcludeFromGeneratedCoverageReport;

import java.util.UUID;

@ExcludeFromGeneratedCoverageReport
public class DcsResponse {

    private final UUID correlationId;
    private final UUID requestId;
    private final boolean error;
    private final boolean valid;
    private final String[] errorMessage;

    public DcsResponse(
            UUID correlationId,
            UUID requestId,
            boolean error,
            boolean valid,
            String[] errorMessage) {
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

    public boolean getError() {
        return error;
    }

    public boolean isValid() {
        return valid;
    }

    public String[] getErrorMessage() {
        return errorMessage;
    }
}
