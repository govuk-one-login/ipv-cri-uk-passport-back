package uk.gov.di.ipv.cri.passport.dto;

import java.util.UUID;

public class DcsResponse {
    private final UUID correlationId;
    private final UUID requestId;
    private final boolean error;
    private final boolean valid;
    private final String[] errorMessage;

    public DcsResponse(UUID correlationId, UUID requestId, boolean error, boolean valid, String[] errorMessage) {
        this.correlationId = correlationId;
        this.requestId = requestId;
        this.error = error;
        this.valid = valid;
        this.errorMessage = errorMessage;
    }
}

