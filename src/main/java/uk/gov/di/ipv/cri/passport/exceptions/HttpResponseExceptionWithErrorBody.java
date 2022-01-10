package uk.gov.di.ipv.cri.passport.exceptions;

import uk.gov.di.ipv.cri.passport.error.ErrorResponse;

import java.util.Map;

public class HttpResponseExceptionWithErrorBody extends Throwable {
    private final int statusCode;
    private final ErrorResponse errorResponse;

    public HttpResponseExceptionWithErrorBody(int statusCode, ErrorResponse errorResponse) {
        this.statusCode = statusCode;
        this.errorResponse = errorResponse;
    }

    public String getErrorReason() {
        return this.errorResponse.getMessage();
    }

    public int getStatusCode() {
        return this.statusCode;
    }

    public Map<String, Object> getErrorBody() {
        return Map.of("code", errorResponse.getCode(), "message", errorResponse.getMessage());
    }
}
