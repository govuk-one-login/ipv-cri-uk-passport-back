package uk.gov.di.ipv.cri.passport.library.exceptions;

import uk.gov.di.ipv.cri.passport.library.error.ErrorResponse;

public class HttpResponseExceptionWithErrorBody extends Exception {
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

    public ErrorResponse getErrorResponse() {
        return this.errorResponse;
    }
}
