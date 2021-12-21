package uk.gov.di.ipv.cri.passport.domain;

public class PassportException extends RuntimeException {

    private final ErrorResponse errorResponse;

    private final int httpStatusCode;

    public PassportException(int httpStatusCode, ErrorResponse errorResponse) {
        this.errorResponse = errorResponse;
        this.httpStatusCode = httpStatusCode;
    }

    public ErrorResponse getErrorResponse() {
        return errorResponse;
    }

    public int getHttpStatusCode() {
        return httpStatusCode;
    }
}

