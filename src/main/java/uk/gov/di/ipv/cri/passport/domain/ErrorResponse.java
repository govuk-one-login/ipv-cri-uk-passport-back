package uk.gov.di.ipv.cri.passport.domain;


public enum ErrorResponse {
    MISSING_QUERY_PARAMETERS(1000, "Missing query parameters for auth request"),
    FAILED_TO_PARSE_OAUTH_QUERY_STRING_PARAMETERS(
            1001, "Failed to parse oauth2-specific query string parameters"),
    FAILED_TO_PARSE_PASSPORT_FORM_DATA(
            1001, "Failed to parse passport form data");

    private final int code;
    private final String message;

    ErrorResponse(int code, String message) {
        this.code = code;
        this.message = message;
    }

    public int getCode() {
        return code;
    }

    public String getMessage() {
        return message;
    }
}
