package uk.gov.di.ipv.cri.passport.library.error;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonFormat(shape = JsonFormat.Shape.OBJECT)
public enum ErrorResponse {
    FAILED_TO_PARSE_PASSPORT_FORM_DATA(1000, "Failed to parse passport form data"),
    MISSING_QUERY_PARAMETERS(1001, "Missing query parameters for auth request"),
    FAILED_TO_PARSE_OAUTH_QUERY_STRING_PARAMETERS(
            1002, "Failed to parse oauth2-specific query string parameters"),
    FAILED_TO_PREPARE_DCS_PAYLOAD(1003, "Failed to prepare DCS payload"),
    ERROR_CONTACTING_DCS(1004, "Error when contacting DCS for passport check"),
    FAILED_TO_UNWRAP_DCS_RESPONSE(1005, "Failed to unwrap Dcs response"),
    ERROR_GETTING_RESPONSE_FROM_DCS(1006, "No response was returned from DCS"),
    DCS_RETURNED_AN_ERROR(1007, "DCS returned an error response");

    private final int code;
    private final String message;

    ErrorResponse(
            @JsonProperty(required = true, value = "code") int code,
            @JsonProperty(required = true, value = "message") String message) {
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
