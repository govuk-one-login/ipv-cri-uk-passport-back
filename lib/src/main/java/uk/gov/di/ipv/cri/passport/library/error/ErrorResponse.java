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
    DCS_RETURNED_AN_ERROR(1006, "DCS returned an error response"),
    MISSING_SHARED_ATTRIBUTES_JWT(1007, "Missing shared attributes JWT from request body"),
    FAILED_TO_PARSE(1008, "Failed to parse"),
    MISSING_CLIENT_ID_QUERY_PARAMETER(1009, "Missing client_id query parameter"),
    FAILED_TO_VERIFY_SIGNATURE(1010, "Failed to verify the signature of the JWT"),
    JWT_SIGNATURE_IS_INVALID(1011, "Signature of the shared attribute JWT is invalid"),
    INVALID_REDIRECT_URL(1012, "Provided redirect URL is not in those configured for client"),
    UNKNOWN_CLIENT_ID(1013, "Unknown client id provided in request params"),
    INVALID_REQUEST_PARAM(1014, "Invalid request param"),
    SHARED_CLAIM_IS_MISSING(1015, "shared_claim missing from shared attribute JWT"),
    FAILED_TO_SEND_AUDIT_MESSAGE_TO_SQS_QUEUE(
            1016, "Failed to send message to aws SQS audit event queue");

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
