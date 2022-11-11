package uk.gov.di.ipv.cri.passport.library.metrics;

public class Definitions {

    // These completed metrics record all escape routes from the lambdas.
    // OK for expected routes with ERROR being all others
    public static final String LAMBDA_INITIALISE_SESSION_COMPLETED_OK =
            "lambda_initialise_session_completed_ok";
    public static final String LAMBDA_INITIALISE_SESSION_COMPLETED_ERROR =
            "lambda_initialise_session_completed_error";

    public static final String LAMBDA_CHECK_PASSPORT_COMPLETED_OK =
            "lambda_check_passport_completed_ok";
    public static final String LAMBDA_CHECK_PASSPORT_COMPLETED_ERROR =
            "lambda_check_passport_completed_error";

    public static final String LAMBDA_BUILD_CLIENT_OAUTH_RESPONSE_COMPLETED_OK =
            "lambda_build_client_oauth_response_completed_ok";
    public static final String LAMBDA_BUILD_CLIENT_OAUTH_RESPONSE_COMPLETED_ERROR =
            "lambda_build_client_oauth_response_completed_error";

    public static final String LAMBDA_ACCESS_TOKEN_COMPLETED_OK =
            "lambda_access_token_completed_ok";
    public static final String LAMBDA_ACCESS_TOKEN_COMPLETED_ERROR =
            "lambda_access_token_completed_error";

    public static final String LAMBDA_ISSUE_CREDENTIAL_COMPLETED_OK =
            "lambda_issue_credential_completed_ok";
    public static final String LAMBDA_ISSUE_CREDENTIAL_COMPLETED_ERROR =
            "lambda_issue_credential_completed_error";

    // Document Status after an attempt
    public static final String LAMBDA_CHECK_PASSPORT_ATTEMPT_STATUS_VERIFIED_PREFIX =
            "lambda_check_passport_attempt_status_verified_"; // Attempt count appended
    public static final String LAMBDA_CHECK_PASSPORT_ATTEMPT_STATUS_RETRY =
            "lambda_check_passport_attempt_status_retry";
    public static final String LAMBDA_CHECK_PASSPORT_ATTEMPT_STATUS_UNVERIFIED =
            "lambda_check_passport_attempt_status_unverified";

    // FormDataParse
    public static final String FORM_DATA_PARSE_PASS = "form_data_parse_pass";
    public static final String FORM_DATA_PARSE_FAIL = "form_data_parse_fail";

    // DCS
    public static final String DCS_CHECK_REQUEST_SUCCEEDED = "dcs_check_request_succeeded";
    public static final String DCS_CHECK_REQUEST_FAILED = "dcs_check_request_failed";

    public static final String PASSPORT_CI_PREFIX = "passport_ci_";

    // Third Party Response Type DCS
    public static final String THIRD_PARTY_DCS_RESPONSE_OK = "third_party_dcs_response_ok";
    public static final String THIRD_PARTY_DCS_RESPONSE_TYPE_ERROR =
            "third_party_dcs_response_type_error";
    public static final String THIRD_PARTY_DCS_RESPONSE_TYPE_EMPTY =
            "third_party_dcs_response_type_empty";

    private Definitions() {
        throw new IllegalStateException("Instantiation is not valid for this class.");
    }
}
