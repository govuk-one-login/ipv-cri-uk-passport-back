package uk.gov.di.ipv.cri.passport.library.domain;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ErrorObject;
import uk.gov.di.ipv.cri.passport.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
public class AuthorizationCodeResponse {

    private boolean isValidPassport;
    private AuthorizationCode code;
    private String error;
    private String error_description;


    public AuthorizationCodeResponse(
            @JsonProperty(value = "isValidPassport", required = true) boolean isValidPassport,
            @JsonProperty(value = "code", required = false) AuthorizationCode code,
            @JsonProperty(value = "error", required = false) String error,
            @JsonProperty(value = "error_description", required = false) String error_description) {
        this.isValidPassport = isValidPassport;
        this.code = code;
        this.error = error;
        this.error_description = error_description;
    }
}
