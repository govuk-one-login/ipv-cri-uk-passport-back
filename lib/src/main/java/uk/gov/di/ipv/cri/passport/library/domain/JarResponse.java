package uk.gov.di.ipv.cri.passport.library.domain;

import com.fasterxml.jackson.annotation.JsonProperty;
import uk.gov.di.ipv.cri.passport.library.annotations.ExcludeFromGeneratedCoverageReport;

import java.util.Map;

@ExcludeFromGeneratedCoverageReport
public class JarResponse {
    @JsonProperty("shared_claims")
    private Map<String, Object> sharedClaims;

    @JsonProperty("passportSessionId")
    private String passportSessionId;

    @JsonProperty("redirect_uri")
    private String redirectUrl;

    public JarResponse(
            Map<String, Object> sharedClaims, String passportSessionId, String redirectUrl) {
        this.sharedClaims = sharedClaims;
        this.passportSessionId = passportSessionId;
        this.redirectUrl = redirectUrl;
    }

    public Map<String, Object> getSharedClaims() {
        return sharedClaims;
    }

    public String getPassportSessionId() {
        return passportSessionId;
    }
}
