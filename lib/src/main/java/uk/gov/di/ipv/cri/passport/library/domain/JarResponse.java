package uk.gov.di.ipv.cri.passport.library.domain;

import com.fasterxml.jackson.annotation.JsonProperty;
import uk.gov.di.ipv.cri.passport.library.annotations.ExcludeFromGeneratedCoverageReport;

import java.util.Map;

@ExcludeFromGeneratedCoverageReport
public class JarResponse {
    @JsonProperty("authParams")
    private AuthParams authParams;

    @JsonProperty("user_id")
    private String userId;

    @JsonProperty("shared_claims")
    private Map<String, Object> sharedClaims;

    @JsonProperty("passportSessionId")
    private String passportSessionId;

    public JarResponse(
            AuthParams authParams,
            String userId,
            Map<String, Object> sharedClaims,
            String passportSessionId) {
        this.authParams = authParams;
        this.userId = userId;
        this.sharedClaims = sharedClaims;
        this.passportSessionId = passportSessionId;
    }

    public AuthParams getAuthParams() {
        return authParams;
    }

    public String getUserId() {
        return userId;
    }

    public Map<String, Object> getSharedClaims() {
        return sharedClaims;
    }

    public String getPassportSessionId() {
        return passportSessionId;
    }
}
