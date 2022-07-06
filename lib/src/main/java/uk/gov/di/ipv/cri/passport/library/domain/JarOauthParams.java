package uk.gov.di.ipv.cri.passport.library.domain;

import com.fasterxml.jackson.annotation.JsonProperty;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import uk.gov.di.ipv.cri.passport.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
@DynamoDbBean
public class JarOauthParams {
    @JsonProperty("authParams")
    private AuthParams authParams;

    @JsonProperty("user_id")
    private String userId;

    public JarOauthParams() {}

    public JarOauthParams(AuthParams authParams, String userId) {
        this.authParams = authParams;
        this.userId = userId;
    }

    public AuthParams getAuthParams() {
        return authParams;
    }

    public void setAuthParams(AuthParams authParams) {
        this.authParams = authParams;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }
}
