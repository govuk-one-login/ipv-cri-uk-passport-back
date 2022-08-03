package uk.gov.di.ipv.cri.passport.library.persistence.item;

import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;
import uk.gov.di.ipv.cri.passport.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.cri.passport.library.domain.AuthParams;

@DynamoDbBean
@ExcludeFromGeneratedCoverageReport
public class PassportSessionItem implements DynamodbItem {
    private String passportSessionId;
    private String creationDateTime;
    private String latestDcsResponseResourceId;
    private String userId;
    private String govukSigninJourneyId;
    private int attemptCount;
    private AuthParams authParams;
    private long ttl;

    @DynamoDbPartitionKey
    public String getPassportSessionId() {
        return passportSessionId;
    }

    public void setPassportSessionId(String passportSessionId) {
        this.passportSessionId = passportSessionId;
    }

    public String getCreationDateTime() {
        return creationDateTime;
    }

    public void setCreationDateTime(String creationDateTime) {
        this.creationDateTime = creationDateTime;
    }

    public String getLatestDcsResponseResourceId() {
        return latestDcsResponseResourceId;
    }

    public void setLatestDcsResponseResourceId(String latestDcsResponseResourceId) {
        this.latestDcsResponseResourceId = latestDcsResponseResourceId;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getGovukSigninJourneyId() {
        return govukSigninJourneyId;
    }

    public void setGovukSigninJourneyId(String govukSigninJourneyId) {
        this.govukSigninJourneyId = govukSigninJourneyId;
    }

    public int getAttemptCount() {
        return attemptCount;
    }

    public void setAttemptCount(int attemptCount) {
        this.attemptCount = attemptCount;
    }

    public AuthParams getAuthParams() {
        return authParams;
    }

    public void setAuthParams(AuthParams authParams) {
        this.authParams = authParams;
    }

    public long getTtl() {
        return ttl;
    }

    @Override
    public void setTtl(long ttl) {
        this.ttl = ttl;
    }
}
