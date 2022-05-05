package uk.gov.di.ipv.cri.passport.library.persistence.item;

import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;
import uk.gov.di.ipv.cri.passport.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.cri.passport.library.domain.DcsPayload;
import uk.gov.di.ipv.cri.passport.library.domain.verifiablecredential.Evidence;

@DynamoDbBean
@ExcludeFromGeneratedCoverageReport
public class PassportCheckDao {
    private String resourceId;
    private DcsPayload dcsPayload;
    private Evidence gpg45Score;
    private String userId;

    public PassportCheckDao() {}

    public PassportCheckDao(
            String resourceId, DcsPayload dcsPayload, Evidence gpg45Score, String userId) {
        this.resourceId = resourceId;
        this.dcsPayload = dcsPayload;
        this.gpg45Score = gpg45Score;
        this.userId = userId;
    }

    @DynamoDbPartitionKey
    public String getResourceId() {
        return resourceId;
    }

    public void setResourceId(String resourceId) {
        this.resourceId = resourceId;
    }

    public DcsPayload getDcsPayload() {
        return dcsPayload;
    }

    public void setDcsPayload(DcsPayload dcsPayload) {
        this.dcsPayload = dcsPayload;
    }

    public Evidence getGpg45Score() {
        return gpg45Score;
    }

    public void setGpg45Score(Evidence gpg45Score) {
        this.gpg45Score = gpg45Score;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }
}
