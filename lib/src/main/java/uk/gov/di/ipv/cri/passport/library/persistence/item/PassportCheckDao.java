package uk.gov.di.ipv.cri.passport.library.persistence.item;

import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;
import uk.gov.di.ipv.cri.passport.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.cri.passport.library.domain.DcsPayload;
import uk.gov.di.ipv.cri.passport.library.domain.verifiablecredential.Evidence;

@DynamoDbBean
@ExcludeFromGeneratedCoverageReport
public class PassportCheckDao implements DynamodbItem {
    private String resourceId;
    private DcsPayload dcsPayload;
    private Evidence evidence;
    private String userId;
    private String clientId;
    private long ttl;

    public PassportCheckDao() {}

    public PassportCheckDao(
            String resourceId,
            DcsPayload dcsPayload,
            Evidence evidence,
            String userId,
            String clientId) {
        this.resourceId = resourceId;
        this.dcsPayload = dcsPayload;
        this.evidence = evidence;
        this.userId = userId;
        this.clientId = clientId;
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

    public Evidence getEvidence() {
        return evidence;
    }

    public void setEvidence(Evidence evidence) {
        this.evidence = evidence;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public long getTtl() {
        return ttl;
    }

    public void setTtl(long ttl) {
        this.ttl = ttl;
    }
}
