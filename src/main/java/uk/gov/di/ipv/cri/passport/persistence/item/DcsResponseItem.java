package uk.gov.di.ipv.cri.passport.persistence.item;

import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;

@DynamoDbBean
public class DcsResponseItem {

    private String resourceId;
    private String resourcePayload;

    public DcsResponseItem(String resourceId, String resourcePayload) {
        this.resourceId = resourceId;
        this.resourcePayload = resourcePayload;
    }

    @DynamoDbPartitionKey
    public String getResourceId() {
        return resourceId;
    }

    public void setResourceId(String resourceId) {
        this.resourceId = resourceId;
    }

    public String getResourcePayload() {
        return resourcePayload;
    }

    public void setResourcePayload(String resourcePayload) {
        this.resourcePayload = resourcePayload;
    }
}
