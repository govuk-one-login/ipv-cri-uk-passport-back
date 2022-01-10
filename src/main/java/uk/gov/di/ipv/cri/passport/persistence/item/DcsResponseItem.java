package uk.gov.di.ipv.cri.passport.persistence.item;

import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;
import uk.gov.di.ipv.cri.passport.domain.DcsResponse;

@DynamoDbBean
public class DcsResponseItem {

    private String resourceId;
    private DcsResponse dcsResponse;

    public DcsResponseItem(String resourceId, DcsResponse dcsResponse) {
        this.resourceId = resourceId;
        this.dcsResponse = dcsResponse;
    }

    @DynamoDbPartitionKey
    public String getResourceId() {
        return resourceId;
    }

    public void setResourceId(String resourceId) {
        this.resourceId = resourceId;
    }

    public DcsResponse getDcsResponse() {
        return dcsResponse;
    }

    public void setDcsResponse(DcsResponse dcsResponse) {
        this.dcsResponse = dcsResponse;
    }
}
