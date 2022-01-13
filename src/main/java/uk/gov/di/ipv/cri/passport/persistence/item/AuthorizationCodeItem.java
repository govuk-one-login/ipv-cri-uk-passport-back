package uk.gov.di.ipv.cri.passport.persistence.item;

import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;

@DynamoDbBean
public class AuthorizationCodeItem {

    private String authCode;
    private String resourceId;

    public AuthorizationCodeItem() {}

    public AuthorizationCodeItem(String authCode, String resourceId) {
        this.authCode = authCode;
        this.resourceId = resourceId;
    }

    @DynamoDbPartitionKey
    public String getAuthCode() {
        return authCode;
    }

    public void setAuthCode(String authCode) {
        this.authCode = authCode;
    }

    public String getResourceId() {
        return resourceId;
    }

    public void setResourceId(String resourceId) {
        this.resourceId = resourceId;
    }
}
