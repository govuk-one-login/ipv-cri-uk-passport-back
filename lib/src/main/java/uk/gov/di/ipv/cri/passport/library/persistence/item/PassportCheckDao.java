package uk.gov.di.ipv.cri.passport.library.persistence.item;

import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBAttribute;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbConvertedBy;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;
import uk.gov.di.ipv.cri.passport.library.domain.PassportAttributes;

@DynamoDbBean
public class PassportCheckDao {

    private String resourceId;

    @DynamoDBAttribute(attributeName = "attributes")
    private PassportAttributes attributes;

    public PassportCheckDao() {}

    public PassportCheckDao(
            String resourceId, PassportAttributes attributes) {
        this.resourceId = resourceId;
        this.attributes = attributes;
    }

    @DynamoDbPartitionKey
    public String getResourceId() {
        return resourceId;
    }

    public void setResourceId(String resourceId) {
        this.resourceId = resourceId;
    }

    @DynamoDbConvertedBy(PassportAttributesConverter.class)
    public PassportAttributes getAttributes() {
        return attributes;
    }

    public void setAttributes(PassportAttributes passportAttributes) {
        this.attributes = passportAttributes;
    }
}
