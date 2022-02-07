package uk.gov.di.ipv.cri.passport.library.persistence.item;

import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBAttribute;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbConvertedBy;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;
import uk.gov.di.ipv.cri.passport.library.domain.PassportAttributes;
import uk.gov.di.ipv.cri.passport.library.domain.PassportGpg45Score;

@DynamoDbBean
public class PassportCheckDao {

    private String resourceId;

    @DynamoDBAttribute(attributeName = "attributes")
    private PassportAttributes attributes;

    @DynamoDBAttribute(attributeName = "gpg45Score")
    private PassportGpg45Score gpg45Score;

    public PassportCheckDao() {}

    public PassportCheckDao(
            String resourceId, PassportAttributes attributes, PassportGpg45Score gpg45Score) {
        this.resourceId = resourceId;
        this.attributes = attributes;
        this.gpg45Score = gpg45Score;
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

    @DynamoDbConvertedBy(PassportGpg45ScoreConverter.class)
    public PassportGpg45Score getGpg45Score() {
        return gpg45Score;
    }

    public void setAttributes(PassportAttributes passportAttributes) {
        this.attributes = passportAttributes;
    }
}
