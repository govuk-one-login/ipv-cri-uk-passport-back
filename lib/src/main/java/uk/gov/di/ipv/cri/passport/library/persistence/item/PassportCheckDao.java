package uk.gov.di.ipv.cri.passport.library.persistence.item;

import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;
import uk.gov.di.ipv.cri.passport.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.cri.passport.library.domain.PassportAttributes;
import uk.gov.di.ipv.cri.passport.library.domain.verifiablecredential.Evidence;

@DynamoDbBean
@ExcludeFromGeneratedCoverageReport
public class PassportCheckDao {
    private String resourceId;
    private PassportAttributes attributes;
    private Evidence gpg45Score;

    public PassportCheckDao() {}

    public PassportCheckDao(String resourceId, PassportAttributes attributes, Evidence gpg45Score) {
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

    public PassportAttributes getAttributes() {
        return attributes;
    }

    public void setAttributes(PassportAttributes passportAttributes) {
        this.attributes = passportAttributes;
    }

    public Evidence getGpg45Score() {
        return gpg45Score;
    }

    public void setGpg45Score(Evidence gpg45Score) {
        this.gpg45Score = gpg45Score;
    }
}
