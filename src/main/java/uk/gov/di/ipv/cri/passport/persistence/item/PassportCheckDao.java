package uk.gov.di.ipv.cri.passport.persistence.item;

import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;
import uk.gov.di.ipv.cri.passport.domain.DcsResponse;
import uk.gov.di.ipv.cri.passport.domain.PassportFormRequest;

@DynamoDbBean
public class PassportCheckDao {

    private String resourceId;
    private DcsResponse dcsResponse;
    private PassportFormRequest passportFormRequest;

    public PassportCheckDao(
            String resourceId, PassportFormRequest passportFormRequest, DcsResponse dcsResponse) {
        this.resourceId = resourceId;
        this.passportFormRequest = passportFormRequest;
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

    public PassportFormRequest getPassportFormRequest() {
        return passportFormRequest;
    }

    public void setPassportFormRequest(PassportFormRequest passportFormRequest) {
        this.passportFormRequest = passportFormRequest;
    }
}
