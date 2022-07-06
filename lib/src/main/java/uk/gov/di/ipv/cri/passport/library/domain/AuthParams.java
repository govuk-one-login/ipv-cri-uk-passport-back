package uk.gov.di.ipv.cri.passport.library.domain;

import com.fasterxml.jackson.annotation.JsonProperty;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import uk.gov.di.ipv.cri.passport.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
@DynamoDbBean
public class AuthParams {
    @JsonProperty("response_type")
    private String responseType;

    @JsonProperty("client_id")
    private String clientId;

    @JsonProperty("state")
    private String state;

    @JsonProperty("redirect_uri")
    private String redirectUri;

    public AuthParams() {}

    public AuthParams(
            @JsonProperty(value = "response_type") String responseType,
            @JsonProperty(value = "client_id") String clientId,
            @JsonProperty(value = "state") String state,
            @JsonProperty(value = "redirect_uri") String redirectUri) {
        this.responseType = responseType;
        this.clientId = clientId;
        this.state = state;
        this.redirectUri = redirectUri;
    }

    public String getResponseType() {
        return responseType;
    }

    public void setResponseType(String responseType) {
        this.responseType = responseType;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getState() {
        return state;
    }

    public void setState(String state) {
        this.state = state;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public void setRedirectUri(String redirectUri) {
        this.redirectUri = redirectUri;
    }
}
