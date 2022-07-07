package uk.gov.di.ipv.cri.passport.buildclientoauthresponse.domain;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import uk.gov.di.ipv.cri.passport.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
@JsonInclude(Include.NON_EMPTY)
public class ClientDetails {
    @JsonProperty private final String redirectUrl;

    @JsonCreator
    public ClientDetails(@JsonProperty(value = "redirectUrl", required = true) String redirectUrl) {
        this.redirectUrl = redirectUrl;
    }

    public String getRedirectUrl() {
        return redirectUrl;
    }
}
