package uk.gov.di.ipv.cri.passport.library.error;

import com.fasterxml.jackson.annotation.JsonProperty;
import net.minidev.json.JSONObject;

public class RedirectErrorResponse {
    private final String redirectUri;
    private final JSONObject errorObject;

    public RedirectErrorResponse(String redirectUri, JSONObject errorObject) {
        this.redirectUri = redirectUri;
        this.errorObject = errorObject;
    }

    @JsonProperty("redirect_uri")
    public String getRedirectUri() {
        return redirectUri;
    }

    @JsonProperty("oauth_error")
    public JSONObject getErrorObject() {
        return errorObject;
    }
}
