package uk.gov.di.ipv.cri.passport.library.error;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import net.minidev.json.JSONObject;

public class RedirectErrorResponse {
    private final String redirectUri;
    private final String state;
    private final JSONObject errorObject;

    public RedirectErrorResponse(String redirectUri, String state, JSONObject errorObject) {
        this.redirectUri = redirectUri;
        this.state = state;
        this.errorObject = errorObject;
    }

    @JsonProperty("redirect_uri")
    public String getRedirectUri() {
        return redirectUri;
    }

    @JsonProperty("state")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public String getState() {
        return state;
    }

    @JsonProperty("oauth_error")
    public JSONObject getErrorObject() {
        return errorObject;
    }
}
