package uk.gov.di.ipv.cri.passport.library.exceptions;

import com.nimbusds.oauth2.sdk.ErrorObject;
import uk.gov.di.ipv.cri.passport.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
public class RecoverableJarValidationException extends JarValidationException {
    private final String redirectUri;
    private final String state;

    public RecoverableJarValidationException(
            ErrorObject errorObject, String redirectUri, String state) {
        super(errorObject);
        this.redirectUri = redirectUri;
        this.state = state;
    }

    public String getRedirectUri() {
        return this.redirectUri;
    }

    public String getState() {
        return this.state;
    }
}
