package uk.gov.di.ipv.cri.passport.library.exceptions;

import com.nimbusds.oauth2.sdk.ErrorObject;
import uk.gov.di.ipv.cri.passport.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
public class RecoverableJarValidationException extends JarValidationException {
    private final String redirectUri;

    public RecoverableJarValidationException(ErrorObject errorObject, String redirectUri) {
        super(errorObject);
        this.redirectUri = redirectUri;
    }

    public String getRedirectUri() {
        return this.redirectUri;
    }
}
