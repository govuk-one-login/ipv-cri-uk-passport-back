package uk.gov.di.ipv.cri.passport.library.exceptions;

import com.nimbusds.oauth2.sdk.ErrorObject;
import uk.gov.di.ipv.cri.passport.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
public class SharedAttributesValidationException extends Exception {
    private final ErrorObject errorObject;

    public SharedAttributesValidationException(ErrorObject errorObject) {
        this.errorObject = errorObject;
    }

    public ErrorObject getErrorObject() {
        return errorObject;
    }
}
