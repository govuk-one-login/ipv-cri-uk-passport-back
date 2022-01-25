package uk.gov.di.ipv.cri.passport.library.exceptions;

import uk.gov.di.ipv.cri.passport.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
public class EmptyDcsResponseException extends Exception {
    public EmptyDcsResponseException(String message) {
        super(message);
    }
}
