package uk.gov.di.ipv.cri.passport.exceptions;

import uk.gov.di.ipv.cri.passport.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
public class EmptyDcsResponseException extends Throwable {
    public EmptyDcsResponseException(String message) {
        super(message);
    }
}
