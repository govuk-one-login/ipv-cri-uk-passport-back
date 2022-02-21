package uk.gov.di.ipv.cri.passport.library.exceptions;

import uk.gov.di.ipv.cri.passport.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
public class UnknownClientException extends RuntimeException {
    public UnknownClientException(String message) {
        super(message);
    }
}
