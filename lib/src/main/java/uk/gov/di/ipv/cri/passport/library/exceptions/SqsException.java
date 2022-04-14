package uk.gov.di.ipv.cri.passport.library.exceptions;

import uk.gov.di.ipv.cri.passport.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
public class SqsException extends Exception {
    public SqsException(Throwable e) {
        super(e);
    }

    public SqsException(String errorMessage) {
        super(errorMessage);
    }
}
