package uk.gov.di.ipv.cri.passport.library.exceptions;

import uk.gov.di.ipv.cri.passport.library.annotations.ExcludeFromGeneratedCoverageReport;

public class IpvCryptoException extends RuntimeException {

    @ExcludeFromGeneratedCoverageReport
    public IpvCryptoException(String message) {
        super(message);
    }
}
