package uk.gov.di.ipv.cri.passport.exceptions;

import uk.gov.di.ipv.cri.passport.annotations.ExcludeFromGeneratedCoverageReport;

public class IpvCryptoException extends RuntimeException {

    @ExcludeFromGeneratedCoverageReport
    public IpvCryptoException(String message) {
        super(message);
    }
}
