package uk.gov.di.ipv.cri.passport.domain;

import uk.gov.di.ipv.cri.passport.annotations.ExcludeFromGeneratedCoverageReport;

public class ProtectedHeader {
    private final String algorithm;
    private final String sha1Thumbprint;
    private final String sha256Thumbprint;

    @ExcludeFromGeneratedCoverageReport
    public ProtectedHeader(String algorithm, String sha1Thumbprint, String sha256Thumbprint) {
        this.algorithm = algorithm;
        this.sha1Thumbprint = sha1Thumbprint;
        this.sha256Thumbprint = sha256Thumbprint;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public String getSha1Thumbprint() {
        return sha1Thumbprint;
    }

    public String getSha256Thumbprint() {
        return sha256Thumbprint;
    }
}
