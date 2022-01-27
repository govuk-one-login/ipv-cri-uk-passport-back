package uk.gov.di.ipv.cri.passport.library.domain;

import com.google.gson.annotations.SerializedName;
import uk.gov.di.ipv.cri.passport.library.annotations.ExcludeFromGeneratedCoverageReport;

public class ProtectedHeader {
    @SerializedName("alg")
    private final String algorithm;

    @SerializedName("x5t")
    private final String sha1Thumbprint;

    @SerializedName("x5t#S256")
    private final String sha256Thumbprint;

    @ExcludeFromGeneratedCoverageReport
    public ProtectedHeader(String algorithm, String sha1Thumbprint, String sha256Thumbprint) {
        this.algorithm = algorithm;
        this.sha1Thumbprint = sha1Thumbprint;
        this.sha256Thumbprint = sha256Thumbprint;
    }
}
