package uk.gov.di.ipv.cri.passport.domain;

public class ProtectedHeader {
    public String algorithm;
    public String sha1Thumbprint;
    public String sha256Thumbprint;

    public ProtectedHeader(String algorithm, String sha1Thumbprint, String sha256Thumbprint) {
        this.algorithm = algorithm;
        this.sha1Thumbprint = sha1Thumbprint;
        this.sha256Thumbprint = sha256Thumbprint;
    }
}
