package uk.gov.di.ipv.cri.passport.domain;

import com.google.gson.annotations.SerializedName;

public class ProtectedHeader {
    @SerializedName("alg")
    String algorithm;

    @SerializedName("x5t")
    String sha1Thumbprint;

    @SerializedName("x5t#S256")
    String sha256Thumbprint;

    @SerializedName("enc")
    String encoding;

    @SerializedName("typ")
    String type;

    public ProtectedHeader(String algorithm, String sha1Thumbprint, String sha256Thumbprint) {
        this.algorithm = algorithm;
        this.sha1Thumbprint = sha1Thumbprint;
        this.sha256Thumbprint = sha256Thumbprint;

    }
}
