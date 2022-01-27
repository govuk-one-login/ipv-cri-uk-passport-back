package uk.gov.di.ipv.cri.passport.library.domain;

public class DcsSignedEncryptedResponse {
    private final String payload;

    public DcsSignedEncryptedResponse(String payload) {
        this.payload = payload;
    }

    public String getPayload() {
        return payload;
    }
}
