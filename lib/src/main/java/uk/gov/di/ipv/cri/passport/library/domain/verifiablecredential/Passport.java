package uk.gov.di.ipv.cri.passport.library.domain.verifiablecredential;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonProperty;

public class Passport {
    private String documentNumber;

    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd")
    private String expiryDate;

    public Passport(
            @JsonProperty(value = "documentNumber") String documentNumber,
            @JsonProperty(value = "expiryDate") String expiryDate) {
        this.documentNumber = documentNumber;
        this.expiryDate = expiryDate;
    }

    public String getDocumentNumber() {
        return documentNumber;
    }

    public void setDocumentNumber(String documentNumber) {
        this.documentNumber = documentNumber;
    }

    public String getExpiryDate() {
        return expiryDate;
    }

    public void setExpiryDate(String expiryDate) {
        this.expiryDate = expiryDate;
    }
}
