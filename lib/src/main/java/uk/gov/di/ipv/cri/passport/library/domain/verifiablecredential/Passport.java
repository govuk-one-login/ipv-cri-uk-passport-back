package uk.gov.di.ipv.cri.passport.library.domain.verifiablecredential;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonProperty;

public class Passport {
    private String documentNumber;
    private String icaoIssuerCode;

    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd")
    private String expiryDate;

    public Passport(
            @JsonProperty(value = "documentNumber") String documentNumber,
            @JsonProperty(value = "expiryDate") String expiryDate,
            @JsonProperty(value = "icaoIssuerCode") String icaoIssuerCode) {
        this.documentNumber = documentNumber;
        this.expiryDate = expiryDate;
        this.icaoIssuerCode = icaoIssuerCode;
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

    public String getIcaoIssuerCode() {
        return icaoIssuerCode;
    }

    public void setIcaoIssuerCode(String icaoIssuerCode) {
        this.icaoIssuerCode = icaoIssuerCode;
    }
}
