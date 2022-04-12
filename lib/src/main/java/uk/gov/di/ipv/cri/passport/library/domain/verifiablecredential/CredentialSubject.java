package uk.gov.di.ipv.cri.passport.library.domain.verifiablecredential;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonProperty;
import uk.gov.di.ipv.cri.passport.library.domain.DcsResponse;

public class CredentialSubject {

    @JsonProperty private final Name name;
    @JsonProperty private final String passportNumber;

    @JsonProperty
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd")
    private final BirthDate birthDate;

    @JsonProperty
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd")
    private final String expiryDate;

    @JsonProperty private final String requestId;
    @JsonProperty private final String correlationId;
    @JsonProperty private final DcsResponse dcsResponse;

    @JsonCreator
    public CredentialSubject(
            @JsonProperty(value = "name", required = true) Name name,
            @JsonProperty(value = "passportNumber", required = true) String passportNumber,
            @JsonProperty(value = "birthDate", required = true) BirthDate birthDate,
            @JsonProperty(value = "expiryDate", required = true) String expiryDate,
            @JsonProperty(value = "requestId", required = true) String requestId,
            @JsonProperty(value = "correlationId", required = true) String correlationId,
            @JsonProperty(value = "dcsResponse", required = true) DcsResponse dcsResponse) {
        this.name = name;
        this.passportNumber = passportNumber;
        this.birthDate = birthDate;
        this.expiryDate = expiryDate;
        this.requestId = requestId;
        this.correlationId = correlationId;
        this.dcsResponse = dcsResponse;
    }

    public Name getName() {
        return name;
    }

    public String getPassportNumber() {
        return passportNumber;
    }

    public BirthDate getBirthDate() {
        return birthDate;
    }

    public String getExpiryDate() {
        return expiryDate;
    }

    public String getRequestId() {
        return requestId;
    }

    public String getCorrelationId() {
        return correlationId;
    }

    public DcsResponse getDcsResponse() {
        return dcsResponse;
    }

    public static class Builder {
        private Name name;
        private String passportNumber;
        private BirthDate birthDate;
        private String expiryDate;
        private String requestId;
        private String correlationId;
        private DcsResponse dcsResponse;

        public Builder setName(Name name) {
            this.name = name;
            return this;
        }

        public Builder setPassportNumber(String passportNumber) {
            this.passportNumber = passportNumber;
            return this;
        }

        public Builder setBirthDate(BirthDate birthDate) {
            this.birthDate = birthDate;
            return this;
        }

        public Builder setExpiryDate(String expiryDate) {
            this.expiryDate = expiryDate;
            return this;
        }

        public Builder setRequestId(String requestId) {
            this.requestId = requestId;
            return this;
        }

        public Builder setCorrelationId(String correlationId) {
            this.correlationId = correlationId;
            return this;
        }

        public Builder setDcsResponse(DcsResponse dcsResponse) {
            this.dcsResponse = dcsResponse;
            return this;
        }

        public CredentialSubject build() {
            return new CredentialSubject(
                    name,
                    passportNumber,
                    birthDate,
                    expiryDate,
                    requestId,
                    correlationId,
                    dcsResponse);
        }
    }
}
