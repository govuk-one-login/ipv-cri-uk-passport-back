package uk.gov.di.ipv.cri.passport.library.domain.verifiablecredential;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonProperty;
import uk.gov.di.ipv.cri.passport.library.domain.DcsResponse;

import java.time.LocalDate;
import java.util.UUID;

public class CredentialSubject {

    @JsonProperty private final Name name;
    @JsonProperty private final String passportNumber;

    @JsonProperty
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd")
    private final BirthDate birthDate;

    @JsonProperty
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd")
    private final LocalDate expiryDate;

    @JsonProperty private final UUID requestId;
    @JsonProperty private final UUID correlationId;
    @JsonProperty private final DcsResponse dcsResponse;

    @JsonCreator
    public CredentialSubject(
            @JsonProperty(value = "name", required = true) Name name,
            @JsonProperty(value = "passportNumber", required = true) String passportNumber,
            @JsonProperty(value = "birthDate", required = true) BirthDate birthDate,
            @JsonProperty(value = "expiryDate", required = true) LocalDate expiryDate,
            @JsonProperty(value = "requestId", required = true) UUID requestId,
            @JsonProperty(value = "correlationId", required = true) UUID correlationId,
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

    public LocalDate getExpiryDate() {
        return expiryDate;
    }

    public UUID getRequestId() {
        return requestId;
    }

    public UUID getCorrelationId() {
        return correlationId;
    }

    public DcsResponse getDcsResponse() {
        return dcsResponse;
    }

    public static class Builder {
        private Name name;
        private String passportNumber;
        private BirthDate birthDate;
        private LocalDate expiryDate;
        private UUID requestId;
        private UUID correlationId;
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

        public Builder setExpiryDate(LocalDate expiryDate) {
            this.expiryDate = expiryDate;
            return this;
        }

        public Builder setRequestId(UUID requestId) {
            this.requestId = requestId;
            return this;
        }

        public Builder setCorrelationId(UUID correlationId) {
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
