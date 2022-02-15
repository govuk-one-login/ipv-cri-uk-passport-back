package uk.gov.di.ipv.cri.passport.dcscredential.domain;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonProperty;
import uk.gov.di.ipv.cri.passport.library.domain.DcsResponse;
import uk.gov.di.ipv.cri.passport.library.domain.PassportGpg45Score;
import uk.gov.di.ipv.cri.passport.library.persistence.item.PassportCheckDao;

import java.time.LocalDate;
import java.util.UUID;

public class PassportCredentialIssuerResponse {

    @JsonProperty private String resourceId;
    @JsonProperty private Attributes attributes;
    @JsonProperty private PassportGpg45Score gpg45Score;

    public PassportCredentialIssuerResponse() {}

    public PassportCredentialIssuerResponse(
            String resourceId, Attributes attributes, PassportGpg45Score gpg45Score) {
        this.resourceId = resourceId;
        this.attributes = attributes;
        this.gpg45Score = gpg45Score;
    }

    public static PassportCredentialIssuerResponse fromPassportCheckDao(
            PassportCheckDao credential) {
        Attributes attributes =
                new Attributes.Builder()
                        .setNames(
                                new Name(
                                        credential.getAttributes().getSurname(),
                                        credential.getAttributes().getForenames()))
                        .setPassportNumber(credential.getAttributes().getPassportNumber())
                        .setDateOfBirth(credential.getAttributes().getDateOfBirth())
                        .setExpiryDate(credential.getAttributes().getExpiryDate())
                        .setRequestId(credential.getAttributes().getRequestId())
                        .setCorrelationId(credential.getAttributes().getCorrelationId())
                        .setDcsResponse(credential.getAttributes().getDcsResponse())
                        .build();
        return new PassportCredentialIssuerResponse(
                credential.getResourceId(), attributes, credential.getGpg45Score());
    }

    public String getResourceId() {
        return resourceId;
    }

    public Attributes getAttributes() {
        return attributes;
    }

    public PassportGpg45Score getGpg45Score() {
        return gpg45Score;
    }

    public static class Attributes {

        @JsonProperty private final Name names;
        @JsonProperty private final String passportNumber;

        @JsonProperty
        @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd")
        private final LocalDate dateOfBirth;

        @JsonProperty
        @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd")
        private final LocalDate expiryDate;

        @JsonProperty private final UUID requestId;
        @JsonProperty private final UUID correlationId;
        @JsonProperty private final DcsResponse dcsResponse;

        @JsonCreator
        public Attributes(
                @JsonProperty(value = "names", required = true) Name names,
                @JsonProperty(value = "passportNumber", required = true) String passportNumber,
                @JsonProperty(value = "dateOfBirth", required = true) LocalDate dateOfBirth,
                @JsonProperty(value = "expiryDate", required = true) LocalDate expiryDate,
                @JsonProperty(value = "requestId", required = true) UUID requestId,
                @JsonProperty(value = "correlationId", required = true) UUID correlationId,
                @JsonProperty(value = "dcsResponse", required = true) DcsResponse dcsResponse) {
            this.names = names;
            this.passportNumber = passportNumber;
            this.dateOfBirth = dateOfBirth;
            this.expiryDate = expiryDate;
            this.requestId = requestId;
            this.correlationId = correlationId;
            this.dcsResponse = dcsResponse;
        }

        public Name getNames() {
            return names;
        }

        public String getPassportNumber() {
            return passportNumber;
        }

        public LocalDate getDateOfBirth() {
            return dateOfBirth;
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
            private Name names;
            private String passportNumber;
            private LocalDate dateOfBirth;
            private LocalDate expiryDate;
            private UUID requestId;
            private UUID correlationId;
            private DcsResponse dcsResponse;

            public Builder setNames(Name names) {
                this.names = names;
                return this;
            }

            public Builder setPassportNumber(String passportNumber) {
                this.passportNumber = passportNumber;
                return this;
            }

            public Builder setDateOfBirth(LocalDate dateOfBirth) {
                this.dateOfBirth = dateOfBirth;
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

            public Attributes build() {
                return new Attributes(
                        names,
                        passportNumber,
                        dateOfBirth,
                        expiryDate,
                        requestId,
                        correlationId,
                        dcsResponse);
            }
        }
    }
}
