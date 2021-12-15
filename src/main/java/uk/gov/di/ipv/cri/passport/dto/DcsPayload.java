package uk.gov.di.ipv.cri.passport.dto;

import java.time.Instant;
import java.util.UUID;

public class DcsPayload {
    private final UUID correlationId;
    private final UUID requestId;
    private final Instant timestamp;
    private final String passportNumber;
    private final String surname;
    private final String[] forenames;

    //@JsonAdapter(InstantShortDateAdapter.class)
    private final Instant dateOfBirth;

    //@JsonAdapter(InstantShortDateAdapter.class)
    private final Instant expiryDate;

    public DcsPayload(UUID correlationId, UUID requestId, Instant timestamp, String passportNumber, String surname, String[] forenames, Instant dateOfBirth, Instant expiryDate) {
        this.correlationId = correlationId;
        this.requestId = requestId;
        this.timestamp = timestamp;
        this.passportNumber = passportNumber;
        this.surname = surname;
        this.forenames = forenames;
        this.dateOfBirth = dateOfBirth;
        this.expiryDate = expiryDate;
    }

    public UUID getCorrelationId() {
        return correlationId;
    }

    public UUID getRequestId() {
        return requestId;
    }

    public Instant getTimestamp() {
        return timestamp;
    }

    public String getPassportNumber() {
        return passportNumber;
    }

    public String getSurname() {
        return surname;
    }

    public String[] getForenames() {
        return forenames;
    }

    public Instant getDateOfBirth() {
        return dateOfBirth;
    }

    public Instant getExpiryDate() {
        return expiryDate;
    }

}
