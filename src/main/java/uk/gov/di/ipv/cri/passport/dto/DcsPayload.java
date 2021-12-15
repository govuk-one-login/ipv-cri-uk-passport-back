package uk.gov.di.ipv.cri.passport.dto;

import java.sql.Timestamp;
import java.util.Date;
import java.util.UUID;

public class DcsPayload {
    private final UUID correlationId;
    private final UUID requestId;
    private final Timestamp timestamp;
    private final String passportNumber;
    private final String surname;
    private final String[] forenames;

    //@JsonAdapter(InstantShortDateAdapter.class)
    private final Date dateOfBirth;

    //@JsonAdapter(InstantShortDateAdapter.class)
    private final Date expiryDate;

    public DcsPayload(UUID correlationId, UUID requestId, Timestamp timestamp, String passportNumber, String surname, String[] forenames, Date dateOfBirth, Date expiryDate) {
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

    public Timestamp getTimestamp() {
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

    public Date getDateOfBirth() {
        return dateOfBirth;
    }

    public Date getExpiryDate() {
        return expiryDate;
    }

}
