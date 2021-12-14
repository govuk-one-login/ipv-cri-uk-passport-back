package uk.gov.di.ipv.cri.passport.dto;

import java.time.Instant;

public class DcsCheckRequestDto {

    private String passportNumber;
    private String surname;
    private String forenames;
    private Instant dateOfBirth;
    private Instant expiryDate;

    public DcsCheckRequestDto() {};

    public DcsCheckRequestDto(
            String passportNumber,
            String surname,
            String forenames,
            Instant dateOfBirth,
            Instant expiryDate) {
        this.passportNumber = passportNumber;
        this.surname = surname;
        this.forenames = forenames;
        this.dateOfBirth = dateOfBirth;
        this.expiryDate = expiryDate;
    }

    public String getPassportNumber() {
        return passportNumber;
    }

    public String getSurname() { return surname; }

    public String getForenames() {
        return forenames;
    }

    public Instant getDateOfBirth() {
        return dateOfBirth;
    }

    public Instant getExpiryDate() {
        return expiryDate;
    }
}
