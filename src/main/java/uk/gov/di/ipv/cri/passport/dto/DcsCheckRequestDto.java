package uk.gov.di.ipv.cri.passport.dto;

import java.util.Date;

public class DcsCheckRequestDto {

    private String passportNumber;
    private String surname;
    private String forenames;
    private Date dateOfBirth;
    private Date expiryDate;

    public DcsCheckRequestDto() {};

    public DcsCheckRequestDto(
            String passportNumber,
            String surname,
            String forenames,
            Date dateOfBirth,
            Date expiryDate) {
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

    public Date getDateOfBirth() {
        return dateOfBirth;
    }

    public Date getExpiryDate() {
        return expiryDate;
    }
}
