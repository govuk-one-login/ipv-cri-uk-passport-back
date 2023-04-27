package uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.UtilitiesFromIpvRepo;

public enum InvalidPassportSubject implements TestInput {
    PassportSubjectInvalid(
            "543543543", "Testlastname", "Testfirstname", "10", "12", "1970", "01", "01", "2040"),
    PassportSubjectInvalid2(
            "393945342", "Testlast", "Testfirst", "15", "12", "1970", "01", "01", "2030");

    public String passportNumber;
    public String surname;
    public String givenName;
    public String birthDay;
    public String birthMonth;
    public String birthYear;
    public String expiryDay;
    public String expiryMonth;
    public String expiryYear;

    InvalidPassportSubject(
            String passportNumber,
            String surname,
            String givenName,
            String birthDay,
            String birthMonth,
            String birthYear,
            String expiryDay,
            String expiryMonth,
            String expiryYear) {
        this.passportNumber = passportNumber;
        this.surname = surname;
        this.givenName = givenName;
        this.birthDay = birthDay;
        this.birthMonth = birthMonth;
        this.birthYear = birthYear;
        this.expiryDay = expiryDay;
        this.expiryMonth = expiryMonth;
        this.expiryYear = expiryYear;
    }

    public String getinvalidpassportNumber() {
        return passportNumber;
    }

    public String getinvalidsurname() {
        return surname;
    }

    public String getinvalidgivenName() {
        return givenName;
    }

    public String getinvalidbirthDay() {
        return birthDay;
    }

    public String getinvalidbirthMonth() {
        return birthMonth;
    }

    public String getinvalidbirthYear() {
        return birthYear;
    }

    public String getinvalidexpiryDay() {
        return expiryDay;
    }

    public String getinvalidexpiryMonth() {
        return expiryMonth;
    }

    public String getinvalidexpiryYear() {
        return expiryYear;
    }
}
