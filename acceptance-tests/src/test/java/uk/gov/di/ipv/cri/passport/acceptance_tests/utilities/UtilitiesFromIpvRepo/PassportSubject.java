package uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.UtilitiesFromIpvRepo;

public enum PassportSubject implements TestInput {
    PassportSubjectHappyDanny(
            "543543543", "Smith", "Danny", "27", "08", "1995", "01", "01", "2030"),
    PassportSubjectHappyKenneth(
            "321654987", "DECERQUEIRA", "KENNETH", "08", "07", "1965", "01", "01", "2030"),
    PassportSubjectHappyArkil(
            "543543900", "ALBERT", "ARKIL", "05", "10", "1943", "01", "01", "2030"),
    PassportSubjectHappySuzie(
            "543543542", "SHREEVE", "SUZIE", "09", "08", "1985", "01", "01", "2030"),
    PassportSubjectHappySandra(
            "543543541", "DRYSDALE", "SANDRA", "18", "05", "1970", "01", "01", "2030"),
    PassportSubjectHappyBen("543543540", "OMEARA", "BEN", "05", "02", "1974", "01", "01", "2030"),
    PassportSubjectHappyAlex(
            "543543539", "ELEGBA", "ALEXANDRA", "21", "06", "1993", "01", "01", "2030"),
    PassportSubjectHappyMichelle(
            "543543538", "KABIR", "MICHELLE", "28", "07", "1981", "01", "01", "2030"),
    PassportSubjectInvalid("123456789", "Smith", "Danny", "27", "08", "1995", "01", "01", "2030"),
    InvalidPassportNumber(
            "ABCDEFGHI", "DECERQUEIRA", "KENNETH", "23", "08", "1959", "01", "01", "2030"),
    InvalidfirstName("321654987", "DECERQUEIRA", "KENNE£4", "23", "08", "1959", "01", "01", "2030"),
    Invalidsurname("321654987", "DECERQ&^%3RA", "KENNETH", "23", "08", "1959", "01", "01", "2030"),
    InvalidDateofBirth(
            "321654987", "DECERQUEIRA", "KENNETH", "23", "13", "1959", "01", "01", "2030"),
    InvalidPassport("123456789", "DECERQUEIRA", "KENNETH", "23", "08", "1959", "01", "01", "2030"),
    InvalidExpiryDate(
            "321654987", "DECERQUEIRA", "KENNETH", "23", "08", "1959", "41", "01", "2030");

    public String passportNumber;
    public String surname;
    public String givenName;
    public String birthDay;
    public String birthMonth;
    public String birthYear;
    public String expiryDay;
    public String expiryMonth;
    public String expiryYear;

    PassportSubject(
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

    public String getpassportNumber() {
        return passportNumber;
    }

    public String getsurname() {
        return surname;
    }

    public String getgivenName() {
        return givenName;
    }

    public String getbirthDay() {
        return birthDay;
    }

    public String getbirthMonth() {
        return birthMonth;
    }

    public String getbirthYear() {
        return birthYear;
    }

    public String getexpiryDay() {
        return expiryDay;
    }

    public String getexpiryMonth() {
        return expiryMonth;
    }

    public String getexpiryYear() {
        return expiryYear;
    }
}
