package uk.gov.di.ipv.cri.passport.acceptance_tests.utilities;

public class PassportSubject implements TestInput {

    private String passportNumber,
            lastName,
            firstName,
            middleNames,
            birthDay,
            birthMonth,
            birthYear,
            validToDay,
            validToMonth,
            validToYear;

    PassportSubject(
            String passportNumber,
            String lastName,
            String firstName,
            String middleNames,
            String birthDay,
            String birthMonth,
            String birthYear,
            String validToDay,
            String validToMonth,
            String validToYear) {
        this.passportNumber = passportNumber;
        this.lastName = lastName;
        this.firstName = firstName;
        this.middleNames = middleNames;
        this.birthDay = birthDay;
        this.birthMonth = birthMonth;
        this.birthYear = birthYear;
        this.validToDay = validToDay;
        this.validToMonth = validToMonth;
        this.validToYear = validToYear;
    }

    PassportSubject(PassportSubject passportSubject) {
        this.passportNumber = passportSubject.passportNumber;
        this.lastName = passportSubject.lastName;
        this.firstName = passportSubject.firstName;
        this.middleNames = passportSubject.middleNames;
        this.birthDay = passportSubject.birthDay;
        this.birthMonth = passportSubject.birthMonth;
        this.birthYear = passportSubject.birthYear;
        this.validToDay = passportSubject.validToDay;
        this.validToMonth = passportSubject.validToMonth;
        this.validToYear = passportSubject.validToYear;
    }

    @Override
    public String getPassportNumber() {
        return passportNumber;
    }

    public void setPassportNumber(String passportNumber) {
        this.passportNumber = passportNumber;
    }

    public String getLastName() {
        return lastName;
    }

    public void setLastName(String lastName) {
        this.lastName = lastName;
    }

    public String getFirstName() {
        return firstName;
    }

    @Override
    public String getMiddleNames() {
        return middleNames;
    }

    public void setMiddleNames(String middleNames) {
        this.middleNames = middleNames;
    }

    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }

    public String getBirthDay() {
        return birthDay;
    }

    public void setBirthDay(String birthDay) {
        this.birthDay = birthDay;
    }

    public String getBirthMonth() {
        return birthMonth;
    }

    public void setBirthMonth(String birthMonth) {
        this.birthMonth = birthMonth;
    }

    public String getBirthYear() {
        return birthYear;
    }

    public void setBirthYear(String birthYear) {
        this.birthYear = birthYear;
    }

    public String getValidToDay() {
        return validToDay;
    }

    public void setValidToDay(String validToDay) {
        this.validToDay = validToDay;
    }

    public String getValidToMonth() {
        return validToMonth;
    }

    public void setValidToMonth(String validToMonth) {
        this.validToMonth = validToMonth;
    }

    public String getValidToYear() {
        return validToYear;
    }

    public void setValidToYear(String validToYear) {
        this.validToYear = validToYear;
    }
}
