package uk.gov.di.ipv.cri.passport.acceptance_tests.utilities;

import java.util.HashMap;
import java.util.Map;

public class TestDataCreator {

    public static Map<String, TestInput> passportTestUsers = new HashMap<>();

    public static PassportSubject kennethHappyPath;
    public static PassportSubject selinaUnhappyPath;
    public static PassportSubject kennethIncorrectPassportNumber;
    public static PassportSubject kennethIncorrectDateOfBirth;
    public static PassportSubject kennethIncorrectLastName;
    public static PassportSubject kennethIncorrectFirstName;
    public static PassportSubject kennethIncorrectIssueDate;
    public static PassportSubject kennethIncorrectValidToDate;
    public static PassportSubject kennethIncorrectPostcode;
    public static PassportSubject kennethLastNameWithNumbers;
    public static PassportSubject kennethIncorrectLastNameWithSpecialChars;
    public static PassportSubject kennethIncorrectNoSecondName;
    public static PassportSubject kennethIncorrectFirstNameWithNumbers;
    public static PassportSubject kennethIncorrectFirstNameWithSpecialChars;
    public static PassportSubject kennethIncorrectNoFirstName;
    public static PassportSubject kennethIncorrectMiddleNameWithSpecialChars;
    public static PassportSubject kennethIncorrectMiddleNameWithNumbers;
    public static PassportSubject kennethIncorrectInvalidDateOfBirth;
    public static PassportSubject kennethIncorrectDoBWithSpecialChars;
    public static PassportSubject kennethIncorrectDoBInFuture;
    public static PassportSubject kennethIncorrectNoDoB;
    public static PassportSubject kennethIncorrectInvalidIssueDate;
    public static PassportSubject kennethIncorrectIssueDateWithSpecialChars;
    public static PassportSubject kennethIncorrectIssueDateInFuture;
    public static PassportSubject kennethIncorrectInvalidToDate;
    public static PassportSubject kennethIncorrectValidToDateWithSpecialChars;
    public static PassportSubject kennethValidToDateInPast;
    public static PassportSubject kennethIncorrectNoValidToDate;
    public static PassportSubject kennethIncorrectLessThan8Chars;
    public static PassportSubject kennethIncorrectPassportNumberWithSpecialChars;
    public static PassportSubject kennethIncorrectPassportNumberWithAlphanumerics;
    public static PassportSubject kennethIncorrectPassportNumberWithAlphaChars;
    public static PassportSubject kennethIncorrectNoPassportNumber;
    public static PassportSubject kennethIncorrectNoPostcode;

    public static void createDefaultResponses() {
        kennethHappyPath =
                new PassportSubject(
                        "321654987",
                        "DECERQUEIRA",
                        "KENNETH",
                        "",
                        "08",
                        "07",
                        "1965",
                        "01",
                        "10",
                        "2042");
        selinaUnhappyPath =
                new PassportSubject(
                        "88776655", "KYLE", "SELINA", "", "12", "08", "1985", "04", "08", "2032");

        kennethIncorrectPassportNumber = new PassportSubject(kennethHappyPath);
        kennethIncorrectPassportNumber.setPassportNumber("887766551");

        kennethIncorrectDateOfBirth = new PassportSubject(kennethHappyPath);
        kennethIncorrectDateOfBirth.setBirthDay("12");
        kennethIncorrectDateOfBirth.setBirthMonth("08");
        kennethIncorrectDateOfBirth.setBirthYear("1985");

        kennethIncorrectLastName = new PassportSubject(kennethHappyPath);
        kennethIncorrectLastName.setLastName("KYLE");

        kennethIncorrectFirstName = new PassportSubject(kennethHappyPath);
        kennethIncorrectFirstName.setFirstName("SELINA");

        kennethIncorrectValidToDate = new PassportSubject(kennethHappyPath);
        kennethIncorrectValidToDate.setValidToDay("04");
        kennethIncorrectValidToDate.setValidToMonth("08");
        kennethIncorrectValidToDate.setValidToYear("2032");

        kennethLastNameWithNumbers = new PassportSubject(kennethHappyPath);
        kennethLastNameWithNumbers.setLastName("KYLE123");

        kennethIncorrectLastNameWithSpecialChars = new PassportSubject(kennethHappyPath);
        kennethIncorrectLastNameWithSpecialChars.setLastName("KYLE^&(");

        kennethIncorrectNoSecondName = new PassportSubject(kennethHappyPath);
        kennethIncorrectNoSecondName.setLastName("");

        kennethIncorrectFirstNameWithNumbers = new PassportSubject(kennethHappyPath);
        kennethIncorrectFirstNameWithNumbers.setFirstName("SELINA987");

        kennethIncorrectFirstNameWithSpecialChars = new PassportSubject(kennethHappyPath);
        kennethIncorrectFirstNameWithSpecialChars.setFirstName("SELINA%$@");

        kennethIncorrectMiddleNameWithSpecialChars = new PassportSubject(kennethHappyPath);
        kennethIncorrectMiddleNameWithSpecialChars.setMiddleNames("SELINA%$@");

        kennethIncorrectMiddleNameWithNumbers = new PassportSubject(kennethHappyPath);
        kennethIncorrectMiddleNameWithNumbers.setMiddleNames("SELINA987");

        kennethIncorrectNoFirstName = new PassportSubject(kennethHappyPath);
        kennethIncorrectNoFirstName.setFirstName("");

        kennethIncorrectInvalidDateOfBirth = new PassportSubject(kennethHappyPath);
        kennethIncorrectInvalidDateOfBirth.setBirthDay("51");
        kennethIncorrectInvalidDateOfBirth.setBirthMonth("71");
        kennethIncorrectInvalidDateOfBirth.setBirthYear("198");

        kennethIncorrectDoBWithSpecialChars = new PassportSubject(kennethHappyPath);
        kennethIncorrectDoBWithSpecialChars.setBirthDay("@");
        kennethIncorrectDoBWithSpecialChars.setBirthMonth("*&");
        kennethIncorrectDoBWithSpecialChars.setBirthYear("19 7");

        kennethIncorrectDoBInFuture = new PassportSubject(kennethHappyPath);
        kennethIncorrectDoBInFuture.setBirthDay("10");
        kennethIncorrectDoBInFuture.setBirthMonth("10");
        kennethIncorrectDoBInFuture.setBirthYear("2042");

        kennethIncorrectNoDoB = new PassportSubject(kennethHappyPath);
        kennethIncorrectNoDoB.setBirthDay("");
        kennethIncorrectNoDoB.setBirthMonth("");
        kennethIncorrectNoDoB.setBirthYear("");

        kennethIncorrectInvalidToDate = new PassportSubject(kennethHappyPath);
        kennethIncorrectInvalidToDate.setValidToDay("50");
        kennethIncorrectInvalidToDate.setValidToMonth("10");
        kennethIncorrectInvalidToDate.setValidToYear("2030");

        kennethIncorrectValidToDateWithSpecialChars = new PassportSubject(kennethHappyPath);
        kennethIncorrectValidToDateWithSpecialChars.setValidToDay("!@");
        kennethIncorrectValidToDateWithSpecialChars.setValidToMonth("£$");
        kennethIncorrectValidToDateWithSpecialChars.setValidToYear("%^ *");

        kennethValidToDateInPast = new PassportSubject(kennethHappyPath);
        kennethValidToDateInPast.setValidToDay("10");
        kennethValidToDateInPast.setValidToMonth("01");
        kennethValidToDateInPast.setValidToYear("2010");

        kennethIncorrectNoValidToDate = new PassportSubject(kennethHappyPath);
        kennethIncorrectNoValidToDate.setValidToDay("");
        kennethIncorrectNoValidToDate.setValidToMonth("");
        kennethIncorrectNoValidToDate.setValidToYear("");

        kennethIncorrectLessThan8Chars = new PassportSubject(kennethHappyPath);
        kennethIncorrectLessThan8Chars.setPassportNumber("5566778");

        kennethIncorrectPassportNumberWithSpecialChars = new PassportSubject(kennethHappyPath);
        kennethIncorrectPassportNumberWithSpecialChars.setPassportNumber("555667^&*");

        kennethIncorrectPassportNumberWithAlphanumerics = new PassportSubject(kennethHappyPath);
        kennethIncorrectPassportNumberWithAlphanumerics.setPassportNumber("555667ABC");

        kennethIncorrectPassportNumberWithAlphaChars = new PassportSubject(kennethHappyPath);
        kennethIncorrectPassportNumberWithAlphaChars.setPassportNumber("XYZabdABC");

        kennethIncorrectNoPassportNumber = new PassportSubject(kennethHappyPath);
        kennethIncorrectNoPassportNumber.setPassportNumber("");

        passportTestUsers.put("PassportSubjectHappyBilly", kennethHappyPath);
        passportTestUsers.put("PassportSubjectUnhappySelina", selinaUnhappyPath);
        passportTestUsers.put("NoLastName", kennethIncorrectNoSecondName);
        passportTestUsers.put("NoFirstName", kennethIncorrectNoFirstName);
        passportTestUsers.put("NoDateOfBirth", kennethIncorrectNoDoB);
        passportTestUsers.put("NoValidToDate", kennethIncorrectNoValidToDate);
        passportTestUsers.put("NoPassportNumber", kennethIncorrectNoPassportNumber);
        passportTestUsers.put("NoPostcode", kennethIncorrectNoPostcode);
        passportTestUsers.put("InvalidFirstNameWithNumbers", kennethIncorrectFirstNameWithNumbers);
        passportTestUsers.put(
                "InvalidFirstNameWithSpecialCharacters", kennethIncorrectFirstNameWithSpecialChars);
        passportTestUsers.put(
                "DateOfBirthWithSpecialCharacters", kennethIncorrectDoBWithSpecialChars);
        passportTestUsers.put("InvalidDateOfBirth", kennethIncorrectInvalidDateOfBirth);
        passportTestUsers.put("IncorrectDateOfBirth", kennethIncorrectDateOfBirth);
        passportTestUsers.put(
                "IssueDateWithSpecialCharacters", kennethIncorrectIssueDateWithSpecialChars);
        passportTestUsers.put(
                "ValidToDateWithSpecialCharacters", kennethIncorrectValidToDateWithSpecialChars);
        passportTestUsers.put("ValidToDateInPast", kennethValidToDateInPast);
        passportTestUsers.put(
                "PassportNumberWithSpecialChar", kennethIncorrectPassportNumberWithSpecialChars);
        passportTestUsers.put(
                "PassportNumberWithAlphaChar", kennethIncorrectPassportNumberWithAlphaChars);
        passportTestUsers.put(
                "PassportNumberWithNumericChar", kennethIncorrectPassportNumberWithAlphanumerics);
        passportTestUsers.put("PassportNumLessThan8Char", kennethIncorrectLessThan8Chars);
        passportTestUsers.put("InvalidValidToDate", kennethIncorrectValidToDateWithSpecialChars);
        passportTestUsers.put("IncorrectValidToDate", kennethIncorrectValidToDate);
        passportTestUsers.put("IssueDateInFuture", kennethIncorrectIssueDateInFuture);
        passportTestUsers.put("DateOfBirthInFuture", kennethIncorrectDoBInFuture);
        passportTestUsers.put("InvalidLastNameWithNumbers", kennethLastNameWithNumbers);
        passportTestUsers.put(
                "InvalidLastNameWithSpecialCharacters", kennethIncorrectLastNameWithSpecialChars);
        passportTestUsers.put("IncorrectPassportNumber", kennethIncorrectPassportNumber);
        passportTestUsers.put("IncorrectPostcode", kennethIncorrectPostcode);
        passportTestUsers.put("IncorrectLastName", kennethIncorrectLastName);
        passportTestUsers.put("IncorrectFirstName", kennethIncorrectFirstName);
        passportTestUsers.put("InvalidIssueDate", kennethIncorrectInvalidIssueDate);
        passportTestUsers.put("IncorrectIssueDate", kennethIncorrectIssueDate);
    }

    public static TestInput getPassportTestUserFromMap(String scenario) {
        return passportTestUsers.get(scenario);
    }
}
