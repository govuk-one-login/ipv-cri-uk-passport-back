package uk.gov.di.ipv.cri.passport.dcscredential.domain;

import org.junit.jupiter.api.Test;
import uk.gov.di.ipv.cri.passport.library.domain.DcsResponse;
import uk.gov.di.ipv.cri.passport.library.domain.PassportAttributes;
import uk.gov.di.ipv.cri.passport.library.persistence.item.PassportCheckDao;

import java.time.LocalDate;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;

class PassportCredentialIssuerResponseTest {

    public static final String FAMILY_NAME = "familyName";
    public static final String[] GIVEN_NAMES = {"givenNames"};
    public static final String PASSPORT_NUMBER = "passportNumber";
    public static final LocalDate DATE_OF_BIRTH = LocalDate.now();
    public static final LocalDate EXPIRY_DATE = LocalDate.now();
    public static final String RESOURCE_ID = "resourceId";

    @Test
    void shouldConvertPassportCheckDaoToPassportCredentialIssuerResponse() {

        PassportAttributes attributes = new PassportAttributes(PASSPORT_NUMBER, FAMILY_NAME, GIVEN_NAMES, DATE_OF_BIRTH, EXPIRY_DATE);
        attributes.setDcsResponse(new DcsResponse(UUID.randomUUID(), UUID.randomUUID(), true, false, new String[]{}));
        PassportCheckDao passportCheckDao = new PassportCheckDao(RESOURCE_ID, attributes);

        PassportCredentialIssuerResponse passportCredentialIssuerResponse = PassportCredentialIssuerResponse.fromPassportCheckDao(passportCheckDao);

        assertEquals(RESOURCE_ID, passportCredentialIssuerResponse.getResourceId());
        assertEquals(FAMILY_NAME, passportCredentialIssuerResponse.getAttributes().getNames().getFamilyName());
        assertEquals(GIVEN_NAMES, passportCredentialIssuerResponse.getAttributes().getNames().getGivenNames());
        assertEquals(PASSPORT_NUMBER, passportCredentialIssuerResponse.getAttributes().getPassportNumber());
        assertEquals(DATE_OF_BIRTH, passportCredentialIssuerResponse.getAttributes().getDateOfBirth());
        assertEquals(EXPIRY_DATE, passportCredentialIssuerResponse.getAttributes().getExpiryDate());
        assertEquals(passportCheckDao.getAttributes().getRequestId(), passportCredentialIssuerResponse.getAttributes().getRequestId());
        assertEquals(passportCheckDao.getAttributes().getCorrelationId(), passportCredentialIssuerResponse.getAttributes().getCorrelationId());
        assertEquals(passportCheckDao.getAttributes().getDcsResponse(), passportCredentialIssuerResponse.getAttributes().getDcsResponse());
    }
}
