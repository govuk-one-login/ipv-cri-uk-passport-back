package uk.gov.di.ipv.cri.passport.service;

import com.amazonaws.services.kms.AWSKMS;
import com.nimbusds.jose.JOSEException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Date;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.cri.passport.dto.DcsCheckRequestDto;
import uk.gov.di.ipv.cri.passport.dto.DcsResponse;
import uk.gov.di.ipv.cri.passport.kms.KmsSigner;

@ExtendWith(MockitoExtension.class)
class PassPortServiceTest {

    public static final String PASSPORT_NUMBER = "Test";
    public static final String SURNAME = "Hello";
    public static final String FORENAMES = "World";
    public static final Date DATE_OF_BIRTH = new Date();
    public static final Date EXPIRY_DATE = new Date();
    @Mock
    EncryptionService encryptionService;

    @Mock
    SigningService signingService;

    @Mock
    ConfigurationService configurationService;

    @Mock
    AWSKMS kmsClient;

    @Test
    void postValidPassportRequest()
        throws CertificateException, NoSuchAlgorithmException, InvalidKeySpecException, JOSEException {
        KmsSigner kmsSigner = new KmsSigner("test", kmsClient);

        PassPortService passPortService = new PassPortService(encryptionService, signingService);

        DcsResponse dcsResponse = passPortService.postValidPassportRequest(new DcsCheckRequestDto(PASSPORT_NUMBER, SURNAME, FORENAMES, DATE_OF_BIRTH, EXPIRY_DATE));

       // Todo : Assert response is correct
    }
}
