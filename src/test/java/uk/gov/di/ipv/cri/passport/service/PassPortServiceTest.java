package uk.gov.di.ipv.cri.passport.service;

import com.amazonaws.services.kms.AWSKMS;
import com.nimbusds.jose.JOSEException;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Date;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContexts;
import org.apache.http.util.EntityUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.cri.passport.dto.DcsCheckRequestDto;
import uk.gov.di.ipv.cri.passport.dto.DcsResponse;
import uk.gov.di.ipv.cri.passport.kms.KmsSigner;

import javax.net.ssl.SSLContext;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

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
    PostService postService;
    @Mock
    AWSKMS kmsClient;

    @Test
    void postValidPassportRequest()
            throws CertificateException, NoSuchAlgorithmException, InvalidKeySpecException, JOSEException, UnrecoverableKeyException, KeyStoreException, IOException, KeyManagementException {
        KmsSigner kmsSigner = new KmsSigner("test", kmsClient);

        PassPortService passPortService = new PassPortService(encryptionService, signingService, postService);

        DcsResponse dcsResponse = passPortService.postValidPassportRequest(new DcsCheckRequestDto(PASSPORT_NUMBER, SURNAME, FORENAMES, DATE_OF_BIRTH, EXPIRY_DATE));

        // Todo : Assert response is correct
    }

    // Build a keystore.jks
    public KeyStore readStore() throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {


        final String ca1 = "MIIC/TCCAeWgAwIBAgIBATANBgkqhkiG9w0BAQsFADAsMR0wGwYDVQQDDBRjcmktdWstcGFzc3BvcnQtYmFjazELMAkGA1UEBhMCR0IwHhcNMjExMjE3MTEwNTM5WhcNMjIxMjE3MTEwNTM5WjAsMR0wGwYDVQQDDBRjcmktdWstcGFzc3BvcnQtYmFjazELMAkGA1UEBhMCR0IwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDYIxWKwYNoz2MIDvYb2ip4nhCOGUccufIqwSHXl5FBOoOxOZh1rV57sWhdKO/hyZYbF5YUYTwzV4rW7DgLkfx0sN/p5igk74BZRSXvV/s+XCkVC5c0NDhNGh6WK5rc8Qbm0Ad5vEO1JpQih5y2mPGCwfLBqcY8AC7fwZinP/4YoMTCtEk5ueA0HwZLHXOEMWl/QCkj7WlSBL4i6ozk4So3RFL4awYP6nvhY7OLAcad7g/ZW0dXvztPOJnT9rwi1p6BNoD/Zk6jMJHhbvKyGsluUy7PYVGYCQ36Uuzby2Jq8cG5qNS+CBjy0/d/RmrClKd7gcnLY/J5NOC+YSynoHXRAgMBAAGjKjAoMA4GA1UdDwEB/wQEAwIFoDAWBgNVHSUBAf8EDDAKBggrBgEFBQcDBDANBgkqhkiG9w0BAQsFAAOCAQEAvHT2AGTymh02A9HWrnGm6PEXx2Ye3NXV9eJNU1z6J298mS2kYq0Z4D0hj9i8+IoCQRbWOxLTAWBNt/CmH7jWltE4uqoAwTZD6mDgkC2eo5dY+RcuydsvJNfTcvUOyi47KKGGEcddfLti4NuX51BQIY5vSBfqZXt8+y28WuWqBMh6eny2wJtxNHo20wQei5g7w19lqwJu2F+l/ykX9K5DHjhXqZUJ77YWmY8sy/WROLjOoZZRy6YuzV8S/+c/nsPzqDAkD4rpWwASjsEDaTcH22xpGq5XUAf1hwwNsuiyXKGUHCxafYYS781LR8pLg6DpEAgcn8tBbq6MoiEGVeOp7Q==";
        final CertificateFactory cf = CertificateFactory.getInstance("X.509");
        final Certificate cert1 = cf.generateCertificate(new ByteArrayInputStream(Base64.getDecoder().decode(ca1)));
        final KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(null, null);

        keyStore.setCertificateEntry("my-ca-1", cert1);
        return keyStore;

    }

    // read the keystore  file & check if valid
    @Test
    public void readKeyStore() throws Exception {
        assertNotNull(readStore());
    }


    // perform clientRequest setting the SSLContext & call
    @Test
    public void performClientRequest() throws CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException, UnrecoverableKeyException, KeyManagementException {
        SSLContext sslContext = SSLContexts.custom()
                .loadKeyMaterial(readStore(), null) // use null as second param if you don't have a separate key password
                .build();

        HttpClient httpClient = HttpClients.custom().setSSLContext(sslContext).build();
        HttpResponse response = httpClient.execute(new HttpGet("https://slsh.iki.fi/client-certificate/protected/"));
        assertEquals(200, response.getStatusLine().getStatusCode());
        HttpEntity entity = response.getEntity();

        System.out.println("----------------------------------------");
        System.out.println(response.getStatusLine());
        EntityUtils.consume(entity);
    }
}

