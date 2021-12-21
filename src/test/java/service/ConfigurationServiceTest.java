package service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.lambda.powertools.parameters.SSMProvider;
import uk.gov.di.ipv.cri.passport.service.ConfigurationService;
import uk.org.webcompere.systemstubs.environment.EnvironmentVariables;
import uk.org.webcompere.systemstubs.jupiter.SystemStub;
import uk.org.webcompere.systemstubs.jupiter.SystemStubsExtension;
import uk.org.webcompere.systemstubs.properties.SystemProperties;

import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;

import static com.github.tomakehurst.wiremock.client.WireMock.getAllServeEvents;
import static com.github.tomakehurst.wiremock.client.WireMock.ok;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

@WireMockTest(httpPort = ConfigurationService.LOCALHOST_PORT)
@ExtendWith(MockitoExtension.class)
@ExtendWith(SystemStubsExtension.class)
class ConfigurationServiceTest {

    public static final String TEST_CERT =
            "MIIC/TCCAeWgAwIBAgIBATANBgkqhkiG9w0BAQsFADAsMR0wGwYDVQQDDBRjcmktdWstcGFzc3BvcnQtYmFjazELMAkGA1UEBhMCR0IwHhcNMjExMjE3MTEwNTM5WhcNMjIxMjE3MTEwNTM5WjAsMR0wGwYDVQQDDBRjcmktdWstcGFzc3BvcnQtYmFjazELMAkGA1UEBhMCR0IwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDYIxWKwYNoz2MIDvYb2ip4nhCOGUccufIqwSHXl5FBOoOxOZh1rV57sWhdKO/hyZYbF5YUYTwzV4rW7DgLkfx0sN/p5igk74BZRSXvV/s+XCkVC5c0NDhNGh6WK5rc8Qbm0Ad5vEO1JpQih5y2mPGCwfLBqcY8AC7fwZinP/4YoMTCtEk5ueA0HwZLHXOEMWl/QCkj7WlSBL4i6ozk4So3RFL4awYP6nvhY7OLAcad7g/ZW0dXvztPOJnT9rwi1p6BNoD/Zk6jMJHhbvKyGsluUy7PYVGYCQ36Uuzby2Jq8cG5qNS+CBjy0/d/RmrClKd7gcnLY/J5NOC+YSynoHXRAgMBAAGjKjAoMA4GA1UdDwEB/wQEAwIFoDAWBgNVHSUBAf8EDDAKBggrBgEFBQcDBDANBgkqhkiG9w0BAQsFAAOCAQEAvHT2AGTymh02A9HWrnGm6PEXx2Ye3NXV9eJNU1z6J298mS2kYq0Z4D0hj9i8+IoCQRbWOxLTAWBNt/CmH7jWltE4uqoAwTZD6mDgkC2eo5dY+RcuydsvJNfTcvUOyi47KKGGEcddfLti4NuX51BQIY5vSBfqZXt8+y28WuWqBMh6eny2wJtxNHo20wQei5g7w19lqwJu2F+l/ykX9K5DHjhXqZUJ77YWmY8sy/WROLjOoZZRy6YuzV8S/+c/nsPzqDAkD4rpWwASjsEDaTcH22xpGq5XUAf1hwwNsuiyXKGUHCxafYYS781LR8pLg6DpEAgcn8tBbq6MoiEGVeOp7Q==";
    public static final String TEST_KEY =
            "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JSUNlQUlCQURBTkJna3Foa2lHOXcwQkFRRUZBQVNDQW1Jd2dnSmVBZ0VBQW9HQkFNcGVPUDZqcVlsT3dTVlMKcWdZMXFUQVhHbXZuektPWDVaSG1mVzcxZDE3RlcrOHNzcmFvVTl5Y3hQUUp2MjZFc3FGTGV5Nk9NUit2VjZyNApLT0JvMWdvTzB2TDhucnJ1MjNIL1I0L292L3d6ZCtkSFB2bmhYNDdHcHM1MmxsV0g5SjZENUNzRXB5Kzh2MzFMCmpOMERBdXoyRllmRy9xanhGSk4wbVpvYnU5Z0hBZ01CQUFFQ2dZQnNHak0yQzdWb0RQTHVmaDhuWEFqNkVJMWoKc1JySEZVQmtWUTBTZGZ3RFcwaEdGc21NKzVSNDJDSDUveThNMmNRV2w1ekEvT0pPKzdySU1QS2RGa09uZm9IRwpaYnFnQmVNSWUwRlkwKzhLTVlWYkpCRk5tY3A0a2RhSURSNkFSME9TYnQ3emFCYVpnOFl4R1d4R3lkbFpUMHY2CnFqSEJ2eDh0cE9pN2ZNS1FhUUpCQU9ybGtwaUFjU0RhR0wyTDIyMDN3T0pQdXdpbmNBOGozRmJxd1dSU3ZaeEEKbDlyTnNjVkVlRDBYOElZRE02SE9vWGcvVnJUSjV6MzY0aUwzLzBwUkFnVUNRUURjaklSaENpVDV4dVArTUpYOAozaDF2TnRZd1kxU0krRHpJOEJnaFdISU5MallTSmsyT1FkWDNla3Rac1E4d2ZPOW0xa2w2aVZGV2pEeGlzL2FiCmFGT2JBa0VBcE5qeU5YWkdibURBNWgwRnBETnhlU0d0UjlpQ0N3NEdyelRXL2ZvWE9WWVhmQ1hJOFlFb3hPOU4KREMrcEI1QkV2MmZzQ0xwOVA0RVhQS1ZBa3o0Z3BRSkJBTnU3SzlDNm1LZzZIY0NNaTRLSmtPM1N4b2NqRDMvLwpRaUE0QlBLRCtlMWowdjgySmlMTE9PLzlhY0VNaE1PY1ZiQXhZcmV3dzlia2xPMEp1M0tOK0cwQ1FRREdXQk5HClllSXFMZ29VRWFNWVYzK3U4ZmtGVDFaeHVNSG5Mbll0Y2xMRVFjYVMyWXUwZmEvM2hGOU0vSXd5Q3h5U3AzTXkKYWFYRFdXa2p4V05CNmhDaAotLS0tLUVORCBQUklWQVRFIEtFWS0tLS0tCg==";

    @SystemStub private EnvironmentVariables environmentVariables;

    @SystemStub private SystemProperties systemProperties;

    @Mock SSMProvider ssmProvider;

    private ConfigurationService configurationService;

    @BeforeEach
    void setUp() {
        configurationService = new ConfigurationService(ssmProvider);
        environmentVariables.set("IS_LOCAL", "true");
        environmentVariables.set("AWS_ACCESS_KEY_ID", "ASDFGHJKL");
        environmentVariables.set("AWS_SECRET_ACCESS_KEY", "1234567890987654321");

        systemProperties.set(
                "software.amazon.awssdk.http.service.impl",
                "software.amazon.awssdk.http.urlconnection.UrlConnectionSdkHttpService");
    }

    @Test
    void shouldLoadCertificateFromParameterStore() throws CertificateException {
        environmentVariables.set("DCS_ENCRYPTION_CERT_PARAM", "/dev/dcs/encryption-cert");
        when(ssmProvider.get("/dev/dcs/encryption-cert")).thenReturn(TEST_CERT);

        X509Certificate underTest = (X509Certificate) configurationService.getDcsEncryptionCert();
        assertEquals("C=GB,CN=cri-uk-passport-back", underTest.getIssuerX500Principal().getName());
    }

    @Test
    void shouldLoadKeyFromParameterStore()
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        environmentVariables.set(
                "PASSPORT_CRI_ENCRYPTION_KEY_PARAM", "/dev/cri/passport/encryption-key");
        when(ssmProvider.get("/dev/cri/passport/encryption-key")).thenReturn(TEST_KEY);

        Key underTest = configurationService.getPassportCRIEncryptionKey();
        assertEquals("PKCS#8", underTest.getFormat());
        assertEquals("RSA", underTest.getAlgorithm());
    }

    @Test
    void usesLocalSSMProviderWhenRunningLocally(WireMockRuntimeInfo wmRuntimeInfo)
            throws JsonProcessingException {
        stubFor(post("/").willReturn(ok()));

        SSMProvider ssmProvider = new ConfigurationService().getSsmProvider();
        assertThrows(NullPointerException.class, () -> ssmProvider.get("any-old-thing"));

        HashMap requestBody =
                new ObjectMapper()
                        .readValue(
                                getAllServeEvents().get(0).getRequest().getBodyAsString(),
                                HashMap.class);

        assertEquals("any-old-thing", requestBody.get("Name"));
        assertEquals(false, requestBody.get("WithDecryption"));
    }
}
