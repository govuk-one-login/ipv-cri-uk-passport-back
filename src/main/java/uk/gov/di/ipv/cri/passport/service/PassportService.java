package uk.gov.di.ipv.cri.passport.service;

import com.nimbusds.jose.JWSObject;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import uk.gov.di.ipv.cri.passport.helpers.HttpClientSetUp;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

public class PassportService {

    private final ConfigurationService configurationService;
    private final DcsSigningService dcsSigningService;
    private final DcsEncryptionService dcsEncryptionService;
    private final HttpClient httpClient;

    public PassportService(
            HttpClient httpClient,
            ConfigurationService configurationService,
            DcsEncryptionService dcsEncryptionService,
            DcsSigningService dcsSigningService) {
        this.httpClient = httpClient;
        this.configurationService = configurationService;
        this.dcsEncryptionService = dcsEncryptionService;
        this.dcsSigningService = dcsSigningService;
    }

    public PassportService()
            throws CertificateException, NoSuchAlgorithmException, InvalidKeySpecException,
                    KeyStoreException, IOException {
        this.configurationService = new ConfigurationService();
        this.dcsSigningService = new DcsSigningService();
        this.dcsEncryptionService = new DcsEncryptionService();
        this.httpClient = HttpClientSetUp.generateHttpClient(configurationService);
    }

    public String dcsPassportCheck(String payload) throws IOException {
        try {
            JWSObject signedPayload = dcsSigningService.signData(payload);
            String encryptedPayload = dcsEncryptionService.encrypt(signedPayload.serialize());
            String reSignedPayload = dcsSigningService.signData(encryptedPayload).serialize();

            var request = new HttpPost(configurationService.getDCSPostUrl());
            request.addHeader("content-type", "application/jose");
            request.setEntity(new StringEntity(reSignedPayload));

            HttpResponse response = httpClient.execute(request);

            if ((response != null)) {
                return response.toString();
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}
