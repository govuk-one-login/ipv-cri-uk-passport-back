package uk.gov.di.ipv.cri.passport.service;

import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSObject;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import uk.gov.di.ipv.cri.passport.helpers.HttpClientSetUp;
import uk.gov.di.ipv.cri.passport.persistence.DataStore;
import uk.gov.di.ipv.cri.passport.persistence.item.DcsResponseItem;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.UUID;

public class PassportService {

    private final ConfigurationService configurationService;
    private final DcsSigningService dcsSigningService;
    private final DcsEncryptionService dcsEncryptionService;
    private final DataStore<DcsResponseItem> dataStore;
    private final HttpClient httpClient;

    public PassportService(
            HttpClient httpClient,
            ConfigurationService configurationService,
            DcsEncryptionService dcsEncryptionService,
            DcsSigningService dcsSigningService,
            DataStore<DcsResponseItem> dataStore) {
        this.httpClient = httpClient;
        this.configurationService = configurationService;
        this.dcsEncryptionService = dcsEncryptionService;
        this.dcsSigningService = dcsSigningService;
        this.dataStore = dataStore;
    }

    public PassportService()
            throws CertificateException, NoSuchAlgorithmException, InvalidKeySpecException,
                    KeyStoreException, IOException {
        this.configurationService = new ConfigurationService();
        this.dcsSigningService = new DcsSigningService();
        this.dcsEncryptionService = new DcsEncryptionService();
        this.dataStore =
                new DataStore<>(
                        configurationService.getDcsResponseTableName(),
                        DcsResponseItem.class,
                        DataStore.getClient());
        this.httpClient = HttpClientSetUp.generateHttpClient(configurationService);
    }

    public String dcsPassportCheck(String payload) {
        try {
            JWSObject signedPayload = dcsSigningService.createJWS(payload);
            JWEObject encryptedPayload = dcsEncryptionService.createJWE(signedPayload.serialize());
            JWSObject signedAndEncryptedPayload =
                    dcsSigningService.createJWS(encryptedPayload.serialize());

            var request = new HttpPost(configurationService.getDCSPostUrl());
            request.addHeader("content-type", "application/jose");
            request.setEntity(new StringEntity(signedAndEncryptedPayload.serialize()));

            HttpResponse response = httpClient.execute(request);

            if ((response != null)) {
                return response.toString();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public DcsResponseItem persistDcsResponse(String responsePayload) {
        DcsResponseItem dcsResponseItem = new DcsResponseItem();
        dcsResponseItem.setResourceId(UUID.randomUUID().toString());
        dcsResponseItem.setResourcePayload(responsePayload);

        dataStore.create(dcsResponseItem);
        return dcsResponseItem;
    }
}
