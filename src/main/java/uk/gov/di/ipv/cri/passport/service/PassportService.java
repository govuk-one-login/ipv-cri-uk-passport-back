package uk.gov.di.ipv.cri.passport.service;

import com.nimbusds.jose.JWSObject;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import uk.gov.di.ipv.cri.passport.domain.DcsSignedEncryptedResponse;
import uk.gov.di.ipv.cri.passport.helpers.HttpClientSetUp;
import uk.gov.di.ipv.cri.passport.persistence.DataStore;
import uk.gov.di.ipv.cri.passport.persistence.item.DcsResponseItem;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

public class PassportService {

    private final ConfigurationService configurationService;
    private final DataStore<DcsResponseItem> dataStore;
    private final HttpClient httpClient;

    public PassportService(
            HttpClient httpClient,
            ConfigurationService configurationService,
            DataStore<DcsResponseItem> dataStore) {
        this.httpClient = httpClient;
        this.configurationService = configurationService;
        this.dataStore = dataStore;
    }

    public PassportService()
            throws CertificateException, NoSuchAlgorithmException, InvalidKeySpecException,
                    KeyStoreException, IOException {
        this.configurationService = new ConfigurationService();
        this.dataStore =
                new DataStore<>(
                        configurationService.getDcsResponseTableName(),
                        DcsResponseItem.class,
                        DataStore.getClient());
        this.httpClient = HttpClientSetUp.generateHttpClient(configurationService);
    }

    public DcsSignedEncryptedResponse dcsPassportCheck(JWSObject payload) {
        try {
            HttpPost request = new HttpPost(configurationService.getDCSPostUrl());
            request.addHeader("content-type", "application/jose");
            request.setEntity(new StringEntity(payload.serialize()));

            HttpResponse response = httpClient.execute(request);

            if ((response != null)) {
                return new DcsSignedEncryptedResponse(response.toString());
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public void persistDcsResponse(DcsResponseItem responsePayload) {
        dataStore.create(responsePayload);
    }
}
