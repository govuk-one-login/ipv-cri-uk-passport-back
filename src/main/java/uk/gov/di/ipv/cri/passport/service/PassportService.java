package uk.gov.di.ipv.cri.passport.service;

import com.nimbusds.jose.JWSObject;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import uk.gov.di.ipv.cri.passport.domain.DcsSignedEncryptedResponse;
import uk.gov.di.ipv.cri.passport.exceptions.EmptyDcsResponseException;
import uk.gov.di.ipv.cri.passport.helpers.HttpClientSetUp;
import uk.gov.di.ipv.cri.passport.persistence.DataStore;
import uk.gov.di.ipv.cri.passport.persistence.item.PassportCheckDao;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Optional;

public class PassportService {

    public static final String CONTENT_TYPE = "content-type";
    public static final String APPLICATION_JOSE = "application/jose";
    private final ConfigurationService configurationService;
    private final DataStore<PassportCheckDao> dataStore;
    private final HttpClient httpClient;

    public PassportService(
            HttpClient httpClient,
            ConfigurationService configurationService,
            DataStore<PassportCheckDao> dataStore) {
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
                        PassportCheckDao.class,
                        DataStore.getClient(configurationService.getDynamoDbUri()));
        this.httpClient = HttpClientSetUp.generateHttpClient(configurationService);
    }

    public DcsSignedEncryptedResponse dcsPassportCheck(JWSObject payload)
            throws IOException, EmptyDcsResponseException {
        HttpPost request = new HttpPost(configurationService.getDCSPostUrl());
        request.addHeader(CONTENT_TYPE, APPLICATION_JOSE);
        request.setEntity(new StringEntity(payload.serialize()));

        Optional<HttpResponse> response = Optional.ofNullable(httpClient.execute(request));

        if (response.isEmpty()) {
            throw new EmptyDcsResponseException("Response from DCS is empty");
        }

        return new DcsSignedEncryptedResponse(response.get().toString());
    }

    public void persistDcsResponse(PassportCheckDao responsePayload) {
        dataStore.create(responsePayload);
    }
}
