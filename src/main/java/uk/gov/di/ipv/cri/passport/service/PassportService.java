package uk.gov.di.ipv.cri.passport.service;

import com.nimbusds.jose.JWSObject;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.HttpResponseException;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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

public class PassportService {

    public static final String CONTENT_TYPE = "content-type";
    public static final String APPLICATION_JOSE = "application/jose";
    private static final Logger LOGGER = LoggerFactory.getLogger(PassportService.class);
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
                        DataStore.getClient(configurationService.getDynamoDbEndpointOverride()));
        this.httpClient = HttpClientSetUp.generateHttpClient(configurationService);
    }

    public DcsSignedEncryptedResponse dcsPassportCheck(JWSObject payload)
            throws IOException, EmptyDcsResponseException {
        HttpPost request = new HttpPost(configurationService.getDCSPostUrl());
        request.addHeader(CONTENT_TYPE, APPLICATION_JOSE);
        request.setEntity(new StringEntity(payload.serialize()));

        HttpResponse response = httpClient.execute(request);

        if (response == null) {
            throw new EmptyDcsResponseException("Response from DCS is empty");
        }

        if (response.getStatusLine().getStatusCode() != 200) {
            LOGGER.error(
                    String.format(
                            "Response from DCS has status code: %d",
                            response.getStatusLine().getStatusCode()));
            throw new HttpResponseException(
                    response.getStatusLine().getStatusCode(), "DCS responded with an error");
        }

        return new DcsSignedEncryptedResponse(response.toString());
    }

    public void persistDcsResponse(PassportCheckDao responsePayload) {
        dataStore.create(responsePayload);
    }
}
