package uk.gov.di.ipv.cri.passport.library.service;

import com.nimbusds.jose.JWSObject;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.HttpResponseException;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.util.EntityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.ipv.cri.common.library.util.EventProbe;
import uk.gov.di.ipv.cri.passport.library.config.ConfigurationService;
import uk.gov.di.ipv.cri.passport.library.config.EnvironmentVariable;
import uk.gov.di.ipv.cri.passport.library.domain.DcsSignedEncryptedResponse;
import uk.gov.di.ipv.cri.passport.library.exceptions.EmptyDcsResponseException;
import uk.gov.di.ipv.cri.passport.library.helpers.HttpClientSetUp;
import uk.gov.di.ipv.cri.passport.library.persistence.DataStore;
import uk.gov.di.ipv.cri.passport.library.persistence.item.PassportCheckDao;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

import static uk.gov.di.ipv.cri.passport.library.config.ConfigurationVariable.DCS_POST_URL_PARAM;
import static uk.gov.di.ipv.cri.passport.library.metrics.Definitions.THIRD_PARTY_DCS_RESPONSE_OK;
import static uk.gov.di.ipv.cri.passport.library.metrics.Definitions.THIRD_PARTY_DCS_RESPONSE_TYPE_EMPTY;
import static uk.gov.di.ipv.cri.passport.library.metrics.Definitions.THIRD_PARTY_DCS_RESPONSE_TYPE_ERROR;

public class PassportService {

    public static final String CONTENT_TYPE = "content-type";
    public static final String APPLICATION_JOSE = "application/jose";
    private static final Logger LOGGER = LoggerFactory.getLogger(PassportService.class);
    private final ConfigurationService configurationService;
    private final DataStore<PassportCheckDao> dataStore;
    private final HttpClient httpClient;
    private final EventProbe eventProbe;

    public PassportService(
            HttpClient httpClient,
            ConfigurationService configurationService,
            DataStore<PassportCheckDao> dataStore,
            EventProbe eventProbe) {
        this.httpClient = httpClient;
        this.configurationService = configurationService;
        this.dataStore = dataStore;
        this.eventProbe = eventProbe;
    }

    public PassportService(ConfigurationService configurationService, EventProbe eventProbe)
            throws CertificateException, NoSuchAlgorithmException, InvalidKeySpecException,
                    KeyStoreException, IOException {
        this.configurationService = configurationService;
        this.eventProbe = eventProbe;
        this.dataStore =
                new DataStore<>(
                        this.configurationService.getEnvironmentVariable(
                                EnvironmentVariable.DCS_RESPONSE_TABLE_NAME),
                        PassportCheckDao.class,
                        DataStore.getClient(
                                this.configurationService.getDynamoDbEndpointOverride()),
                        configurationService);
        this.httpClient = HttpClientSetUp.generateHttpClient(this.configurationService);
    }

    public DcsSignedEncryptedResponse dcsPassportCheck(JWSObject payload)
            throws IOException, EmptyDcsResponseException {
        HttpPost request = new HttpPost(configurationService.getSsmParameter(DCS_POST_URL_PARAM));
        request.addHeader(CONTENT_TYPE, APPLICATION_JOSE);
        request.setEntity(new StringEntity(payload.serialize()));

        HttpResponse response = httpClient.execute(request);

        if (response == null) {
            eventProbe.counterMetric(THIRD_PARTY_DCS_RESPONSE_TYPE_EMPTY);
            throw new EmptyDcsResponseException("Response from DCS is empty");
        }

        if (response.getStatusLine().getStatusCode() != 200) {
            int statusCode = response.getStatusLine().getStatusCode();
            LOGGER.error("Response from DCS has status code: {}", statusCode);
            eventProbe.counterMetric(THIRD_PARTY_DCS_RESPONSE_TYPE_ERROR);
            throw new HttpResponseException(
                    response.getStatusLine().getStatusCode(), "DCS responded with an error");
        }

        eventProbe.counterMetric(THIRD_PARTY_DCS_RESPONSE_OK);

        return new DcsSignedEncryptedResponse(EntityUtils.toString(response.getEntity()));
    }

    public void persistDcsResponse(PassportCheckDao responsePayload) {
        dataStore.create(responsePayload);
    }
}
