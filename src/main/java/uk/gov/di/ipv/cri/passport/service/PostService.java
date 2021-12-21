package uk.gov.di.ipv.cri.passport.service;

import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContexts;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.ipv.cri.passport.dto.DcsPayload;
import uk.gov.di.ipv.cri.passport.dto.DcsResponse;
import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

public class PostService {

    private static final Logger LOGGER = LoggerFactory.getLogger(PostService.class);
    private final ConfigurationService configurationService;

    public PostService(ConfigurationService configurationService) {
        this.configurationService = configurationService;
    }

    public PostService() {
        this.configurationService = new ConfigurationService();
    }

    public DcsResponse postToDcs(String signed, DcsPayload dcsPayload) throws CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException, UnrecoverableKeyException, KeyManagementException {

        SSLContext sslContext = SSLContexts.custom()
                .loadKeyMaterial(readStore(), null) // use null as second param if you don't have a separate key password
                .build();

        HttpClient httpClient = HttpClients.custom().setSSLContext(sslContext).build();
        HttpPost request = new HttpPost(configurationService.getPassportPostUri());
        request.addHeader("content-type", "application/jose");
        request.setEntity(new StringEntity(signed));

        HttpResponse response = httpClient.execute(request);

        DcsResponse dcsResponse;

        if (response.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {
            LOGGER.info(
                    "Received a 200 response from DCS (requestId: {}, correlationId: {})",
                    dcsPayload.getRequestId(),
                    dcsPayload.getCorrelationId()
            );

            dcsResponse = setResponse(dcsPayload, false, true, new String[]{""});

        } else if (response.getStatusLine().getStatusCode() == 404) {   // todo - check this any 400 ??
            LOGGER.warn(
                    "Received a 4xx response from DCS (requestId: {}, correlationId: {})",
                    dcsPayload.getRequestId(),
                    dcsPayload.getCorrelationId()
            );
            dcsResponse = setResponse(dcsPayload, true, false, new String[]{"DCS responded with a 4xx error"});

        } else {
            LOGGER.error(
                    "Unable to process request (requestId: {}, correlationId: {})",
                    dcsPayload.getRequestId(),
                    dcsPayload.getCorrelationId()
            );
            dcsResponse = setResponse(dcsPayload, true, false, new String[]{"DCS responded with an exception"});
        }
        return dcsResponse;

    }

    public KeyStore readStore() throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {
        final Certificate cert1 = configurationService.getDcsTlsCert();
        final KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(null, null);
        keyStore.setCertificateEntry("my-ca-1", cert1);
        return keyStore;

    }

    private DcsResponse setResponse(DcsPayload dcsPayload, boolean error, boolean valid, String[] errorMessage) {
        return new DcsResponse(dcsPayload.getCorrelationId(), dcsPayload.getRequestId(), error, valid, errorMessage);
    }
}
