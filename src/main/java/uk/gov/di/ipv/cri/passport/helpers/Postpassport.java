package uk.gov.di.ipv.cri.passport.helpers;

import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContexts;
import uk.gov.di.ipv.cri.passport.domain.ErrorResponse;
import uk.gov.di.ipv.cri.passport.domain.PassportException;
import uk.gov.di.ipv.cri.passport.service.ConfigurationService;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

public class Postpassport {

    public static HttpClient generateHttpClient()  {
        // todo check this -- must be injected ??
        HttpClient httpClient;

        try {
            ConfigurationService configurationService = new ConfigurationService();
            final Certificate cert1 = configurationService.getDcsTlsCert();
            SSLContext sslContext = SSLContexts.custom()
                    .loadKeyMaterial(readStore(cert1), null) // use null as second param if you don't have a separate key password
                    .build();

            httpClient = HttpClients.custom().setSSLContext(sslContext).build();
            return httpClient;
        } catch (CertificateException | NoSuchAlgorithmException | KeyManagementException | KeyStoreException | UnrecoverableKeyException | IOException e) {
            e.printStackTrace();
        }

        return null;
    }


    //  method that can be mocked later on
    public static HttpResponse postToDcs(String signed) {

        try {
            // todo check this -- must be injected ??
            ConfigurationService configurationService = new ConfigurationService();
            final Certificate cert1 = configurationService.getDcsTlsCert();
            SSLContext sslContext = SSLContexts.custom()
                    .loadKeyMaterial(readStore(cert1), null) // use null as second param if you don't have a separate key password
                    .build();

            HttpClient httpClient = HttpClients.custom().setSSLContext(sslContext).build();
            HttpPost request = new HttpPost(configurationService.getPassportPostUri());
            request.addHeader("content-type", "application/jose");
            request.setEntity(new StringEntity(signed));
            HttpResponse response = httpClient.execute(request);
            return response;
        } catch (NoSuchAlgorithmException | KeyManagementException | KeyStoreException | UnrecoverableKeyException | CertificateException | IOException e) {
            e.printStackTrace();
            throw new PassportException(
                    HTTPResponse.SC_SERVER_ERROR,
                    ErrorResponse.FAILED_TO_PARSE_PASSPORT_FORM_DATA);
        }
    }

    public static KeyStore readStore(Certificate cert1) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {
        final KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(null, null);
        keyStore.setCertificateEntry("my-ca-1", cert1);
        return keyStore;
    }
}
