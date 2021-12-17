package uk.gov.di.ipv.cri.passport.service;

import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContexts;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

public class PostService {

    private final ConfigurationService configurationService;

    public PostService(ConfigurationService configurationService) {
        this.configurationService = configurationService;
    }

    public PostService() {
        this.configurationService = new ConfigurationService();
    }
    //TODO - return type needed
    // DCSRESPONSE
    public void postToDcs(String signed) throws CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException, UnrecoverableKeyException, KeyManagementException {

        SSLContext sslContext = SSLContexts.custom()
                .loadKeyMaterial(readStore(), null) // use null as second param if you don't have a separate key password
                .build();

        HttpClient httpClient = HttpClients.custom().setSSLContext(sslContext).build();
        HttpPost request = new HttpPost(configurationService.GetPassportPostUri());
        request.addHeader("content-type", "application/jose");
        request.setEntity(new StringEntity(signed));

        HttpResponse response = httpClient.execute(request);

    }


    public KeyStore readStore() throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {

        final Certificate cert1 = configurationService.getDcsTlsCert();
        final KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(null, null);

        keyStore.setCertificateEntry("my-ca-1", cert1);
        return keyStore;

    }
}
