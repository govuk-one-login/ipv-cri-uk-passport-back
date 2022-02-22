package uk.gov.di.ipv.cri.passport.library.helpers;

import org.apache.http.client.HttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContexts;
import uk.gov.di.ipv.cri.passport.library.exceptions.HttpClientException;
import uk.gov.di.ipv.cri.passport.library.service.ConfigurationService;

import javax.net.ssl.SSLContext;

import java.io.IOException;
import java.security.Key;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

public class HttpClientSetUp {

    private static final char[] password = "password".toCharArray();

    private HttpClientSetUp() {}

    public static HttpClient generateHttpClient(ConfigurationService configurationService)
            throws NoSuchAlgorithmException, InvalidKeySpecException, CertificateException,
                    KeyStoreException, IOException {
        KeyStore keystoreTLS =
                createKeyStore(
                        configurationService.getPassportCriTlsCert(),
                        configurationService.getPassportCriTlsKey());

        KeyStore trustStore = createTrustStore(configurationService.getDcsTlsCertChain());

        return contextSetup(keystoreTLS, trustStore);
    }

    private static HttpClient contextSetup(KeyStore clientTls, KeyStore caBundle) {
        try {
            SSLContext sslContext =
                    SSLContexts.custom()
                            .loadKeyMaterial(clientTls, password)
                            .loadTrustMaterial(caBundle, null)
                            .build();

            return HttpClients.custom().setSSLContext(sslContext).build();
        } catch (NoSuchAlgorithmException
                | KeyManagementException
                | KeyStoreException
                | UnrecoverableKeyException e) {
            throw new HttpClientException(e);
        }
    }

    private static KeyStore createKeyStore(Certificate cert, Key key)
            throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {
        final KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(null, password);

        keyStore.setKeyEntry("TlSKey", key, password, new Certificate[] {cert});
        keyStore.setCertificateEntry("my-ca-1", cert);
        return keyStore;
    }

    private static KeyStore createTrustStore(Certificate[] certificates)
            throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {
        final KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(null, null);
        int k = 0;
        for (Certificate cert : certificates) {
            k++;
            keyStore.setCertificateEntry("my-ca-" + k, cert);
        }

        return keyStore;
    }
}
