package uk.gov.di.ipv.cri.passport.service;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSAEncrypter;

import java.security.cert.CertificateException;
import java.security.interfaces.RSAPublicKey;

public class DcsEncryptionService {

    private final ConfigurationService configurationService;

    public DcsEncryptionService(ConfigurationService configurationService) {
        this.configurationService = configurationService;
    }

    public DcsEncryptionService() {
        this.configurationService = new ConfigurationService();
    }

    public String encrypt(String data) throws JOSEException, CertificateException {

        var header =
                new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128CBC_HS256)
                        .type(new JOSEObjectType("JWE"))
                        .build();
        var jwe = new JWEObject(header, new Payload(data));

        jwe.encrypt(
                new RSAEncrypter(
                        (RSAPublicKey)
                                configurationService
                                        .getDcsEncryptionForClientsCert()
                                        .getPublicKey()));

        if (!jwe.getState().equals(JWEObject.State.ENCRYPTED)) {
            throw new RuntimeException("Something went wrong, couldn't encrypt JWE");
        }

        return jwe.serialize();
    }
}
