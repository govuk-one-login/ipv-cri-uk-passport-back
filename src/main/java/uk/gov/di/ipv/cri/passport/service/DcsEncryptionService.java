package uk.gov.di.ipv.cri.passport.service;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import uk.gov.di.ipv.cri.passport.exceptions.IpvCryptoException;

import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.text.ParseException;

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
                        (RSAPublicKey) configurationService.getDcsEncryptionCert().getPublicKey()));

        if (!jwe.getState().equals(JWEObject.State.ENCRYPTED)) {
            throw new IpvCryptoException("Something went wrong, couldn't encrypt JWE");
        }

        return jwe.serialize();
    }

    public JWSObject decrypt(String encrypted) {
        try {
            JWEObject jweObject = JWEObject.parse(encrypted);
            RSADecrypter rsaDecrypter =
                    new RSADecrypter(
                            configurationService.getPassportCriPrivateKey());
            jweObject.decrypt(rsaDecrypter);

            return JWSObject.parse(jweObject.getPayload().toString());
        } catch (ParseException
                | NoSuchAlgorithmException
                | InvalidKeySpecException
                | JOSEException exception) {
            throw new IpvCryptoException(
                    String.format("Cannot Decrypt DCS Payload: %s", exception.getMessage()));
        }
    }
}
