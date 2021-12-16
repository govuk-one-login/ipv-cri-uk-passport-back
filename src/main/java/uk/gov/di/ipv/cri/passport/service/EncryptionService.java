package uk.gov.di.ipv.cri.passport.service;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSADecrypter;
import java.security.Key;
import java.security.PrivateKey;
import java.text.ParseException;
import uk.gov.di.ipv.cri.passport.kms.KmsEncrypt;

public class EncryptionService {

    private final KmsEncrypt kmsEncrypt;
    private final ConfigurationService configurationService;

    public EncryptionService() {
        this.configurationService = new ConfigurationService();
        this.kmsEncrypt = new KmsEncrypt(configurationService.getDcsEncryptionKey());
    }

    public EncryptionService(ConfigurationService configurationService, KmsEncrypt kmsEncrypt) {
        this.configurationService = configurationService;
        this.kmsEncrypt = kmsEncrypt;
    }

    public String encrypt(String data) {
        try {
            var header = new JWEHeader
                .Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128CBC_HS256)
                .type(new JOSEObjectType("JWE"))
                .build();
            var jwe = new JWEObject(header, new Payload(data));

            jwe.encrypt(kmsEncrypt);

            if (!jwe.getState().equals(JWEObject.State.ENCRYPTED)) {
                throw new RuntimeException("Something went wrong, couldn't encrypt JWE");
            }

            return jwe.serialize();
        } catch (JOSEException e) {
            //todo
            return "our customised error";
            //return Mono.error(e);
        }
    }

    public String decrypt(String data, Key clientEncryptionKey) {
        try {
            var jwe = JWEObject.parse(data);
            var decrypter = new RSADecrypter((PrivateKey) clientEncryptionKey);
            jwe.decrypt(decrypter);

            if (!jwe.getState().equals(JWEObject.State.DECRYPTED)) {
                throw new RuntimeException("Something went wrong, couldn't decrypt JWE");
            }

            return jwe.getPayload().toString();
        } catch (ParseException | JOSEException e) {
            //todo
            return "our customised error";
            //return Mono.error(e);
        }
    }
}
