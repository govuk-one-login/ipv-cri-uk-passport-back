package uk.gov.di.ipv.cri.passport.service;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;

import java.security.Key;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;

public class EncryptionService {


    public String encrypt(String data, Certificate serverEncryptionCert) {
        try {
            var header = new JWEHeader
                    .Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128CBC_HS256)
                    .type(new JOSEObjectType("JWE"))
                    .build();
            var jwe = new JWEObject(header, new Payload(data));
            var encrypter = new RSAEncrypter((RSAPublicKey) serverEncryptionCert.getPublicKey());

            jwe.encrypt(encrypter);

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
