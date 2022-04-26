package uk.gov.di.ipv.cri.passport.integrationtest;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSAEncrypter;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import uk.gov.di.ipv.cri.passport.library.service.ConfigurationService;
import uk.gov.di.ipv.cri.passport.library.service.KmsRsaDecrypter;

import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;

class KmsRsaDecrypterIT {
    private static ConfigurationService configurationService;

    @BeforeAll
    public static void setup() {
        configurationService = new ConfigurationService();
    }

    @Test
    void decryptWithKms() throws Exception {
        // Will replace with values from the config service once the keys have been generated in kms
        // String kmsId = configurationService.getJarKmsEncryptionKeyId();
        // String pubKey = configurationService.getJarKmsPublickKey();
        String kmsId = "6cb3602b-da86-4d53-b2bb-67044cccd931";
        String pubKey =
                "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtJTS5j+DsSIR0y1ZiRxq8j77ZekHVnspDc6ZdxURWLoDmRJh3qeepOkcLEByNob2bFUUEnzU3FXNrEPevWqaRufssShFKXS1D1WYZpepcfDmHdTuBt0N3shtU8ydRJuJ36FZtzol/vLFD8TfAIj1XChepKiu9DTQ7bOSXmZ+nfin34yasawZBlbc0gnvhpYrrlunnpWpY6o6UPMbgfBUcqu8vV35YkDF7yBQjV9zLFKgdiEMX2o3oPL8qhN8RtFMBphKDcY4+YTiIoDpSVqk1yIh/ia66GChbcSxYaAKqNJ/AOSXdl2qNKrru8YJByC8+saiw23dm8F5nakQvvkffQIDAQAB";

        var header =
                new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
                        .type(new JOSEObjectType("JWE"))
                        .build();
        JWEObject jweObject = new JWEObject(header, new Payload("Decrypt me!"));

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        RSAPublicKey publicKey =
                (RSAPublicKey)
                        keyFactory.generatePublic(
                                new X509EncodedKeySpec(Base64.getDecoder().decode(pubKey)));
        jweObject.encrypt(new RSAEncrypter(publicKey));

        jweObject.decrypt(new KmsRsaDecrypter(kmsId));
        String s = jweObject.getPayload().toString();

        assertEquals("Decrypt me!", s);
    }
}
