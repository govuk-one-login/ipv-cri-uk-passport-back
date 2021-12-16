package uk.gov.di.ipv.cri.passport.kms;

import static com.amazonaws.services.kms.model.EncryptionAlgorithmSpec.RSAES_OAEP_SHA_256;

import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClientBuilder;
import com.amazonaws.services.kms.model.EncryptRequest;
import com.amazonaws.services.kms.model.EncryptResult;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWECryptoParts;
import com.nimbusds.jose.JWEEncrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.jca.JWEJCAContext;
import com.nimbusds.jose.util.Base64URL;
import java.nio.ByteBuffer;
import java.util.Set;

public class KmsEncrypt implements JWEEncrypter {

    private final AWSKMS kmsClient;
    private final String keyId;

    public KmsEncrypt(String keyId, AWSKMS kmsClient) {
        this.keyId = keyId;
        this.kmsClient = kmsClient;
    }

    public KmsEncrypt(String keyId) {
        this.keyId = keyId;
        this.kmsClient = AWSKMSClientBuilder.defaultClient();
    }

    @Override
    public JWECryptoParts encrypt(JWEHeader header, byte[] clearText) throws JOSEException {
        EncryptRequest encryptRequest =
            new EncryptRequest()
                .withEncryptionAlgorithm(RSAES_OAEP_SHA_256)
                .withKeyId(keyId)
                .withPlaintext(ByteBuffer.wrap(clearText));

        EncryptResult encryptResult = kmsClient.encrypt(encryptRequest);

        // Todo - these should not be null. What should they be?
        return new JWECryptoParts(null, null, Base64URL.encode(encryptResult.getCiphertextBlob().array()), null);
    }

    @Override
    public Set<JWEAlgorithm> supportedJWEAlgorithms() {
        return null;
    }

    @Override
    public Set<EncryptionMethod> supportedEncryptionMethods() {
        return null;
    }

    @Override
    public JWEJCAContext getJCAContext() {
        return null;
    }
}
