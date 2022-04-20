package uk.gov.di.ipv.cri.passport.library.service;

import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClientBuilder;
import com.amazonaws.services.kms.model.DecryptRequest;
import com.amazonaws.services.kms.model.DecryptResult;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.crypto.impl.ContentCryptoProvider;
import com.nimbusds.jose.jca.JWEJCAContext;
import com.nimbusds.jose.util.Base64URL;

import javax.crypto.spec.SecretKeySpec;

import java.nio.ByteBuffer;
import java.util.Set;

import static com.amazonaws.services.kms.model.EncryptionAlgorithmSpec.RSAES_OAEP_SHA_256;
import static com.nimbusds.jose.EncryptionMethod.A128CBC_HS256;
import static com.nimbusds.jose.JWEAlgorithm.RSA_OAEP_256;

public class KmsRsaDecrypter implements JWEDecrypter {

    private final AWSKMS kmsClient = AWSKMSClientBuilder.defaultClient();

    private final String keyId;
    private final JWEJCAContext jwejcaContext = new JWEJCAContext();

    public KmsRsaDecrypter(String keyId) {
        this.keyId = keyId;
    }

    @Override
    public byte[] decrypt(
            JWEHeader header,
            Base64URL encryptedKey,
            Base64URL iv,
            Base64URL cipherText,
            Base64URL authTag)
            throws JOSEException {
        DecryptRequest encryptedKeyDecryptRequest =
                new DecryptRequest()
                        .withCiphertextBlob(ByteBuffer.wrap(encryptedKey.decode()))
                        .withEncryptionAlgorithm(RSAES_OAEP_SHA_256)
                        .withKeyId(keyId);

        DecryptResult decryptResult = kmsClient.decrypt(encryptedKeyDecryptRequest);

        SecretKeySpec contentEncryptionKey =
                new SecretKeySpec(decryptResult.getPlaintext().array(), "AES");

        return ContentCryptoProvider.decrypt(
                header, encryptedKey, iv, cipherText, authTag, contentEncryptionKey, jwejcaContext);
    }

    @Override
    public Set<JWEAlgorithm> supportedJWEAlgorithms() {
        return Set.of(RSA_OAEP_256);
    }

    @Override
    public Set<EncryptionMethod> supportedEncryptionMethods() {
        return Set.of(A128CBC_HS256);
    }

    @Override
    public JWEJCAContext getJCAContext() {
        return jwejcaContext;
    }
}
