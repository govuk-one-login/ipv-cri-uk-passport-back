package uk.gov.di.ipv.cri.passport.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.google.gson.Gson;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import uk.gov.di.ipv.cri.passport.domain.DcsPayload;
import uk.gov.di.ipv.cri.passport.domain.DcsSignedEncryptedResponse;
import uk.gov.di.ipv.cri.passport.domain.ProtectedHeader;
import uk.gov.di.ipv.cri.passport.domain.Thumbprints;
import uk.gov.di.ipv.cri.passport.exceptions.IpvCryptoException;
import uk.gov.di.ipv.cri.passport.persistence.item.DcsResponseItem;

import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.text.ParseException;
import java.util.Map;
import java.util.UUID;

public class DcsCryptographyService {

    private final ConfigurationService configurationService;
    private final Gson gson = new Gson();
    private final ObjectMapper objectMapper =
            new ObjectMapper().registerModule(new JavaTimeModule());

    public DcsCryptographyService(ConfigurationService configurationService) {
        this.configurationService = configurationService;
    }

    public JWSObject preparePayload(DcsPayload passportDetails)
            throws CertificateException, NoSuchAlgorithmException, InvalidKeySpecException,
                    JOSEException, JsonProcessingException {
        JWSObject signedPassportDetails =
                createJWS(objectMapper.writeValueAsString(passportDetails));
        JWEObject encryptedPassportDetails = createJWE(signedPassportDetails.serialize());
        JWSObject signedAndEncryptedPassportDetails =
                createJWS(encryptedPassportDetails.serialize());
        return signedAndEncryptedPassportDetails;
    }

    public DcsResponseItem unwrapDcsResponse(DcsSignedEncryptedResponse dcsSignedEncryptedResponse)
            throws CertificateException, ParseException, JOSEException {
        JWSObject outerSignedPayload = JWSObject.parse(dcsSignedEncryptedResponse.getPayload());
        if (isInvalidSignature(outerSignedPayload)) {
            throw new IpvCryptoException("DCS Response Outer Signature invalid.");
        }
        JWEObject encryptedSignedPayload =
                JWEObject.parse(outerSignedPayload.getPayload().toString());
        JWSObject decryptedSignedPayload = decrypt(encryptedSignedPayload);
        if (isInvalidSignature(decryptedSignedPayload)) {
            throw new IpvCryptoException("DCS Response Inner Signature invalid.");
        }
        return new DcsResponseItem(
                UUID.randomUUID().toString(), decryptedSignedPayload.getPayload().toString());
    }

    private JWSObject createJWS(String stringToSign)
            throws NoSuchAlgorithmException, InvalidKeySpecException, JOSEException,
                    CertificateException {

        Thumbprints thumbprints = configurationService.makeThumbprints();

        ProtectedHeader protectedHeader =
                new ProtectedHeader(
                        JWSAlgorithm.RS256.toString(),
                        thumbprints.getSha1Thumbprint(),
                        thumbprints.getSha256Thumbprint());

        String jsonHeaders = gson.toJson(protectedHeader);

        JWSObject jwsObject =
                new JWSObject(
                        new JWSHeader.Builder(JWSAlgorithm.RS256)
                                .customParams(gson.fromJson(jsonHeaders, Map.class))
                                .build(),
                        new Payload(stringToSign));

        jwsObject.sign(new RSASSASigner(configurationService.getPassportCriSigningKey()));

        return jwsObject;
    }

    private JWEObject createJWE(String data) throws JOSEException, CertificateException {

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

        return jwe;
    }

    private boolean isInvalidSignature(JWSObject jwsObject)
            throws CertificateException, JOSEException {
        RSASSAVerifier rsassaVerifier =
                new RSASSAVerifier(
                        (RSAPublicKey) configurationService.getDcsSigningCert().getPublicKey());
        return !jwsObject.verify(rsassaVerifier);
    }

    public JWSObject decrypt(JWEObject encrypted) {
        try {
            RSADecrypter rsaDecrypter =
                    new RSADecrypter(configurationService.getPassportCriPrivateKey());
            encrypted.decrypt(rsaDecrypter);

            return JWSObject.parse(encrypted.getPayload().toString());
        } catch (ParseException
                | NoSuchAlgorithmException
                | InvalidKeySpecException
                | JOSEException exception) {
            throw new IpvCryptoException(
                    String.format("Cannot Decrypt DCS Payload: %s", exception.getMessage()));
        }
    }
}
