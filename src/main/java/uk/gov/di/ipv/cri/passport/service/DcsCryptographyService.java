package uk.gov.di.ipv.cri.passport.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.google.gson.Gson;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import uk.gov.di.ipv.cri.passport.domain.DcsPayload;
import uk.gov.di.ipv.cri.passport.domain.ProtectedHeader;
import uk.gov.di.ipv.cri.passport.domain.Thumbprints;
import uk.gov.di.ipv.cri.passport.exceptions.IpvCryptoException;

import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Map;

public class DcsCryptographyService {

    private final ConfigurationService configurationService;
    private final Gson gson = new Gson();
    private final ObjectMapper objectMapper = new ObjectMapper().registerModule(new JavaTimeModule());

    public DcsCryptographyService(ConfigurationService configurationService) {
        this.configurationService = configurationService;
    }

    public JWSObject preparePayload(DcsPayload passportDetails) throws CertificateException, NoSuchAlgorithmException, InvalidKeySpecException, JOSEException, JsonProcessingException {
        JWSObject signedPassportDetails = createJWS(objectMapper.writeValueAsString(passportDetails));
        JWEObject encryptedPassportDetails = createJWE(signedPassportDetails.serialize());
        JWSObject signedAndEncryptedPassportDetails = createJWS(encryptedPassportDetails.serialize());
        return signedAndEncryptedPassportDetails;
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
}
