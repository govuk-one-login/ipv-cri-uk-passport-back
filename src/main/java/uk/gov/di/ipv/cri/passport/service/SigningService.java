package uk.gov.di.ipv.cri.passport.service;

import com.amazonaws.services.kms.model.GetPublicKeyResult;
import com.google.gson.Gson;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader.Builder;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import io.jsonwebtoken.SignatureAlgorithm;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.text.ParseException;
import java.util.Map;
import uk.gov.di.ipv.cri.passport.domain.ProtectedHeader;
import uk.gov.di.ipv.cri.passport.domain.Thumbprints;
import uk.gov.di.ipv.cri.passport.kms.KmsSigner;

public class SigningService {

    private final ConfigurationService configurationService;
    private final KmsSigner kmsSigner;
    private final Gson gson = new Gson();

    public SigningService() {
        this.configurationService = new ConfigurationService();
        this.kmsSigner = new KmsSigner(configurationService.getDcsSigningKeyId());
    }

    public SigningService(
        ConfigurationService configurationService,
        KmsSigner kmsSigner) {
        this.configurationService = configurationService;
        this.kmsSigner = kmsSigner;
    }

    public String signData(String payload)
        throws CertificateException, NoSuchAlgorithmException, InvalidKeySpecException, JOSEException {

        Thumbprints clientSigningThumbprints = configurationService.makeThumbprints();
        GetPublicKeyResult clientSigningKey = configurationService.getDcsSigningKey();

        var protectedHeader = new ProtectedHeader(
            SignatureAlgorithm.RS256.toString(),
            clientSigningThumbprints.getSha1Thumbprint(),
            clientSigningThumbprints.getSha256Thumbprint());

        var jsonHeaders = gson.toJson(protectedHeader);

        JWSObject jwsObject =
            new JWSObject(
                new Builder(JWSAlgorithm.RS256)
                    .customParams(gson.fromJson(jsonHeaders, Map.class))
                    .keyID(clientSigningKey.getKeyId())
                    .build(),
                new Payload(payload));

        jwsObject.sign(kmsSigner);

        return jwsObject.serialize();
    }

    public String unwrapSignature(String data, Certificate serverSigningCert) {
        try {
            var jws = JWSObject.parse(data);
            var verifier = new RSASSAVerifier((RSAPublicKey) serverSigningCert.getPublicKey());

            if (!jws.verify(verifier)) {
                throw new RuntimeException("Failed to verify received JWS");
            }
            return jws.getPayload().toString();
        } catch (ParseException | JOSEException e) {

            //todo - return our own custome  error
            return "some error ";
            //return error(e);
        }
    }
}
