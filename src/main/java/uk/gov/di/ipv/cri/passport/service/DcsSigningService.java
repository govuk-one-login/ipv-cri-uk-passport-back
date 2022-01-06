package uk.gov.di.ipv.cri.passport.service;

import com.google.gson.Gson;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import uk.gov.di.ipv.cri.passport.domain.ProtectedHeader;
import uk.gov.di.ipv.cri.passport.domain.Thumbprints;

import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.text.ParseException;
import java.util.Map;

public class DcsSigningService {

    private final ConfigurationService configurationService;
    private final Gson gson = new Gson();

    public DcsSigningService(ConfigurationService configurationService) {
        this.configurationService = configurationService;
    }

    public DcsSigningService() {
        this.configurationService = new ConfigurationService();
    }

    public JWSObject signData(String stringToSign)
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

        jwsObject.sign(
                new RSASSASigner(configurationService.getPassportCriSigningKey()));

        return jwsObject;
    }

    public String validateOuterSignature(String response)
            throws CertificateException, ParseException, JOSEException {
        JWSObject jwsObject = JWSObject.parse(response);
        return validateSignature(jwsObject);
    }

    public String validateInnerSignature(JWSObject jwsObject)
            throws JOSEException, CertificateException {
        return validateSignature(jwsObject);
    }

    private String validateSignature(JWSObject jwsObject)
            throws CertificateException, JOSEException {
        RSASSAVerifier rsassaVerifier =
                new RSASSAVerifier(
                        (RSAPublicKey) configurationService.getDcsSigningCert().getPublicKey());
        jwsObject.verify(rsassaVerifier);
        return jwsObject.getPayload().toString();
    }
}
