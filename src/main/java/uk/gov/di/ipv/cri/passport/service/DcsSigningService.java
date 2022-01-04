package uk.gov.di.ipv.cri.passport.service;

import com.google.gson.Gson;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSASSASigner;
import uk.gov.di.ipv.cri.passport.domain.ProtectedHeader;
import uk.gov.di.ipv.cri.passport.domain.Thumbprints;

import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
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
                new RSASSASigner((RSAPrivateKey) configurationService.getPassportCriSigningKey()));

        return jwsObject;
    }
}
