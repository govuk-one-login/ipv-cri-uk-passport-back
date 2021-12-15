package uk.gov.di.ipv.cri.passport.service;

import com.google.gson.Gson;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import uk.gov.di.ipv.cri.passport.domain.ProtectedHeader;
import uk.gov.di.ipv.cri.passport.domain.Thumbprints;

import java.security.Key;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Map;

public class SigningService {

    public String signData(String data, Thumbprints clientSigningThumbprints, Key clientSigningKey) {

        Gson gson = new Gson();
        var protectedHeader = new ProtectedHeader(
                SignatureAlgorithm.RS256.toString(),
                clientSigningThumbprints.getSha1Thumbprint(),
                clientSigningThumbprints.getSha256Thumbprint());

        var jsonHeaders = gson.toJson(protectedHeader);
        var jws = Jwts
                .builder()
                .setPayload(data)
                .signWith(clientSigningKey, SignatureAlgorithm.RS256)
                .setHeaderParams(gson.fromJson(jsonHeaders, Map.class))
                .compact();

        return jws;
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
