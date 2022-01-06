package uk.gov.di.ipv.cri.passport.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.google.gson.Gson;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import org.apache.http.HttpStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.ipv.cri.passport.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.cri.passport.domain.DcsResponse;
import uk.gov.di.ipv.cri.passport.domain.ProtectedHeader;
import uk.gov.di.ipv.cri.passport.domain.Thumbprints;
import uk.gov.di.ipv.cri.passport.exceptions.IpvCryptoException;
import uk.gov.di.ipv.cri.passport.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.cri.passport.service.ConfigurationService;

import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Map;
import java.util.UUID;

@ExcludeFromGeneratedCoverageReport
public class StubDcsHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    static {
        // Set the default synchronous HTTP client to UrlConnectionHttpClient
        System.setProperty(
                "software.amazon.awssdk.http.service.impl",
                "software.amazon.awssdk.http.urlconnection.UrlConnectionSdkHttpService");
    }

    private static final Logger LOGGER = LoggerFactory.getLogger(StubDcsHandler.class);
    private static final Gson gson = new Gson();
    private static final ConfigurationService configService = new ConfigurationService();

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {

        DcsResponse dcsResponse =
                new DcsResponse(UUID.randomUUID(), UUID.randomUUID(), false, true, null);
        LOGGER.info(
                "Generated DCS response with correlationId: {} and requestId: {}",
                dcsResponse.getCorrelationId(),
                dcsResponse.getRequestId());

        try {
            var signedPayload = sign(gson.toJson(dcsResponse));
            var encryptedPayload = encrypt(signedPayload);
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_OK, sign(encryptedPayload));
        } catch (NoSuchAlgorithmException
                | InvalidKeySpecException
                | JOSEException
                | CertificateException e) {
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_INTERNAL_SERVER_ERROR, e);
        }
    }

    private String sign(String stringToSign)
            throws CertificateException, NoSuchAlgorithmException, InvalidKeySpecException,
                    JOSEException {
        Certificate stubDcsSigningCertificate = configService.getStubDcsSigningCert();
        Thumbprints thumbprints =
                new Thumbprints(
                        configService.getThumbprint(
                                (X509Certificate) stubDcsSigningCertificate, "SHA-1"),
                        configService.getThumbprint(
                                (X509Certificate) stubDcsSigningCertificate, "SHA-256"));

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

        jwsObject.sign(new RSASSASigner((RSAPrivateKey) configService.getStubDcsSigningKey()));

        return jwsObject.serialize();
    }

    private String encrypt(String stringToEncrypt) throws CertificateException, JOSEException {
        var header =
                new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128CBC_HS256)
                        .type(new JOSEObjectType("JWE"))
                        .build();
        var jwe = new JWEObject(header, new Payload(stringToEncrypt));

        jwe.encrypt(
                new RSAEncrypter(
                        (RSAPublicKey)
                                configService.getPassportCriEncryptionCert().getPublicKey()));

        if (!jwe.getState().equals(JWEObject.State.ENCRYPTED)) {
            throw new IpvCryptoException("Something went wrong, couldn't encrypt JWE");
        }

        return jwe.serialize();
    }
}
