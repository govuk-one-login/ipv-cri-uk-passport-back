package uk.gov.di.ipv.cri.passport.stubdcs;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;
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
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import org.apache.http.HttpStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.ipv.cri.passport.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.cri.passport.library.domain.DcsResponse;
import uk.gov.di.ipv.cri.passport.library.domain.ProtectedHeader;
import uk.gov.di.ipv.cri.passport.library.domain.Thumbprints;
import uk.gov.di.ipv.cri.passport.library.exceptions.StubDcsException;
import uk.gov.di.ipv.cri.passport.library.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.cri.passport.library.serialization.LocalDateDeserializer;
import uk.gov.di.ipv.cri.passport.library.service.ConfigurationService;

import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.text.ParseException;
import java.time.LocalDate;
import java.util.Map;

@ExcludeFromGeneratedCoverageReport
public class StubDcsHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOGGER = LoggerFactory.getLogger(StubDcsHandler.class);
    private static final Gson gson =
            new GsonBuilder()
                    .registerTypeAdapter(LocalDate.class, new LocalDateDeserializer())
                    .create();
    private static final ConfigurationService configService = new ConfigurationService();
    private static final RSASSAVerifier verifier = getPassportCriVerifier();
    private static final RSAEncrypter encrypter = getPassportCriEncrypter();
    private static final RSASSASigner signer = getStubDcsSigner();
    private static final RSADecrypter decrypter = getStubDcsDecrypter();

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {

        try {
            DcsResponse incomingPayload = verifyAndDecryptAndVerify(input.getBody());

            DcsResponse dcsResponse =
                    new DcsResponse(
                            incomingPayload.getCorrelationId(),
                            incomingPayload.getRequestId(),
                            false,
                            true,
                            null);
            LOGGER.info(
                    "Generated DCS response with correlationId: {} and requestId: {}",
                    dcsResponse.getCorrelationId(),
                    dcsResponse.getRequestId());

            return ApiGatewayResponseGenerator.proxyJoseResponse(
                    HttpStatus.SC_OK, signAndEncryptAndSign(dcsResponse));

        } catch (StubDcsException e) {
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_INTERNAL_SERVER_ERROR, e);
        }
    }

    private String signAndEncryptAndSign(DcsResponse dcsResponse) throws StubDcsException {
        return sign(encrypt(sign(gson.toJson(dcsResponse))));
    }

    private DcsResponse verifyAndDecryptAndVerify(String dcsPayloadString) throws StubDcsException {
        JWSObject signedEncryptedSignedPayload;
        try {
            signedEncryptedSignedPayload = JWSObject.parse(dcsPayloadString);
        } catch (ParseException e) {
            throw new StubDcsException("Unable to parse DCS Payload to JWSObject", e);
        }

        try {
            if (signatureNotValid(signedEncryptedSignedPayload)) {
                throw new StubDcsException("Outer signature of DCS Payload not valid");
            }
        } catch (JOSEException e) {
            throw new StubDcsException("Unable to verify outer signature of DCS Payload", e);
        }

        JWEObject encryptedSignedPayload;
        try {
            encryptedSignedPayload =
                    JWEObject.parse(signedEncryptedSignedPayload.getPayload().toString());
        } catch (ParseException e) {
            throw new StubDcsException("Unable to parse encrypted payload", e);
        }

        JWSObject decryptedSignedPayload = decrypt(encryptedSignedPayload);
        try {
            decryptedSignedPayload.verify(verifier);
        } catch (JOSEException e) {
            throw new StubDcsException("Unable to verify inner signature of DCS Payload", e);
        }

        return gson.fromJson(decryptedSignedPayload.getPayload().toString(), DcsResponse.class);
    }

    private String sign(String stringToSign) throws StubDcsException {
        Thumbprints thumbprints;
        try {
            Certificate stubDcsSigningCertificate = configService.getDcsSigningCert();
            thumbprints =
                    new Thumbprints(
                            configService.getThumbprint(
                                    (X509Certificate) stubDcsSigningCertificate, "SHA-1"),
                            configService.getThumbprint(
                                    (X509Certificate) stubDcsSigningCertificate, "SHA-256"));
        } catch (CertificateException | NoSuchAlgorithmException e) {
            throw new StubDcsException("Unable to generate thumbprints", e);
        }

        ProtectedHeader protectedHeader =
                new ProtectedHeader(
                        JWSAlgorithm.RS256.toString(),
                        thumbprints.getSha1Thumbprint(),
                        thumbprints.getSha256Thumbprint());

        String jsonHeaders = gson.toJson(protectedHeader);

        JWSObject jwsObject =
                new JWSObject(
                        new JWSHeader.Builder(JWSAlgorithm.RS256)
                                .customParams(
                                        gson.fromJson(
                                                jsonHeaders,
                                                new TypeToken<Map<String, Object>>() {}.getType()))
                                .build(),
                        new Payload(stringToSign));

        try {
            jwsObject.sign(signer);
        } catch (JOSEException e) {
            throw new StubDcsException("Unable to sign DCS response", e);
        }

        return jwsObject.serialize();
    }

    private String encrypt(String stringToEncrypt) throws StubDcsException {
        var header =
                new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128CBC_HS256)
                        .type(new JOSEObjectType("JWE"))
                        .build();
        var jwe = new JWEObject(header, new Payload(stringToEncrypt));

        try {
            jwe.encrypt(encrypter);
        } catch (JOSEException e) {
            throw new StubDcsException("Something went wrong, couldn't encrypt JWE", e);
        }

        if (!jwe.getState().equals(JWEObject.State.ENCRYPTED)) {
            throw new StubDcsException(
                    String.format(
                            "Something went wrong, JWE not in encrypted state. State is: '%s'",
                            jwe.getState()));
        }

        return jwe.serialize();
    }

    public JWSObject decrypt(JWEObject encrypted) throws StubDcsException {
        try {
            encrypted.decrypt(decrypter);
            return JWSObject.parse(encrypted.getPayload().toString());
        } catch (ParseException | JOSEException e) {
            throw new StubDcsException("Cannot decrypt DCS payload", e);
        }
    }

    private static RSADecrypter getStubDcsDecrypter() {
        try {
            return new RSADecrypter(configService.getStubDcsEncryptionKey());
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    private static RSASSASigner getStubDcsSigner() {
        try {
            return new RSASSASigner(configService.getStubDcsSigningKey());
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    private static RSAEncrypter getPassportCriEncrypter() {
        try {
            return new RSAEncrypter(
                    (RSAPublicKey) configService.getPassportCriEncryptionCert().getPublicKey());
        } catch (CertificateException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    private static RSASSAVerifier getPassportCriVerifier() {
        try {
            return new RSASSAVerifier(
                    (RSAPublicKey) configService.getPassportCriSigningCert().getPublicKey());
        } catch (CertificateException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    private boolean signatureNotValid(JWSObject toVerify) throws JOSEException {
        return !toVerify.verify(verifier);
    }
}
