package uk.gov.di.ipv.cri.passport.service;

import com.google.gson.Gson;
import com.nimbusds.jose.JOSEException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.UUID;
import uk.gov.di.ipv.cri.passport.dto.DcsCheckRequestDto;
import uk.gov.di.ipv.cri.passport.dto.DcsPayload;
import uk.gov.di.ipv.cri.passport.dto.DcsResponse;

public class PassPortService {

    private final EncryptionService encryptionService;
    private final SigningService signingService;
    private final Gson gson = new Gson();


    public PassPortService(EncryptionService encryptionService, SigningService signingService) {
        this.encryptionService = encryptionService;
        this.signingService = signingService;
    }

    public PassPortService() {
        this.encryptionService = new EncryptionService();
        this.signingService = new SigningService();
    }

    public DcsResponse postValidPassportRequest(DcsCheckRequestDto dto)
        throws JOSEException, CertificateException, NoSuchAlgorithmException, InvalidKeySpecException {

        var dcsPayload = createValidPassportRequestPayload(dto);

        String signed = signingService.signData(gson.toJson(dcsPayload));
        //String encrypted = encryptionService.encrypt(signed, configurationService.getDcsEncryptionCert());
        //String secondSigned = signPayload(encrypted);

        // Send to DCS
        // send payload

        // unwrap response - other ticket

        // TODO
        return null;

    }

    private DcsPayload createValidPassportRequestPayload(DcsCheckRequestDto dto) {
        var correlationId = UUID.randomUUID();
        var requestId = UUID.randomUUID();
        // log.info("Creating new DCS payload (requestId: {}, correlationId: {})", requestId, correlationId);

        return new DcsPayload(correlationId, requestId, Timestamp.from(Instant.now()), dto.getPassportNumber(),
            dto.getSurname(), new String[]{dto.getForenames()}, dto.getDateOfBirth(), dto.getExpiryDate());
    }

     /*
    public String wrapRequestPayload(String unwrappedPayload, Thumbprints clientSigningThumbprints, Key clientSigningKey)  {

        try {
            Certificate serverEncryptionCert = configurationService.getDcsEncryptionCert();
            String jws = signingService.signData(unwrappedPayload, clientSigningThumbprints, clientSigningKey);
            String encryptedResult = encryptionService.encrypt(jws, serverEncryptionCert);
            String jwsOut = signingService.signData(encryptedResult, clientSigningThumbprints, clientSigningKey);
            return jwsOut;
        } catch (RuntimeException | CertificateException e) {

            e.printStackTrace();
        }


        //todo
         return "";

        return signingService.signData(unwrappedPayload)
                .flatMap(encryptionService::encrypt)
                .flatMap(signingService::signData)
                .doOnError(throwable -> { throw new RuntimeException("failed to wrap request payload", throwable); });


    }
    */

}
