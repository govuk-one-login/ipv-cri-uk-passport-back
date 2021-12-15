package uk.gov.di.ipv.cri.passport.service;

import com.google.gson.Gson;
import uk.gov.di.ipv.cri.passport.domain.Thumbprints;
import uk.gov.di.ipv.cri.passport.dto.DcsCheckRequestDto;
import uk.gov.di.ipv.cri.passport.dto.DcsPayload;
import uk.gov.di.ipv.cri.passport.dto.DcsResponse;

import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.time.Instant;
import java.util.UUID;

public class PassPortService {

    private final EncryptionService encryptionService;
    private final SigningService signingService;
    private final ConfigurationService configurationService;

    public PassPortService(EncryptionService encryptionService, SigningService signingService, Gson gson, ConfigurationService configurationService) {
        this.encryptionService = encryptionService;
        this.signingService = signingService;
        this.configurationService = configurationService;
    }

    public DcsResponse postValidPassportRequest(DcsCheckRequestDto dto) throws CertificateException, NoSuchAlgorithmException, InvalidKeySpecException {

        Thumbprints clientSigningThumbprints = configurationService.makeThumbprints();
        Key clientSigningKey = configurationService.getDcsSigningKey();

        Gson gson = new Gson();
        var dcsPayload = createValidPassportRequestPayload(dto);

        var wrapped = wrapRequestPayload(gson.toJson(dcsPayload), clientSigningThumbprints, clientSigningKey);

        // send payload

        // unwrap response - other ticket

        // TODO
        return null;

    }

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
        /*
        return signingService.signData(unwrappedPayload)
                .flatMap(encryptionService::encrypt)
                .flatMap(signingService::signData)
                .doOnError(throwable -> { throw new RuntimeException("failed to wrap request payload", throwable); });

         */
    }



    private DcsPayload createValidPassportRequestPayload(DcsCheckRequestDto dto) {
        var correlationId = UUID.randomUUID();
        var requestId = UUID.randomUUID();
        // log.info("Creating new DCS payload (requestId: {}, correlationId: {})", requestId, correlationId);

        return new DcsPayload(correlationId, requestId, Instant.now(), dto.getPassportNumber(),
                dto.getSurname(), new String[]{dto.getForenames()}, dto.getDateOfBirth(), dto.getExpiryDate());
    }

}
