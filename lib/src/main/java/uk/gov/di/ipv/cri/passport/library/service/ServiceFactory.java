package uk.gov.di.ipv.cri.passport.library.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import software.amazon.awssdk.services.sqs.SqsClient;
import uk.gov.di.ipv.cri.common.library.service.AuditEventFactory;
import uk.gov.di.ipv.cri.common.library.service.AuditService;
import uk.gov.di.ipv.cri.common.library.service.ConfigurationService;
import uk.gov.di.ipv.cri.common.library.service.SessionService;
import uk.gov.di.ipv.cri.passport.library.config.PassportConfigurationService;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.time.Clock;

public class ServiceFactory {
    private final PassportConfigurationService passportConfigurationService;
    private final ConfigurationService configurationService;
    private final ObjectMapper objectMapper;
    private final AuditService auditService;
    private final PassportService passportService;
    private final DcsCryptographyService dcsCryptographyService;
    private final DcsPassportCheckService dcsPassportCheckService;

    private final SessionService sessionService;

    public ServiceFactory(ObjectMapper objectMapper)
            throws NoSuchAlgorithmException, InvalidKeyException, IOException, CertificateException,
                    InvalidKeySpecException, KeyStoreException {
        this.objectMapper = objectMapper;
        this.passportConfigurationService = new PassportConfigurationService();
        this.passportService = new PassportService(passportConfigurationService);
        this.configurationService = new ConfigurationService();
        this.auditService =
                new AuditService(
                        SqsClient.builder().build(),
                        configurationService,
                        objectMapper,
                        new AuditEventFactory(configurationService, Clock.systemUTC()));
        this.dcsCryptographyService = new DcsCryptographyService(passportConfigurationService);
        this.dcsPassportCheckService = new DcsPassportCheckService(passportConfigurationService);

        this.sessionService = new SessionService();
    }

    public PassportService getPassportService() {
        return passportService;
    }

    public PassportConfigurationService getPassportConfigurationService() {
        return passportConfigurationService;
    }

    public AuditService getAuditService() {
        return auditService;
    }

    public DcsCryptographyService getDcsCryptographyService() {
        return dcsCryptographyService;
    }

    public DcsPassportCheckService getDcsPassportCheckService() {
        return dcsPassportCheckService;
    }

    public SessionService getSessionService() {
        return sessionService;
    }
}
