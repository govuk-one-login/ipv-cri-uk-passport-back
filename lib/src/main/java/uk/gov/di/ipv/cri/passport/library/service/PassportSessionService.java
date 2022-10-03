package uk.gov.di.ipv.cri.passport.library.service;

import com.nimbusds.jwt.JWTClaimsSet;
import uk.gov.di.ipv.cri.common.library.persistence.item.SessionItem;
import uk.gov.di.ipv.cri.passport.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.cri.passport.library.config.ConfigurationService;
import uk.gov.di.ipv.cri.passport.library.helpers.LogHelper;
import uk.gov.di.ipv.cri.passport.library.persistence.DataStore;

import java.net.URI;
import java.text.ParseException;
import java.time.Instant;

import static uk.gov.di.ipv.cri.passport.library.config.EnvironmentVariable.PASSPORT_BACK_SESSIONS_TABLE_NAME;

public class PassportSessionService {
    private static final String RESPONSE_TYPE = "response_type";
    private static final String CLIENT_ID = "client_id";
    private static final String STATE = "state";
    private static final String REDIRECT_URI = "redirect_uri";
    private static final String GOVUK_SIGNIN_JOURNEY_ID = "govuk_signin_journey_id";

    private final DataStore<SessionItem> dataStore;
    private final ConfigurationService configurationService;

    @ExcludeFromGeneratedCoverageReport
    public PassportSessionService(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        this.dataStore =
                new DataStore<>(
                        this.configurationService.getEnvironmentVariable(
                                PASSPORT_BACK_SESSIONS_TABLE_NAME),
                        SessionItem.class,
                        DataStore.getClient(
                                this.configurationService.getDynamoDbEndpointOverride()),
                        this.configurationService);
    }

    public PassportSessionService(
            DataStore<SessionItem> dataStore, ConfigurationService configurationService) {
        this.dataStore = dataStore;
        this.configurationService = configurationService;
    }

    public SessionItem getPassportSession(String passportSessionId) {
        return dataStore.getItem(passportSessionId);
    }

    public SessionItem generatePassportSession(JWTClaimsSet jwtClaimsSet)
            throws ParseException {
        SessionItem passportSessionItem = new SessionItem();

        LogHelper.attachPassportSessionIdToLogs(passportSessionItem.getSessionId().toString());

        passportSessionItem.setCreatedDate(Instant.now().getEpochSecond());
        passportSessionItem.setAttemptCount(0);
        passportSessionItem.setSubject(jwtClaimsSet.getSubject());

        String govukSigninJourneyId = jwtClaimsSet.getStringClaim(GOVUK_SIGNIN_JOURNEY_ID);
        passportSessionItem.setClientSessionId(govukSigninJourneyId);
        LogHelper.attachGovukSigninJourneyIdToLogs(govukSigninJourneyId);

        passportSessionItem.setClientId(jwtClaimsSet.getStringClaim(CLIENT_ID));
        passportSessionItem.setState(jwtClaimsSet.getStringClaim(STATE));
        passportSessionItem.setRedirectUri(URI.create(jwtClaimsSet.getStringClaim(REDIRECT_URI)));

        dataStore.create(passportSessionItem);

        return passportSessionItem;
    }

    public void setLatestDcsResponseResourceId(String passportSessionID, String resourceId) {
        SessionItem passportSessionItem = dataStore.getItem(passportSessionID);
        passportSessionItem.setLatestDcsResponseResourceId(resourceId);
        dataStore.update(passportSessionItem);
    }

    public void incrementAttemptCount(String passportSessionID) {
        SessionItem passportSessionItem = dataStore.getItem(passportSessionID);
        passportSessionItem.setAttemptCount(passportSessionItem.getAttemptCount() + 1);
        dataStore.update(passportSessionItem);
    }
}
