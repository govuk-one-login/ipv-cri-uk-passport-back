package uk.gov.di.ipv.cri.passport.library.auditing;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;
import uk.gov.di.ipv.cri.passport.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.cri.passport.library.persistence.item.PassportSessionItem;

@ExcludeFromGeneratedCoverageReport
@Data
public class AuditEventUser {

    @JsonProperty(value = "user_id")
    private final String userId;

    @JsonProperty(value = "session_id")
    private final String sessionId;

    @JsonProperty(value = "govuk_signin_journey_id")
    private final String govukSigninJourneyId;

    public AuditEventUser(
            @JsonProperty(value = "user_id") String userId,
            @JsonProperty(value = "session_id") String sessionId,
            @JsonProperty(value = "govuk_signin_journey_id") String govukSigninJourneyId) {
        this.userId = userId;
        this.sessionId = sessionId;
        this.govukSigninJourneyId = govukSigninJourneyId;
    }

    public static AuditEventUser fromPassportSessionItem(PassportSessionItem passportSessionItem) {
        return new AuditEventUser(
                passportSessionItem.getUserId(),
                passportSessionItem.getPassportSessionId(),
                passportSessionItem.getGovukSigninJourneyId());
    }
}
