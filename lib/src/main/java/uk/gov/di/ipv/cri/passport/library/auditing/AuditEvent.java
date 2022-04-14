package uk.gov.di.ipv.cri.passport.library.auditing;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import uk.gov.di.ipv.cri.passport.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
public class AuditEvent {
    @JsonProperty private int timestamp;

    @JsonProperty("event_name")
    private AuditEventTypes event;

    @JsonCreator
    public AuditEvent(
            @JsonProperty(value = "timestamp", required = true) int timestamp,
            @JsonProperty(value = "event_name", required = true) AuditEventTypes event) {
        this.timestamp = timestamp;
        this.event = event;
    }

    public long getTimestamp() {
        return timestamp;
    }

    public AuditEventTypes getEvent() {
        return event;
    }
}
