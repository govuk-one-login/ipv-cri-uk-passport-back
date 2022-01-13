package uk.gov.di.ipv.cri.passport.domain;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonProperty;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;

import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.UUID;

@DynamoDbBean
public class PassportFormRequest {
    private static final String DATE_FORMAT = "yyyy-MM-dd";
    private static final String TIME_ZONE = "UTC";

    @JsonProperty private UUID correlationId;
    @JsonProperty private UUID requestId;
    @JsonProperty private String timestamp;
    @JsonProperty private String passportNumber;
    @JsonProperty private String surname;

    @JsonFormat(with = JsonFormat.Feature.ACCEPT_SINGLE_VALUE_AS_ARRAY)
    public String[] forenames;

    @JsonFormat(pattern = DATE_FORMAT, timezone = TIME_ZONE)
    public LocalDate dateOfBirth;

    @JsonFormat(pattern = DATE_FORMAT, timezone = TIME_ZONE)
    public LocalDate expiryDate;

    public PassportFormRequest() {}

    @JsonCreator
    public PassportFormRequest(
            @JsonProperty(value = "passportNumber", required = true) String passportNumber,
            @JsonProperty(value = "surname", required = true) String surname,
            @JsonProperty(value = "forenames", required = true) String[] forenames,
            @JsonProperty(value = "dateOfBirth", required = true) LocalDate dateOfBirth,
            @JsonProperty(value = "expiryDate", required = true) LocalDate expiryDate) {
        this.passportNumber = passportNumber;
        this.surname = surname;
        this.forenames = forenames;
        this.dateOfBirth = dateOfBirth;
        this.expiryDate = expiryDate;
        this.correlationId = UUID.randomUUID();
        this.requestId = UUID.randomUUID();
        this.timestamp = ZonedDateTime.now(ZoneOffset.UTC).format(DateTimeFormatter.ISO_INSTANT);
    }

    public UUID getCorrelationId() {
        return correlationId;
    }

    public UUID getRequestId() {
        return requestId;
    }

    public String getTimestamp() {
        return timestamp;
    }

    public String getPassportNumber() {
        return passportNumber;
    }

    public String getSurname() {
        return surname;
    }

    public String[] getForenames() {
        return forenames;
    }

    public LocalDate getDateOfBirth() {
        return dateOfBirth;
    }

    public LocalDate getExpiryDate() {
        return expiryDate;
    }
}
