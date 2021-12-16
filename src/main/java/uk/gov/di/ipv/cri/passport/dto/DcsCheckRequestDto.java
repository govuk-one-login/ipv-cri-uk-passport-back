package uk.gov.di.ipv.cri.passport.dto;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.LocalDate;

public class DcsCheckRequestDto {

    private static final String DATE_FORMAT = "yyyy-MM-dd";
    private static final String TIME_ZONE = "UTC";

    @JsonProperty private final String passportNumber;

    @JsonProperty private final String surname;

    @JsonFormat(with = JsonFormat.Feature.ACCEPT_SINGLE_VALUE_AS_ARRAY)
    private final String[] forenames;

    @JsonFormat(pattern = DATE_FORMAT, timezone = TIME_ZONE)
    private final LocalDate dateOfBirth;

    @JsonFormat(pattern = DATE_FORMAT, timezone = TIME_ZONE)
    private final LocalDate expiryDate;

    @JsonCreator
    public DcsCheckRequestDto(
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
    }
}
