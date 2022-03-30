package uk.gov.di.ipv.cri.passport.library.domain.verifiablecredential;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import uk.gov.di.ipv.cri.passport.library.annotations.ExcludeFromGeneratedCoverageReport;

@JsonInclude(JsonInclude.Include.NON_NULL)
@ExcludeFromGeneratedCoverageReport
public class NameParts {
    private String value;
    private String type;
    private String validFrom;
    private String validUntil;

    public NameParts(
            @JsonProperty(value = "value", required = true) String value,
            @JsonProperty(value = "type", required = true) String type,
            @JsonProperty(value = "validFrom") String validFrom,
            @JsonProperty(value = "validUntil") String validUntil) {
        this.value = value;
        this.type = type;
        this.validFrom = validFrom;
        this.validUntil = validUntil;
    }

    public NameParts(String type, String value) {
        this.value = value;
        this.type = type;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getValidFrom() {
        return validFrom;
    }

    public void setValidFrom(String validFrom) {
        this.validFrom = validFrom;
    }

    public String getValidUntil() {
        return validUntil;
    }

    public void setValidUntil(String validUntil) {
        this.validUntil = validUntil;
    }

    @Override
    public String toString() {
        return "NameParts{"
                + "value='"
                + value
                + '\''
                + ", type='"
                + type
                + '\''
                + ", validFrom='"
                + validFrom
                + '\''
                + ", validUntil='"
                + validUntil
                + '\''
                + '}';
    }
}
