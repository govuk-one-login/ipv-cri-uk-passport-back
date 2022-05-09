package uk.gov.di.ipv.cri.passport.library.domain.verifiablecredential;

import com.fasterxml.jackson.annotation.JsonProperty;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import uk.gov.di.ipv.cri.passport.library.annotations.ExcludeFromGeneratedCoverageReport;

import static uk.gov.di.ipv.cri.passport.library.domain.verifiablecredential.VerifiableCredentialConstants.EVIDENCE_TYPE_IDENTITY_CHECK;

@DynamoDbBean
@ExcludeFromGeneratedCoverageReport
public class Evidence {

    private String type = EVIDENCE_TYPE_IDENTITY_CHECK;
    private String txn;
    private int strength;
    private int validity;

    public Evidence(
            @JsonProperty("strength") int strength,
            @JsonProperty("validity") int validity,
            @JsonProperty("txn") String txn) {
        this.strength = strength;
        this.validity = validity;
        this.txn = txn;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getTxn() {
        return txn;
    }

    public void setTxn(String txn) {
        this.txn = txn;
    }

    public int getStrength() {
        return strength;
    }

    public void setStrength(int strength) {
        this.strength = strength;
    }

    public int getValidity() {
        return validity;
    }

    public void setValidity(int validity) {
        this.validity = validity;
    }

    @Override
    public String toString() {
        return "Evidence{"
                + "type="
                + type
                + ", txn="
                + txn
                + ", strength="
                + strength
                + ", validity="
                + validity
                + '}';
    }
}
