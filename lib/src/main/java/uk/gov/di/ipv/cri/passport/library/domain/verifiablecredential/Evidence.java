package uk.gov.di.ipv.cri.passport.library.domain.verifiablecredential;

import com.fasterxml.jackson.annotation.JsonInclude;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import uk.gov.di.ipv.cri.passport.library.annotations.ExcludeFromGeneratedCoverageReport;

import java.util.List;
import java.util.UUID;

import static uk.gov.di.ipv.cri.passport.library.domain.verifiablecredential.VerifiableCredentialConstants.EVIDENCE_TYPE_IDENTITY_CHECK;

@DynamoDbBean
@ExcludeFromGeneratedCoverageReport
@JsonInclude(JsonInclude.Include.NON_NULL)
public class Evidence {

    private String type = EVIDENCE_TYPE_IDENTITY_CHECK;
    private UUID txn;
    private int strength;
    private int validity;
    private List<ContraIndicators> ci;

    public Evidence() {}

    public Evidence(UUID txn, int strength, int validity, List<ContraIndicators> ci) {
        this.txn = txn;
        this.strength = strength;
        this.validity = validity;
        this.ci = ci;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public UUID getTxn() {
        return txn;
    }

    public void setTxn(UUID txn) {
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

    public List<ContraIndicators> getCi() {
        return ci;
    }

    public void setCi(List<ContraIndicators> ci) {
        this.ci = ci;
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
                + ", ci="
                + ci
                + '}';
    }
}
