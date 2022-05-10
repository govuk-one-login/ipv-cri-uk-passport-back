package uk.gov.di.ipv.cri.passport.library.domain.verifiablecredential;

import com.fasterxml.jackson.annotation.JsonInclude;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import uk.gov.di.ipv.cri.passport.library.annotations.ExcludeFromGeneratedCoverageReport;

import java.util.List;

import static uk.gov.di.ipv.cri.passport.library.domain.verifiablecredential.VerifiableCredentialConstants.EVIDENCE_TYPE_IDENTITY_CHECK;

@DynamoDbBean
@ExcludeFromGeneratedCoverageReport
@JsonInclude(JsonInclude.Include.NON_NULL)
public class Evidence {

    private String type = EVIDENCE_TYPE_IDENTITY_CHECK;
    private String txn;
    private int strengthScore;
    private int validityScore;
    private List<ContraIndicators> ci;

    public Evidence() {}

    public Evidence(String txn, int strengthScore, int validityScore, List<ContraIndicators> ci) {
        this.txn = txn;
        this.strengthScore = strengthScore;
        this.validityScore = validityScore;
        this.ci = ci;
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

    public int getStrengthScore() {
        return strengthScore;
    }

    public void setStrengthScore(int strengthScore) {
        this.strengthScore = strengthScore;
    }

    public int getValidityScore() {
        return validityScore;
    }

    public void setValidityScore(int validityScore) {
        this.validityScore = validityScore;
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
                + strengthScore
                + ", validity="
                + validityScore
                + ", ci="
                + ci
                + '}';
    }
}
