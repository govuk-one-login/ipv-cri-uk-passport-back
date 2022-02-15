package uk.gov.di.ipv.cri.passport.library.domain;

import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import uk.gov.di.ipv.cri.passport.library.annotations.ExcludeFromGeneratedCoverageReport;

@DynamoDbBean
@ExcludeFromGeneratedCoverageReport
public class PassportGpg45Score {
    private Gpg45Evidence evidence;

    public PassportGpg45Score() {}

    public PassportGpg45Score(Gpg45Evidence evidence) {
        this.evidence = evidence;
    }

    public Gpg45Evidence getEvidence() {
        return evidence;
    }

    public void setEvidence(Gpg45Evidence evidence) {
        this.evidence = evidence;
    }

    @Override
    public String toString() {
        return "PassportGpg45Score{" + "evidence=" + (evidence != null ? evidence : "empty") + '}';
    }
}
