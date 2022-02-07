package uk.gov.di.ipv.cri.passport.library.domain;

import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbConvertedBy;
import uk.gov.di.ipv.cri.passport.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.cri.passport.library.persistence.item.Gpg45EvidenceConverter;

@DynamoDbBean
@ExcludeFromGeneratedCoverageReport
public class PassportGpg45Score {
    private final Gpg45Evidence evidence;

    public PassportGpg45Score(Gpg45Evidence evidence) {
        this.evidence = evidence;
    }

    @DynamoDbConvertedBy(Gpg45EvidenceConverter.class)
    public Gpg45Evidence getEvidence() {
        return evidence;
    }
}
