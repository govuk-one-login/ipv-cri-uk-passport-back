package uk.gov.di.ipv.cri.passport.library.domain.verifiablecredential;

import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import uk.gov.di.ipv.cri.passport.library.annotations.ExcludeFromGeneratedCoverageReport;

@DynamoDbBean
@ExcludeFromGeneratedCoverageReport
public class Evidence {
    private Gpg45Evidence gpg45Evidence;

    public Evidence() {}

    public Evidence(Gpg45Evidence gpg45Evidence) {
        this.gpg45Evidence = gpg45Evidence;
    }

    public Gpg45Evidence getGpg45Evidence() {
        return gpg45Evidence;
    }

    public void setGpg45Evidence(Gpg45Evidence gpg45Evidence) {
        this.gpg45Evidence = gpg45Evidence;
    }

    @Override
    public String toString() {
        return "PassportGpg45Score{"
                + "evidence="
                + (gpg45Evidence != null ? gpg45Evidence : "empty")
                + '}';
    }
}
