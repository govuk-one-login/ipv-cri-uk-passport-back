package uk.gov.di.ipv.cri.passport.library.domain;

import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import uk.gov.di.ipv.cri.passport.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
@DynamoDbBean
public class Gpg45Evidence {
    private int strength;
    private int validity;

    public Gpg45Evidence() {}

    public Gpg45Evidence(int strength, int validity) {
        this.strength = strength;
        this.validity = validity;
    }

    public int getStrength() {
        return strength;
    }

    public int getValidity() {
        return validity;
    }
}
