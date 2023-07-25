package uk.gov.di.ipv.cri.passport.acceptance_tests.POJOFromIpvCoreRepo;

public class PassportCheckResult {

    private String resourceId;
    private Attributes attributes;
    private Gpg45Score gpg45Score;

    @Override
    public String toString() {
        return "Root{"
                + "resourceId='"
                + resourceId
                + '\''
                + ", attributes="
                + attributes
                + ", gpg45Score="
                + gpg45Score
                + '}';
    }
}
