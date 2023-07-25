package uk.gov.di.ipv.cri.passport.acceptance_tests.POJOFromIpvCoreRepo;

public class Evidence {

    private int strength;
    private int validity;

    @Override
    public String toString() {
        return "Evidence{" + "strength=" + strength + ", validity=" + validity + '}';
    }
}
