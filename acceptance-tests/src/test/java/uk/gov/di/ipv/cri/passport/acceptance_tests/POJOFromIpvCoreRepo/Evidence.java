package uk.gov.di.ipv.cri.passport.acceptance_tests.POJOFromIpvCoreRepo;

public class Evidence {

    private int strength;
    private int validity;

    public Evidence() {}

    public Evidence(int strength, int validity) {
        this.strength = strength;
        this.validity = validity;
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
        return "Evidence{" + "strength=" + strength + ", validity=" + validity + '}';
    }
}
