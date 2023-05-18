package uk.gov.di.ipv.cri.passport.acceptance_tests.POJOFromIpvCoreRepo;

import java.util.ArrayList;

public class Names {

    private String familyName;
    private ArrayList<String> givenNames;

    public Names() {}

    public Names(String familyName, ArrayList<String> givenNames) {
        this.familyName = familyName;
        this.givenNames = givenNames;
    }

    public String getFamilyName() {
        return familyName;
    }

    public void setFamilyName(String familyName) {
        this.familyName = familyName;
    }

    public ArrayList<String> getGivenNames() {
        return givenNames;
    }

    public void setGivenNames(ArrayList<String> givenNames) {
        this.givenNames = givenNames;
    }

    @Override
    public String toString() {
        return "Names{" + "familyName='" + familyName + '\'' + ", givenNames=" + givenNames + '}';
    }
}
