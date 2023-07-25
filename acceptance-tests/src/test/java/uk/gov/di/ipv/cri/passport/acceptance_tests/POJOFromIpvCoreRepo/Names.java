package uk.gov.di.ipv.cri.passport.acceptance_tests.POJOFromIpvCoreRepo;

import java.util.ArrayList;

public class Names {

    private String familyName;
    private ArrayList<String> givenNames;

    @Override
    public String toString() {
        return "Names{" + "familyName='" + familyName + '\'' + ", givenNames=" + givenNames + '}';
    }
}
