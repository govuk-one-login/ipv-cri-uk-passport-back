package uk.gov.di.ipv.cri.passport.acceptance_tests.POJOFromIpvCoreRepo;

public class CodeRoot {

    private Code code;

    public CodeRoot() {}

    public CodeRoot(Code code) {
        this.code = code;
    }

    public Code getCode() {
        return code;
    }

    public void setCode(Code code) {
        this.code = code;
    }

    @Override
    public String toString() {
        return "Root{" + "code=" + code + '}';
    }
}
