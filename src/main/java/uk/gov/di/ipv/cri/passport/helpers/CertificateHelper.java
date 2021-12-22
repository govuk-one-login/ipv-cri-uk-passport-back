package uk.gov.di.ipv.cri.passport.helpers;

import java.nio.charset.StandardCharsets;

public class CertificateHelper {

    private CertificateHelper() {}

    public static String removeHeaderAndFooterFromKey(byte[] bytes) {
        return new String(bytes, StandardCharsets.UTF_8)
                .replaceAll("-----[A-Z ]*-----", "")
                .replaceAll("/", "")
                .replaceAll("\\s+", "");
    }
}
