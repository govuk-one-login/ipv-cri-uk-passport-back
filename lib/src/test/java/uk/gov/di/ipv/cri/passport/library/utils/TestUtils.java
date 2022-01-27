package uk.gov.di.ipv.cri.passport.library.utils;

import java.io.ByteArrayInputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Base64;

public class TestUtils {
    public static Certificate getDcsSigningCertificate(String base64certificate)
            throws CertificateException {
        byte[] binaryCertificate = Base64.getDecoder().decode(base64certificate);
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        return factory.generateCertificate(new ByteArrayInputStream(binaryCertificate));
    }
}
