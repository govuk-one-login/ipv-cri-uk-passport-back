package uk.gov.di.ipv.cri.passport.helpers;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class CertificateHelperTest {

    @Test
    void shouldRemoveHeaderAndFooterFromKeyAndRemoveSpaces() {
        String providedString =
                "-----BEGIN RSA PRIVATE KEY-----Hello there!-----END RSA PRIVATE KEY-----";
        byte[] providedBytes = providedString.getBytes(StandardCharsets.UTF_8);

        assertEquals("Hellothere!", CertificateHelper.removeHeaderAndFooterFromKey(providedBytes));
    }
}
