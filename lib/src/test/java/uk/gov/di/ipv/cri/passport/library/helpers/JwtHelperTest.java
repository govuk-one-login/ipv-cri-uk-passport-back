package uk.gov.di.ipv.cri.passport.library.helpers;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.cri.passport.library.domain.verifiablecredential.BirthDate;
import uk.gov.di.ipv.cri.passport.library.domain.verifiablecredential.CredentialSubject;
import uk.gov.di.ipv.cri.passport.library.domain.verifiablecredential.Evidence;
import uk.gov.di.ipv.cri.passport.library.domain.verifiablecredential.Name;
import uk.gov.di.ipv.cri.passport.library.domain.verifiablecredential.NamePartType;
import uk.gov.di.ipv.cri.passport.library.domain.verifiablecredential.NameParts;
import uk.gov.di.ipv.cri.passport.library.domain.verifiablecredential.Passport;
import uk.gov.di.ipv.cri.passport.library.domain.verifiablecredential.VerifiableCredential;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.text.ParseException;
import java.time.Instant;
import java.time.LocalDate;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.ipv.cri.passport.library.helpers.fixtures.TestFixtures.EC_PRIVATE_KEY_1;
import static uk.gov.di.ipv.cri.passport.library.helpers.fixtures.TestFixtures.EC_PUBLIC_JWK_1;

@ExtendWith(MockitoExtension.class)
class JwtHelperTest {
    public static final String BIRTH_DATE = "2020-02-03";
    public static final String PASSPORT_NUMBER = "123456789";
    public static final String GIVEN_NAME = "Paul";
    public static final String EXPIRY_DATE = "2020-01-01";
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void shouldCreateValidSignedJWT()
            throws JOSEException, ParseException, InvalidKeySpecException, NoSuchAlgorithmException,
                    JsonProcessingException {
        ECDSASigner ecSigner = new ECDSASigner(getPrivateKey());

        VerifiableCredential verifiableCredential =
                new VerifiableCredential(
                        new CredentialSubject(
                                List.of(
                                        new Name(
                                                List.of(
                                                        new NameParts(
                                                                NamePartType.GIVEN_NAME.getName(),
                                                                GIVEN_NAME)))),
                                List.of(new BirthDate(BIRTH_DATE)),
                                List.of(
                                        new Passport(
                                                PASSPORT_NUMBER,
                                                LocalDate.parse(EXPIRY_DATE).toString()))),
                        Collections.singletonList(
                                new Evidence(UUID.randomUUID().toString(), 4, 2, null)));

        JWTClaimsSet testClaimsSet =
                new JWTClaimsSet.Builder()
                        .claim("sub", "test-subject")
                        .claim("iss", "test-issuer")
                        .claim("nbf", Instant.now().getEpochSecond())
                        .claim("vc", verifiableCredential)
                        .claim("exp", Instant.now().plusSeconds(100000).getEpochSecond())
                        .build();

        SignedJWT signedJWT = JwtHelper.createSignedJwtFromClaimSet(testClaimsSet, ecSigner);
        JWTClaimsSet generatedClaims = signedJWT.getJWTClaimsSet();

        assertTrue(signedJWT.verify(new ECDSAVerifier(ECKey.parse(EC_PUBLIC_JWK_1))));

        JsonNode claimsSet = objectMapper.readTree(generatedClaims.toString());

        JsonNode vcNode = claimsSet.get("vc");
        JsonNode credentialSubjectNode = vcNode.get("credentialSubject");
        JsonNode nameNode = credentialSubjectNode.get("name");
        JsonNode birthDateNode = credentialSubjectNode.get("birthDate");
        JsonNode passportNode = credentialSubjectNode.get("passport");

        assertEquals(GIVEN_NAME, nameNode.get(0).get("nameParts").get(0).get("value").asText());
        assertEquals(
                NamePartType.GIVEN_NAME.getName(),
                nameNode.get(0).get("nameParts").get(0).get("type").asText());
        assertEquals(BIRTH_DATE, birthDateNode.get(0).get("value").asText());
        assertEquals(PASSPORT_NUMBER, passportNode.get(0).get("documentNumber").asText());
        assertEquals(EXPIRY_DATE, passportNode.get(0).get("expiryDate").asText());
    }

    private ECPrivateKey getPrivateKey() throws InvalidKeySpecException, NoSuchAlgorithmException {
        return (ECPrivateKey)
                KeyFactory.getInstance("EC")
                        .generatePrivate(
                                new PKCS8EncodedKeySpec(
                                        Base64.getDecoder().decode(EC_PRIVATE_KEY_1)));
    }
}
