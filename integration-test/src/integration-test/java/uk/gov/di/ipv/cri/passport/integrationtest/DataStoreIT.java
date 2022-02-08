package uk.gov.di.ipv.cri.passport.integrationtest;

import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBClient;
import com.amazonaws.services.dynamodbv2.document.DynamoDB;
import com.amazonaws.services.dynamodbv2.document.Item;
import com.amazonaws.services.dynamodbv2.document.PrimaryKey;
import com.amazonaws.services.dynamodbv2.document.Table;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.junit.jupiter.api.Test;
import uk.gov.di.ipv.cri.passport.library.domain.DcsResponse;
import uk.gov.di.ipv.cri.passport.library.domain.Gpg45Evidence;
import uk.gov.di.ipv.cri.passport.library.domain.PassportAttributes;
import uk.gov.di.ipv.cri.passport.library.domain.PassportGpg45Score;
import uk.gov.di.ipv.cri.passport.library.persistence.DataStore;
import uk.gov.di.ipv.cri.passport.library.persistence.item.PassportCheckDao;

import java.time.LocalDate;
import java.util.Arrays;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class DataStoreIT {

    private static final ObjectMapper objectMapper = new ObjectMapper().registerModule(new JavaTimeModule());
    private static final String DCS_RESPONSE_TABLE_NAME = "dcs-response-integration-test";
    private static final DataStore<PassportCheckDao> dcsResponseDataStore =
            new DataStore<>(
                    DCS_RESPONSE_TABLE_NAME, PassportCheckDao.class, DataStore.getClient(null));

    private static final AmazonDynamoDB independentClient =
            AmazonDynamoDBClient
                    .builder()
                    .withRegion("eu-west-2")
                    .build();

    private static final DynamoDB testClient = new DynamoDB(independentClient);
    private static final Table testHarness =
            testClient.getTable(DCS_RESPONSE_TABLE_NAME);

    @Test
    public void shouldPutPassportCheckIntoTable() throws JsonProcessingException {
        String resourceId = UUID.randomUUID().toString();

        DcsResponse dcsResponse = new DcsResponse(UUID.randomUUID(), UUID.randomUUID(), false, true, null);
        PassportAttributes passportAttributes = new PassportAttributes("passport-number", "surname", new String[]{"family-name"}, LocalDate.of(1900, 1, 1), LocalDate.of(2025, 2, 2));
        passportAttributes.setDcsResponse(dcsResponse);
        Gpg45Evidence gpg45Evidence = new Gpg45Evidence(5, 5);
        PassportCheckDao passportCheckDao = new PassportCheckDao(resourceId, passportAttributes, new PassportGpg45Score(gpg45Evidence));

        dcsResponseDataStore.create(passportCheckDao);

        Item savedPassportCheck = testHarness.getItem("resourceId", resourceId);

        assertEquals(resourceId, savedPassportCheck.get("resourceId"));

        PassportAttributes savedPassportAttributes = objectMapper.readValue(savedPassportCheck.get("attributes").toString(), PassportAttributes.class);
        assertEquals(passportAttributes.getPassportNumber(), savedPassportAttributes.getPassportNumber());
        assertEquals(passportAttributes.getCorrelationId(), savedPassportAttributes.getCorrelationId());
        assertEquals(passportAttributes.getDateOfBirth(), savedPassportAttributes.getDateOfBirth());
        assertEquals(Arrays.toString(passportAttributes.getForenames()), Arrays.toString(savedPassportAttributes.getForenames()));
        assertEquals(passportAttributes.getExpiryDate(), savedPassportAttributes.getExpiryDate());
        assertEquals(passportAttributes.getTimestamp(), savedPassportAttributes.getTimestamp());
        assertEquals(passportAttributes.getSurname(), savedPassportAttributes.getSurname());

        cleanUpEntry(resourceId);
    }

    private void cleanUpEntry(String resourceId) {
        testHarness.deleteItem(new PrimaryKey("resourceId", resourceId));
    }
}
