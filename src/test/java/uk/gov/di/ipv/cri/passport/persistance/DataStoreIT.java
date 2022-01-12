package uk.gov.di.ipv.cri.passport.persistance;

import com.amazonaws.client.builder.AwsClientBuilder;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBClient;
import com.amazonaws.services.dynamodbv2.document.DynamoDB;
import com.amazonaws.services.dynamodbv2.document.Item;
import com.amazonaws.services.dynamodbv2.document.Table;
import org.junit.jupiter.api.Test;
import uk.gov.di.ipv.cri.passport.domain.DcsResponse;
import uk.gov.di.ipv.cri.passport.domain.PassportFormRequest;
import uk.gov.di.ipv.cri.passport.persistence.DataStore;
import uk.gov.di.ipv.cri.passport.persistence.item.PassportCheckDao;

import java.net.URI;
import java.time.LocalDate;
import java.util.Arrays;
import java.util.Map;
import java.util.UUID;

import static org.junit.Assert.assertEquals;

public class DataStoreIT {

    private static final String dynamodbUrl = "http://localhost:4567";
    private static final URI endpoint = URI.create(dynamodbUrl);
    private static final String DCS_RESPONSE_TABLE_NAME = "local-dev-dcs-response";
    private static final DataStore<PassportCheckDao> dcsResponseDataStore =
            new DataStore<>(
                    DCS_RESPONSE_TABLE_NAME,
                    PassportCheckDao.class, DataStore.getClient(endpoint));

    private static final AmazonDynamoDB independentClient = AmazonDynamoDBClient.builder()
            .withEndpointConfiguration(new AwsClientBuilder.EndpointConfiguration(dynamodbUrl, "eu-west-2"))
            .build();
    private static final DynamoDB localDynamoDb = new DynamoDB(independentClient);
    private static final Table dcsResponseTableHarness = localDynamoDb.getTable(DCS_RESPONSE_TABLE_NAME);

    @Test
    public void shouldPutPassportCheckIntoTable() {
        DcsResponse validDcsResponse =
                new DcsResponse(UUID.randomUUID(), UUID.randomUUID(), false, true, new String[] {"No errors here"});
        PassportFormRequest passportFormRequest =
                new PassportFormRequest(
                        "passport_number",
                        "surname",
                        new String[]{"forename"},
                        LocalDate.parse("2000-10-28"),
                        LocalDate.parse("2022-11-29"));
        String resourceId = "my resource id 3";
        PassportCheckDao passportCheckDao = new PassportCheckDao(resourceId, passportFormRequest, validDcsResponse);

        dcsResponseDataStore.create(passportCheckDao);

        Item savedPassportCheck = dcsResponseTableHarness.getItem("resourceId", "my resource id 3");

        Map<String, Object> savedDcsResponse = savedPassportCheck.getMap("dcsResponse");
        assertEquals(validDcsResponse.isValid(), savedDcsResponse.get("valid"));
        assertEquals(validDcsResponse.getError(), savedDcsResponse.get("error"));
        assertEquals(Arrays.toString(validDcsResponse.getErrorMessage()), savedDcsResponse.get("errorMessage").toString());
        assertEquals(validDcsResponse.getRequestId().toString(), savedDcsResponse.get("requestId"));
        assertEquals(validDcsResponse.getCorrelationId().toString(), savedDcsResponse.get("correlationId"));

        Map<String, Object> savedPassportRequest = savedPassportCheck.getMap("passportFormRequest");
        assertEquals(passportFormRequest.passportNumber, savedPassportRequest.get("passportNumber"));
        assertEquals(passportFormRequest.surname, savedPassportRequest.get("surname"));
        assertEquals(Arrays.toString(passportFormRequest.forenames), savedPassportRequest.get("forenames"));
        assertEquals(passportFormRequest.dateOfBirth.toString(), savedPassportRequest.get("dateOfBirth"));
        assertEquals(passportFormRequest.expiryDate.toString(), savedPassportRequest.get("expiryDate"));
    }
}