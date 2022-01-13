package uk.gov.di.ipv.cri.passport.integrationtest;

import com.amazonaws.client.builder.AwsClientBuilder;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBClient;
import com.amazonaws.services.dynamodbv2.document.DynamoDB;
import com.amazonaws.services.dynamodbv2.document.Item;
import com.amazonaws.services.dynamodbv2.document.Table;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import uk.gov.di.ipv.cri.passport.domain.DcsResponse;
import uk.gov.di.ipv.cri.passport.domain.PassportFormRequest;
import uk.gov.di.ipv.cri.passport.persistence.DataStore;
import uk.gov.di.ipv.cri.passport.persistence.item.AuthorizationCodeItem;
import uk.gov.di.ipv.cri.passport.persistence.item.PassportCheckDao;
import uk.org.webcompere.systemstubs.environment.EnvironmentVariables;
import uk.org.webcompere.systemstubs.jupiter.SystemStub;
import uk.org.webcompere.systemstubs.jupiter.SystemStubsExtension;

import java.net.URI;
import java.time.LocalDate;
import java.util.Arrays;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;

@ExtendWith(SystemStubsExtension.class)
public class DataStoreIT {

    private static final String dynamodbUrl = "http://localhost:4566";
    private static final URI endpoint = URI.create(dynamodbUrl);
    private static final String DCS_RESPONSE_TABLE_NAME = "integration-test-dcs-response";
    private static final String DCS_AUTHORIZATION_TABLE_NAME =
            "integration-test-cri-passport-auth-codes";
    private static final DataStore<PassportCheckDao> dcsResponseDataStore =
            new DataStore<>(
                    DCS_RESPONSE_TABLE_NAME, PassportCheckDao.class, DataStore.getClient(endpoint));

    private static final AmazonDynamoDB independentClient =
            AmazonDynamoDBClient.builder()
                    .withEndpointConfiguration(
                            new AwsClientBuilder.EndpointConfiguration(dynamodbUrl, "eu-west-2"))
                    .build();
    private static final DynamoDB localDynamoDb = new DynamoDB(independentClient);
    private static final Table dcsResponseTableHarness =
            localDynamoDb.getTable(DCS_RESPONSE_TABLE_NAME);
    private static final Table authorizationCodeTableHarness =
            localDynamoDb.getTable(DCS_AUTHORIZATION_TABLE_NAME);

    @SystemStub
    private final EnvironmentVariables environmentVariables =
            new EnvironmentVariables(
                    "AWS_ACCESS_KEY_ID", "ASDFGHJKL",
                    "AWS_SECRET_ACCESS_KEY", "1234567890987654321");

    @Test
    public void shouldPutPassportCheckIntoTable() {
        DcsResponse validDcsResponse =
                new DcsResponse(UUID.randomUUID(), UUID.randomUUID(), false, true, null);
        PassportFormRequest passportFormRequest =
                new PassportFormRequest(
                        "passport_number",
                        "surname",
                        new String[] {"forename"},
                        LocalDate.parse("2000-10-28"),
                        LocalDate.parse("2022-11-29"));
        String resourceId = "my resource id 3";
        PassportCheckDao passportCheckDao =
                new PassportCheckDao(resourceId, passportFormRequest, validDcsResponse);

        dcsResponseDataStore.create(passportCheckDao);

        Item savedPassportCheck = dcsResponseTableHarness.getItem("resourceId", "my resource id 3");

        Map<String, Object> savedDcsResponse = savedPassportCheck.getMap("dcsResponse");
        assertEquals(validDcsResponse.isValid(), savedDcsResponse.get("valid"));
        assertEquals(validDcsResponse.getError(), savedDcsResponse.get("error"));
        assertEquals(
                validDcsResponse.getErrorMessage(),
                savedDcsResponse.get("errorMessage"));
        assertEquals(validDcsResponse.getRequestId().toString(), savedDcsResponse.get("requestId"));
        assertEquals(
                validDcsResponse.getCorrelationId().toString(),
                savedDcsResponse.get("correlationId"));

        Map<String, Object> savedPassportRequest = savedPassportCheck.getMap("passportFormRequest");
        assertEquals(
                passportFormRequest.getPassportNumber(),
                savedPassportRequest.get("passportNumber"));
        assertEquals(passportFormRequest.getSurname(), savedPassportRequest.get("surname"));
        assertEquals(
                Arrays.toString(passportFormRequest.getForenames()),
                savedPassportRequest.get("forenames"));
        assertEquals(
                passportFormRequest.getDateOfBirth().toString(),
                savedPassportRequest.get("dateOfBirth"));
        assertEquals(
                passportFormRequest.getExpiryDate().toString(),
                savedPassportRequest.get("expiryDate"));
    }

    @Test
    public void shouldPutAuthorizationCodeIntoTable() {
        DataStore<AuthorizationCodeItem> authorizationCodeItemDataStore =
                new DataStore<>(
                        DCS_AUTHORIZATION_TABLE_NAME,
                        AuthorizationCodeItem.class,
                        DataStore.getClient(endpoint));
        AuthorizationCodeItem authorizationCodeItem =
                new AuthorizationCodeItem("authCode item", "resourceId");

        authorizationCodeItemDataStore.create(authorizationCodeItem);

        Item savedAuthorizationCode =
                authorizationCodeTableHarness.getItem("authCode", "authCode item");

        assertEquals(authorizationCodeItem.getAuthCode(), savedAuthorizationCode.get("authCode"));
        assertEquals(
                authorizationCodeItem.getResourceId(), savedAuthorizationCode.get("resourceId"));
    }
}
