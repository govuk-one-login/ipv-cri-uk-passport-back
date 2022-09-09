package uk.gov.di.ipv.cri.passport.library.persistence;

import software.amazon.awssdk.enhanced.dynamodb.DynamoDbEnhancedClient;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.Key;
import software.amazon.awssdk.enhanced.dynamodb.TableSchema;
import software.amazon.awssdk.enhanced.dynamodb.model.QueryConditional;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.DynamoDbClientBuilder;
import uk.gov.di.ipv.cri.passport.library.config.PassportConfigurationService;
import uk.gov.di.ipv.cri.passport.library.persistence.item.DynamodbItem;

import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.stream.Collectors;

import static uk.gov.di.ipv.cri.passport.library.config.ConfigurationVariable.SESSION_TTL;

public class DataStore<T extends DynamodbItem> {

    private final DynamoDbEnhancedClient dynamoDbEnhancedClient;
    private final String tableName;
    private final Class<T> typeParameterClass;
    private final PassportConfigurationService passportConfigurationService;

    public DataStore(
            String tableName,
            Class<T> typeParameterClass,
            DynamoDbEnhancedClient dynamoDbEnhancedClient,
            PassportConfigurationService passportConfigurationService) {
        this.tableName = tableName;
        this.typeParameterClass = typeParameterClass;
        this.dynamoDbEnhancedClient = dynamoDbEnhancedClient;
        this.passportConfigurationService = passportConfigurationService;
    }

    public static DynamoDbEnhancedClient getClient(URI endpointOverride) {
        DynamoDbClientBuilder clientBuilder =
                DynamoDbClient.builder()
                        .endpointOverride(endpointOverride)
                        .httpClient(UrlConnectionHttpClient.create())
                        .region(Region.EU_WEST_2);

        return DynamoDbEnhancedClient.builder().dynamoDbClient(clientBuilder.build()).build();
    }

    public void create(T item) {
        item.setTtl(
                Instant.now()
                        .plusSeconds(
                                Long.parseLong(
                                        passportConfigurationService.getStackSsmParameter(
                                                SESSION_TTL)))
                        .getEpochSecond());
        getTable().putItem(item);
    }

    public T getItem(String partitionValue, String sortValue) {
        return getItemByKey(
                Key.builder().partitionValue(partitionValue).sortValue(sortValue).build());
    }

    public T getItem(String partitionValue) {
        return getItemByKey(Key.builder().partitionValue(partitionValue).build());
    }

    public List<T> getItems(String partitionValue) {
        return getTable()
                .query(
                        QueryConditional.keyEqualTo(
                                Key.builder().partitionValue(partitionValue).build()))
                .stream()
                .flatMap(page -> page.items().stream())
                .collect(Collectors.toList());
    }

    public T update(T item) {
        return getTable().updateItem(item);
    }

    public T delete(String partitionValue, String sortValue) {
        return delete(Key.builder().partitionValue(partitionValue).sortValue(sortValue).build());
    }

    public T delete(String partitionValue) {
        return delete(Key.builder().partitionValue(partitionValue).build());
    }

    private T getItemByKey(Key key) {
        return getTable().getItem(key);
    }

    private T delete(Key key) {
        return getTable().deleteItem(key);
    }

    private DynamoDbTable<T> getTable() {
        return dynamoDbEnhancedClient.table(
                tableName, TableSchema.fromBean(this.typeParameterClass));
    }
}
