package uk.gov.di.ipv.cri.passport.library.persistance;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.ArgumentMatchers;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbEnhancedClient;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.Key;
import software.amazon.awssdk.enhanced.dynamodb.TableSchema;
import software.amazon.awssdk.enhanced.dynamodb.model.PageIterable;
import software.amazon.awssdk.enhanced.dynamodb.model.QueryConditional;
import uk.gov.di.ipv.cri.common.library.persistence.item.SessionItem;
import uk.gov.di.ipv.cri.passport.library.config.ConfigurationService;
import uk.gov.di.ipv.cri.passport.library.persistence.DataStore;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.cri.passport.library.config.ConfigurationVariable.BACKEND_SESSION_TTL;

@ExtendWith(MockitoExtension.class)
class DataStoreTest {
    private static final String TEST_TABLE_NAME = "test-auth-code-table";

    @Mock private DynamoDbEnhancedClient mockDynamoDbEnhancedClient;
    @Mock private DynamoDbTable<SessionItem> mockDynamoDbTable;
    @Mock private PageIterable<SessionItem> mockPageIterable;
    @Mock private ConfigurationService mockConfigurationService;

    private SessionItem SessionItem;
    private DataStore<SessionItem> dataStore;

    @BeforeEach
    void setUp() {
        when(mockDynamoDbEnhancedClient.table(
                        anyString(), ArgumentMatchers.<TableSchema<SessionItem>>any()))
                .thenReturn(mockDynamoDbTable);

        SessionItem = new SessionItem();
        SessionItem.setAuthorizationCode(new AuthorizationCode().getValue());

        dataStore =
                new DataStore<>(
                        TEST_TABLE_NAME,
                        SessionItem.class,
                        mockDynamoDbEnhancedClient,
                        mockConfigurationService);
    }

    @Test
    void shouldPutItemIntoDynamoDbTable() {
        when(mockConfigurationService.getSsmParameter(BACKEND_SESSION_TTL)).thenReturn("100");

        dataStore.create(SessionItem);

        ArgumentCaptor<SessionItem> SessionItemArgumentCaptor =
                ArgumentCaptor.forClass(SessionItem.class);

        verify(mockDynamoDbEnhancedClient)
                .table(
                        eq(TEST_TABLE_NAME),
                        ArgumentMatchers.<TableSchema<SessionItem>>any());
        verify(mockDynamoDbTable).putItem(SessionItemArgumentCaptor.capture());
        assertEquals(
                SessionItem.getAuthorizationCode(),
                SessionItemArgumentCaptor.getValue().getAuthorizationCode());
    }

    @Test
    void shouldGetItemFromDynamoDbTableViaPartitionKeyAndSortKey() {
        dataStore.getItem("partition-key-12345", "sort-key-12345");

        ArgumentCaptor<Key> keyCaptor = ArgumentCaptor.forClass(Key.class);

        verify(mockDynamoDbEnhancedClient)
                .table(
                        eq(TEST_TABLE_NAME),
                        ArgumentMatchers.<TableSchema<SessionItem>>any());
        verify(mockDynamoDbTable).getItem(keyCaptor.capture());
        assertEquals("partition-key-12345", keyCaptor.getValue().partitionKeyValue().s());
        assertEquals("sort-key-12345", keyCaptor.getValue().sortKeyValue().get().s());
    }

    @Test
    void shouldGetItemFromDynamoDbTableViaPartitionKey() {
        dataStore.getItem("partition-key-12345");

        ArgumentCaptor<Key> keyCaptor = ArgumentCaptor.forClass(Key.class);

        verify(mockDynamoDbEnhancedClient)
                .table(
                        eq(TEST_TABLE_NAME),
                        ArgumentMatchers.<TableSchema<SessionItem>>any());
        verify(mockDynamoDbTable).getItem(keyCaptor.capture());
        assertEquals("partition-key-12345", keyCaptor.getValue().partitionKeyValue().s());
        assertTrue(keyCaptor.getValue().sortKeyValue().isEmpty());
    }

    @Test
    void shouldGetItemsFromDynamoDbTableViaPartitionKeyQueryRequest() {
        when(mockDynamoDbTable.query(any(QueryConditional.class))).thenReturn(mockPageIterable);
        when(mockPageIterable.stream()).thenReturn(Stream.empty());

        dataStore.getItems("partition-key-12345");

        verify(mockDynamoDbEnhancedClient)
                .table(
                        eq(TEST_TABLE_NAME),
                        ArgumentMatchers.<TableSchema<SessionItem>>any());
        verify(mockDynamoDbTable).query(any(QueryConditional.class));
    }

    @Test
    void shouldUpdateItemInDynamoDbTable() {
        dataStore.update(SessionItem);

        ArgumentCaptor<SessionItem> SessionItemArgumentCaptor =
                ArgumentCaptor.forClass(SessionItem.class);

        verify(mockDynamoDbEnhancedClient)
                .table(
                        eq(TEST_TABLE_NAME),
                        ArgumentMatchers.<TableSchema<SessionItem>>any());
        verify(mockDynamoDbTable).updateItem(SessionItemArgumentCaptor.capture());
        assertEquals(
                SessionItem.getAuthorizationCode(),
                SessionItemArgumentCaptor.getValue().getAuthorizationCode());
    }

    @Test
    void shouldDeleteItemFromDynamoDbTableViaPartitionKeyAndSortKey() {
        dataStore.delete("partition-key-12345", "sort-key-12345");

        ArgumentCaptor<Key> keyCaptor = ArgumentCaptor.forClass(Key.class);

        verify(mockDynamoDbEnhancedClient)
                .table(
                        eq(TEST_TABLE_NAME),
                        ArgumentMatchers.<TableSchema<SessionItem>>any());
        verify(mockDynamoDbTable).deleteItem(keyCaptor.capture());
        assertEquals("partition-key-12345", keyCaptor.getValue().partitionKeyValue().s());
        assertEquals("sort-key-12345", keyCaptor.getValue().sortKeyValue().get().s());
    }

    @Test
    void shouldDeleteItemFromDynamoDbTableViaPartitionKey() {
        dataStore.delete("partition-key-12345");

        ArgumentCaptor<Key> keyCaptor = ArgumentCaptor.forClass(Key.class);

        verify(mockDynamoDbEnhancedClient)
                .table(
                        eq(TEST_TABLE_NAME),
                        ArgumentMatchers.<TableSchema<SessionItem>>any());
        verify(mockDynamoDbTable).deleteItem(keyCaptor.capture());
        assertEquals("partition-key-12345", keyCaptor.getValue().partitionKeyValue().s());
        assertTrue(keyCaptor.getValue().sortKeyValue().isEmpty());
    }
}
