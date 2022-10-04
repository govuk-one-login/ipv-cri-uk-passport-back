package uk.gov.di.ipv.cri.passport.library.helpers;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import org.junit.jupiter.api.Test;
import uk.gov.di.ipv.cri.passport.library.error.ErrorResponse;
import uk.gov.di.ipv.cri.passport.library.exceptions.HttpResponseExceptionWithErrorBody;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class RequestHelperTest {

    @Test
    void getHeaderByKeyShouldReturnHeaderIfMatchFound() {
        assertEquals("toyou", RequestHelper.getHeaderByKey(Map.of("tome", "toyou"), "tome"));
    }

    @Test
    void getHeaderByKeyShouldReturnNullIfHeaderNotFound() {
        assertNull(RequestHelper.getHeaderByKey(Map.of("tome", "toyou"), "ohdearohdear"));
    }

    @Test
    void getHeaderByKeyShouldReturnNullIfNoHeadersProvided() {
        assertNull(RequestHelper.getHeaderByKey(null, "ohdearohdear"));
    }

    @Test
    void getSessionIdShouldReturnSessionIdFromHeaders() throws Exception {
        var event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("session_id", "qwertyuiop"));

        assertEquals("qwertyuiop", RequestHelper.getSessionId(event));
    }

    @Test
    void getSessionIdShouldThrowIfSessionIdNotFound() {
        var event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("session_id", ""));

        var exception =
                assertThrows(
                        HttpResponseExceptionWithErrorBody.class,
                        () -> RequestHelper.getSessionId(event));

        assertEquals(
                ErrorResponse.MISSING_PASSPORT_SESSION_ID_HEADER, exception.getErrorResponse());
    }
}
