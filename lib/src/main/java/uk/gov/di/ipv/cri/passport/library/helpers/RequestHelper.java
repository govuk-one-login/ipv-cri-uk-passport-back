package uk.gov.di.ipv.cri.passport.library.helpers;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import org.apache.http.HttpStatus;
import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URLEncodedUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.ipv.cri.passport.library.error.ErrorResponse;
import uk.gov.di.ipv.cri.passport.library.exceptions.HttpResponseExceptionWithErrorBody;

import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

public class RequestHelper {

    public static final String PASSPORT_SESSION_ID_HEADER = "passport_session_id";
    private static final Logger LOGGER = LoggerFactory.getLogger(RequestHelper.class);

    private RequestHelper() {}

    public static String getHeaderByKey(Map<String, String> headers, String headerKey) {
        if (Objects.isNull(headers)) {
            return null;
        }
        var values =
                headers.entrySet().stream()
                        .filter(e -> headerKey.equalsIgnoreCase(e.getKey()))
                        .map(Map.Entry::getValue)
                        .collect(Collectors.toList());
        if (values.size() == 1) {
            var value = values.get(0);
            if (StringUtils.isNotBlank(value)) {
                return value;
            }
        }
        return null;
    }

    public static Map<String, String> parseRequestBody(String body) {
        Map<String, String> queryPairs = new HashMap<>();

        for (NameValuePair pair : URLEncodedUtils.parse(body, Charset.defaultCharset())) {
            queryPairs.put(pair.getName(), pair.getValue());
        }

        return queryPairs;
    }

    public static String getPassportSessionId(APIGatewayProxyRequestEvent event)
            throws HttpResponseExceptionWithErrorBody {
        String ipvSessionId =
                RequestHelper.getHeaderByKey(event.getHeaders(), PASSPORT_SESSION_ID_HEADER);
        if (ipvSessionId == null) {
            LOGGER.error("{} not present in headers", PASSPORT_SESSION_ID_HEADER);
            throw new HttpResponseExceptionWithErrorBody(
                    HttpStatus.SC_BAD_REQUEST, ErrorResponse.MISSING_PASSPORT_SESSION_ID_HEADER);
        }
        LogHelper.attachPassportSessionIdToLogs(ipvSessionId);
        return ipvSessionId;
    }
}
