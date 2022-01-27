package uk.gov.di.ipv.cri.passport.library.helpers;

import com.nimbusds.oauth2.sdk.util.StringUtils;

import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

public class RequestHelper {

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
}
