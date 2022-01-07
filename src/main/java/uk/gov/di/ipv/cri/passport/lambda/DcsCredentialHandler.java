package uk.gov.di.ipv.cri.passport.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.http.HttpStatus;
import uk.gov.di.ipv.cri.passport.helpers.ApiGatewayResponseGenerator;

public class DcsCredentialHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
    static {
        // Set the default synchronous HTTP client to UrlConnectionHttpClient
        System.setProperty(
                "software.amazon.awssdk.http.service.impl",
                "software.amazon.awssdk.http.urlconnection.UrlConnectionSdkHttpService");
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        return ApiGatewayResponseGenerator.proxyJsonResponse(HttpStatus.SC_OK, "Hello world");
    }
}
