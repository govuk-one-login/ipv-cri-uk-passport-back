package uk.gov.di.ipv.cri.passport.jwtverification;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import uk.gov.di.ipv.cri.passport.library.error.ErrorResponse;
import uk.gov.di.ipv.cri.passport.library.helpers.ApiGatewayResponseGenerator;

import java.text.ParseException;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

public class JwtVerificationHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOGGER = Logger.getLogger(JwtVerificationHandler.class.getName());
    private static final Integer OK = 200;
    private static final Integer BAD_REQUEST = 400;

    @Override
    public APIGatewayProxyResponseEvent handleRequest(APIGatewayProxyRequestEvent input, Context context) {
        if (input.getBody() == null) {
            return ApiGatewayResponseGenerator.proxyJsonResponse(BAD_REQUEST, ErrorResponse.MISSING_SHARED_ATTRIBUTES_JWT);
        }

        try {
            SignedJWT signedJWT = SignedJWT.parse(input.getBody());
            JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
            Map<String, Object> claims = claimsSet.toJSONObject();

            return ApiGatewayResponseGenerator.proxyJsonResponse(OK, claims);
        } catch(ParseException e) {
            LOGGER.log(Level.WARNING, "Failed to parse the shared attributes JWT");
            return ApiGatewayResponseGenerator.proxyJsonResponse(BAD_REQUEST, ErrorResponse.FAILED_TO_PARSE_SHARED_ATTRIBUTES_JWT);
        }
    }
}
