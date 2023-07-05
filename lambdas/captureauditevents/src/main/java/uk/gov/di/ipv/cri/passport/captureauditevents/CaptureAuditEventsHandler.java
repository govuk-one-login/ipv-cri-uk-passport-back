package uk.gov.di.ipv.cri.passport.captureauditevents;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.SQSEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.lambda.powertools.logging.CorrelationIdPathConstants;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.metrics.Metrics;
import uk.gov.di.ipv.cri.passport.library.helpers.LogHelper;

public class CaptureAuditEventsHandler implements RequestHandler<SQSEvent, Void> {
    private static final Logger LOGGER = LogManager.getLogger();

    public CaptureAuditEventsHandler() {}

    @Override
    @Logging(clearState = true, correlationIdPath = CorrelationIdPathConstants.API_GATEWAY_REST)
    @Metrics(captureColdStart = true)
    public Void handleRequest(SQSEvent input, Context context) {
        LogHelper.attachComponentIdToLogs();
        try {
            for (SQSEvent.SQSMessage msg : input.getRecords()) {
                LOGGER.info(
                        "Audit event consumed",
                        msg.getEventSource(),
                        "messageBody: " + msg.getBody());
            }
            return null;

        } catch (Exception e) {
            return null;
        }
    }
}
