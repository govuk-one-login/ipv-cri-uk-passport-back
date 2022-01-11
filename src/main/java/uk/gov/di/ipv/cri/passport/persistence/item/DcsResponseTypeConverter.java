package uk.gov.di.ipv.cri.passport.persistence.item;

import software.amazon.awssdk.enhanced.dynamodb.AttributeConverter;
import software.amazon.awssdk.enhanced.dynamodb.AttributeValueType;
import software.amazon.awssdk.enhanced.dynamodb.EnhancedType;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import uk.gov.di.ipv.cri.passport.domain.DcsResponse;

import java.util.Map;
import java.util.Objects;
import java.util.UUID;

public class DcsResponseTypeConverter implements AttributeConverter<DcsResponse> {

    @Override
    public AttributeValue transformFrom(DcsResponse input) {

        Map<String, AttributeValue> attributeValueMap = Map.of(
                "correlationId", AttributeValue.builder().s(input.getCorrelationId().toString()).build(),
                "requestId", AttributeValue.builder().s(input.getRequestId().toString()).build(),
                "error", AttributeValue.builder().bool(input.getError()).build(),
                "valid", AttributeValue.builder().bool(input.isValid()).build(),
                "errorMessage", Objects.isNull(input.getErrorMessage()) ?
                        AttributeValue.builder().nul(true).build() :
                        AttributeValue.builder().ss(input.getErrorMessage()).build()
        );

        return AttributeValue.builder()
                .m(attributeValueMap)
                .build();
    }

    @Override
    public DcsResponse transformTo(AttributeValue input) {
        Map<String, AttributeValue> attributeMap = input.m();
        return new DcsResponse(
                UUID.fromString(attributeMap.get("correlationId").s()),
                UUID.fromString(attributeMap.get("requestId").s()),
                attributeMap.get("error").bool(),
                attributeMap.get("valid").bool(),
                attributeMap.get("errorMessage").ss().toArray(new String[0])
        );
    }

    @Override
    public EnhancedType<DcsResponse> type() {
        return EnhancedType.of(DcsResponse.class);
    }

    @Override
    public AttributeValueType attributeValueType() {
        return AttributeValueType.M;
    }
}
