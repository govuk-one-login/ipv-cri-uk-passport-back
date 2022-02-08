package uk.gov.di.ipv.cri.passport.library.persistence.item;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import software.amazon.awssdk.enhanced.dynamodb.AttributeConverter;
import software.amazon.awssdk.enhanced.dynamodb.AttributeValueType;
import software.amazon.awssdk.enhanced.dynamodb.EnhancedType;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import uk.gov.di.ipv.cri.passport.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.cri.passport.library.domain.Gpg45Evidence;
import uk.gov.di.ipv.cri.passport.library.domain.PassportGpg45Score;

import java.util.Map;

@ExcludeFromGeneratedCoverageReport
public class PassportGpg45ScoreConverter implements AttributeConverter<PassportGpg45Score> {
    ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public AttributeValue transformFrom(PassportGpg45Score input) {
        Map<String, AttributeValue> attributeValueMap =
                Map.of(
                        "evidence",
                        AttributeValue.builder()
                                .m(
                                        objectMapper.convertValue(
                                                input.getEvidence(),
                                                new TypeReference<
                                                        Map<String, AttributeValue>>() {}))
                                .build());

        return AttributeValue.builder().m(attributeValueMap).build();
    }

    @Override
    public PassportGpg45Score transformTo(AttributeValue input) {
        Map<String, AttributeValue> attributeMap = input.m();

        Map<String, AttributeValue> evidenceMap = attributeMap.get("evidence").m();
        Gpg45Evidence evidence =
                new Gpg45Evidence(
                        Integer.parseInt(evidenceMap.get("strength").s()),
                        Integer.parseInt(evidenceMap.get("validity").s()));

        return new PassportGpg45Score(evidence);
    }

    @Override
    public EnhancedType<PassportGpg45Score> type() {
        return EnhancedType.of(PassportGpg45Score.class);
    }

    @Override
    public AttributeValueType attributeValueType() {
        return AttributeValueType.M;
    }
}
