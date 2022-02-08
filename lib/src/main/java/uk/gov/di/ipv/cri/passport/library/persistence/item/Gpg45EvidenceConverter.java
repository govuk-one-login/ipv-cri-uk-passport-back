package uk.gov.di.ipv.cri.passport.library.persistence.item;

import software.amazon.awssdk.enhanced.dynamodb.AttributeConverter;
import software.amazon.awssdk.enhanced.dynamodb.AttributeValueType;
import software.amazon.awssdk.enhanced.dynamodb.EnhancedType;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import uk.gov.di.ipv.cri.passport.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.cri.passport.library.domain.Gpg45Evidence;

import java.util.Map;

@ExcludeFromGeneratedCoverageReport
public class Gpg45EvidenceConverter implements AttributeConverter<Gpg45Evidence> {
    @Override
    public AttributeValue transformFrom(Gpg45Evidence input) {
        Map<String, AttributeValue> attributeValueMap =
                Map.of(
                        "strength",
                        AttributeValue.builder().s(Integer.toString(input.getStrength())).build(),
                        "validity",
                        AttributeValue.builder().s(Integer.toString(input.getValidity())).build());

        return AttributeValue.builder().m(attributeValueMap).build();
    }

    @Override
    public Gpg45Evidence transformTo(AttributeValue input) {
        Map<String, AttributeValue> attributeMap = input.m();
        return new Gpg45Evidence(
                Integer.parseInt(attributeMap.get("strength").s()),
                Integer.parseInt(attributeMap.get("validity").s()));
    }

    @Override
    public EnhancedType<Gpg45Evidence> type() {
        return EnhancedType.of(Gpg45Evidence.class);
    }

    @Override
    public AttributeValueType attributeValueType() {
        return AttributeValueType.M;
    }
}
