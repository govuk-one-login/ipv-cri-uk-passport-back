package uk.gov.di.ipv.cri.passport.library.persistence.item.converter;

import uk.gov.di.ipv.cri.passport.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.cri.passport.library.domain.PassportAttributes;

@ExcludeFromGeneratedCoverageReport
public class PassportAttributesConverter extends JacksonAttributeConverter<PassportAttributes> {
   public PassportAttributesConverter() {
       super(PassportAttributes.class);
   }
}
