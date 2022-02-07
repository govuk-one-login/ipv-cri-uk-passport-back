package uk.gov.di.ipv.cri.passport.library.persistence.item.converter;

import uk.gov.di.ipv.cri.passport.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.cri.passport.library.domain.DcsResponse;

@ExcludeFromGeneratedCoverageReport
public class DcsResponseConverter extends JacksonAttributeConverter<DcsResponse> {
    public DcsResponseConverter() {
        super(DcsResponse.class);
    }
}
