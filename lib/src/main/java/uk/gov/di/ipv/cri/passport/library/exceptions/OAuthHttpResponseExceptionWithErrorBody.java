package uk.gov.di.ipv.cri.passport.library.exceptions;

import uk.gov.di.ipv.cri.passport.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.cri.passport.library.error.ErrorResponse;

@ExcludeFromGeneratedCoverageReport
public class OAuthHttpResponseExceptionWithErrorBody extends HttpResponseExceptionWithErrorBody {
    public OAuthHttpResponseExceptionWithErrorBody(int statusCode, ErrorResponse errorResponse) {
        super(statusCode, errorResponse);
    }
}
