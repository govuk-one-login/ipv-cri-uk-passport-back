package uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.UtilitiesFromIpvRepo;

public class PassportAPIGlobals {

    public String redirectURI =
            "https://dev-danw-di-ipv-core-front.london.cloudapps.digital/credential-issuer/callback?id=ukPassport";
    public String passportPostUrl =
            "https://e7jswiyhje.execute-api.eu-west-2.amazonaws.com/dev/passport?redirect_uri=https://dev-danw-di-ipv-core-front.london.cloudapps.digital/credential-issuer/callback?id=ukPassport&client_id=ipv-core&response_type=code&scope=openid";
    public String tokenPostUrl = "https://e7jswiyhje.execute-api.eu-west-2.amazonaws.com/dev/token";
    public String credentialGetUrl =
            "https://e7jswiyhje.execute-api.eu-west-2.amazonaws.com/dev/credential";
    public String clientId = "ipv-core";
    public String redirect_uri =
            "https://dev-danw-di-ipv-core-front.london.cloudapps.digital/credential-issuer/callback?id=ukPassport";
    public String grant_type = "authorization_code";
    public String client_id = "ipv-core-stub";
}
