package uk.gov.di.ipv.cri.passport.acceptance_tests.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

public class ClientResponse {
    @JsonProperty private final ClientDetails client;

    @JsonCreator
    public ClientResponse(@JsonProperty(value = "client", required = true) ClientDetails client) {
        this.client = client;
    }

    public ClientDetails getClient() {
        return client;
    }
}
