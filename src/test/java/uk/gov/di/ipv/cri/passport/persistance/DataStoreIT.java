package uk.gov.di.ipv.cri.passport.persistance;

import org.junit.jupiter.api.Test;
import uk.gov.di.ipv.cri.passport.domain.DcsResponse;
import uk.gov.di.ipv.cri.passport.domain.PassportFormRequest;
import uk.gov.di.ipv.cri.passport.persistence.DataStore;
import uk.gov.di.ipv.cri.passport.persistence.item.PassportCheckDao;

import java.net.URI;
import java.time.LocalDate;
import java.util.UUID;

public class DataStoreIT {

    private static final URI endpoint = URI.create("http://localhost:4567");
    private static final String TEST_TABLE_NAME = "local-dev-dcs-response";
    private static DataStore<PassportCheckDao> dataStore =
            new DataStore<PassportCheckDao>(
    TEST_TABLE_NAME,
    PassportCheckDao.class, DataStore.getClient(endpoint));

    @Test
    public void shouldPutPassportCheckIntoTable() {
        DcsResponse validDcsResponse =
                new DcsResponse(UUID.randomUUID(), UUID.randomUUID(), false, true, new String[] {"No errors here"});
        PassportFormRequest passportFormRequest =
                new PassportFormRequest(
                        "passport_number",
                        "surname",
                        new String[]{"forename"},
                        LocalDate.parse("2000-10-28"),
                        LocalDate.parse("2022-11-29"));
        String resourceId = "my resource id 3";
        PassportCheckDao passportCheckDao = new PassportCheckDao(resourceId, passportFormRequest, validDcsResponse);
        dataStore.create(passportCheckDao);
        dataStore.getItem("my resource id 3");

    }
}
