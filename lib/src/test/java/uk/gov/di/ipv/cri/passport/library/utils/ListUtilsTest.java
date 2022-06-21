package uk.gov.di.ipv.cri.passport.library.utils;

import org.junit.jupiter.api.Test;
import uk.gov.di.ipv.cri.passport.library.util.ListUtil;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

class ListUtilsTest {

    @Test
    void shouldReturnItemFromList() {
        List<String> testList = Collections.singletonList("test");

        String result = ListUtil.getOneItemOrThrowError(testList);

        assertEquals("test", result);
    }

    @Test
    void shouldThrowExceptionIfListIsNull() {
        try {
            ListUtil.getOneItemOrThrowError(null);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException e) {
            assertEquals("No items found", e.getMessage());
        }
    }

    @Test
    void shouldThrowExceptionIfListIsEmpty() {
        try {
            ListUtil.getOneItemOrThrowError(Collections.emptyList());
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException e) {
            assertEquals("No items found", e.getMessage());
        }
    }

    @Test
    void shouldThrowExceptionIfMoreThanOneItemInList() {
        try {
            List<String> testList = Arrays.asList("test", "test2", "test3");
            ListUtil.getOneItemOrThrowError(testList);

            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException e) {
            assertEquals("More than one item found", e.getMessage());
        }
    }
}
