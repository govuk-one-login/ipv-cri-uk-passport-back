package utilsFromIpvRepo;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Random;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

public class UiSupport {

    private UiSupport() {}

    static Logger logger = LoggerFactory.getLogger(UiSupport.class);

    public static void mySleep(int val) {
        try {
            TimeUnit.SECONDS.sleep(val);
        } catch (InterruptedException e) {
            logger.warn("Thread Interrupted");
            Thread.currentThread().interrupt();
        }
    }

    public static String generateRandomAlphanumeric(int length) throws NoSuchAlgorithmException {
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" + "abcdefghijklmnopqrstuvwxyz" + "0123456789";
        Random random = SecureRandom.getInstanceStrong();
        return random.ints(length, 0, chars.length())
                .mapToObj(i -> "" + chars.charAt(i))
                .collect(Collectors.joining());
    }
}
