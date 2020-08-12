package services;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class DigesterTest {
  private static Log logger = LogFactory.getLog(DigesterTest.class);

  @Test
  public void testCall() {
    Map<String, Optional<String>> map = Stream.of(new String[][] {
      { "nonce", "046b6c7f-0b8a-43b9-b35d-6489e6daee91" }, 
      { "timestamp", "2020-06-22T21:51:10Z" }, 
    }).collect(Collectors.toMap(data -> data[0], data -> Optional.of(data[1])));

    String digest = Digester.call(map);
    logger.info("digest = " + digest);
    Assertions.assertEquals("Vgl+PyGzh5v6SAYmbNERMbhe3WEeIdiz/eaZeOhSXyw=", digest);
  }
}
