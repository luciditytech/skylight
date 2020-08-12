package services;

import java.sql.Timestamp;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.apache.commons.lang3.tuple.Pair;
import org.apache.http.client.utils.URIBuilder;
import org.bouncycastle.jcajce.provider.digest.Keccak;
import org.bouncycastle.jcajce.provider.digest.Keccak.Digest256;
import org.bouncycastle.util.encoders.Hex;

public class Digester {
  private static List<String> FIELDS = Arrays.asList(
    "nonce",
    "timestamp"
  );

  static {
    Collections.sort(FIELDS);
  }

  public static String call(Map<String, Optional<String>> map) {
    Digest256 digester = new Keccak.Digest256();
 
    Iterator<String> iterator = FIELDS.iterator();

    while (iterator.hasNext()) {
      String key = iterator.next();
      String value = map.get(key).orElse("");
      digester.update(value.getBytes());
    }

    byte[] output = digester.digest();
    // String digest = new String(Hex.encode(output));
    String digest = Base64.getEncoder().encodeToString(output);

    return digest;
  }
}
