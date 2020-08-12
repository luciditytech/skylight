package services;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.Files;

public class VerifierTest {
  private static Log logger = LogFactory.getLog(SignerTest.class);

  @Test
  public void testCall() {
    assertDoesNotThrow(() -> {
      String publicKeyPath = "./samples/public_key.pem";
      String publicKeyContent = new String(Files.readAllBytes(Paths.get(publicKeyPath)));
      logger.info("public key = \n" + publicKeyContent);

      String digestPath = "./samples/digest.txt";
      String digest = new String(Files.readAllBytes(Paths.get(digestPath)));
      logger.info("digest = " + digest);

      String signaturePath = "./samples/signature.b64";
      String signature = new String(Files.readAllBytes(Paths.get(signaturePath)));
      logger.info("signature = " + signature);

      boolean result = Verifier.call(digest, signature, publicKeyContent);
      assertEquals(true, result);
    });
  }
}
