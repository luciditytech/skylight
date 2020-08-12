package services;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.Files;

public class SignerTest {
  private static Log logger = LogFactory.getLog(SignerTest.class);

  @Test
  public void testCall() {
    assertDoesNotThrow(() -> {
      String privateKeyPath = "./samples/private_key.pem";

      String privateKey = new String(Files.readAllBytes(Paths.get(privateKeyPath)));
      logger.info("private key = \n" + privateKey);

      String digest = "Vgl+PyGzh5v6SAYmbNERMbhe3WEeIdiz/eaZeOhSXyw=";
      logger.info("digest = " + digest);

      String signature = Signer.call(digest, privateKey);
      logger.info("signature = " + signature);
 
      String publicKeyPath = "./samples/public_key.pem";
      String publicKeyContent = new String(Files.readAllBytes(Paths.get(publicKeyPath)));
      logger.info("public key = \n" + publicKeyContent);

      boolean result = Verifier.call(digest, signature, publicKeyContent);
      assertEquals(result, true);
    });
  }
}
