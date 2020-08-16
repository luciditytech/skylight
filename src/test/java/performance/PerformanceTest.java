package performance;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.config.TinkConfig;
import com.google.crypto.tink.signature.PublicKeySignFactory;
import com.google.crypto.tink.signature.PublicKeyVerifyFactory;
import com.google.crypto.tink.signature.SignatureKeyTemplates;

import services.Digester;
import services.Signer;

public class PerformanceTest {
  private static Log logger = LogFactory.getLog(PerformanceTest.class);

  @Test
  public void testPerformance() throws GeneralSecurityException {
    TinkConfig.register();

    String digest = "Vgl+PyGzh5v6SAYmbNERMbhe3WEeIdiz/eaZeOhSXyw=";

    KeysetHandle privateKeysetHandle = KeysetHandle.generateNew(SignatureKeyTemplates.ED25519WithRawOutput);
    PublicKeySign signer = PublicKeySignFactory.getPrimitive(privateKeysetHandle);

    long start = System.nanoTime();

    byte[] signature = signer.sign(digest.getBytes(StandardCharsets.UTF_8));

    long finish = System.nanoTime();
    long timeElapsed = finish - start;

    logger.info(String.format("time taken to sign: %s (ms)", timeElapsed / 1000000.0));

    String encoded = new String(Base64.getEncoder().encode(signature), StandardCharsets.UTF_8);
    logger.info(String.format("encoded signature: %s", encoded));

    // VERIFY JUST CREATED SIGNATURE USING PUBLIC KEY
    KeysetHandle publicKeysetHandle = privateKeysetHandle.getPublicKeysetHandle();
    PublicKeyVerify verifier = PublicKeyVerifyFactory.getPrimitive(publicKeysetHandle);

    start = System.nanoTime();

    verifier.verify(signature, digest.getBytes(StandardCharsets.UTF_8));

    finish = System.nanoTime();
    timeElapsed = finish - start;
    logger.info(String.format("time taken to verify: %s (ms)", timeElapsed / 1000000.0));
  }
}
