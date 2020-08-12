package services;

import java.io.IOException;
import java.io.StringReader;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Base64;

import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

public class Signer {
  static {
    Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
  }

  // See: https://github.com/bcgit/bc-java/blob/master/pkix/src/test/java/org/bouncycastle/openssl/test/ParserTest.java
  public static String call(String digest, String secretKey) throws IOException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
    PEMParser parser = new PEMParser(new StringReader(secretKey));

    ASN1ObjectIdentifier curveId = (ASN1ObjectIdentifier) parser.readObject();
    PEMKeyPair pemPair = (PEMKeyPair) parser.readObject();

    parser.close();

    java.security.KeyPair keyPair = new JcaPEMKeyConverter().setProvider("BC").getKeyPair(pemPair);

    Signature signer = Signature.getInstance("ECDSA", "BC");
    signer.initSign(keyPair.getPrivate());
    signer.update(digest.getBytes());

    byte[] signature = signer.sign();
    // String encoded = new String(Hex.encode(signature));
    String encoded = Base64.getEncoder().encodeToString(signature);

    return encoded;
  }
}
