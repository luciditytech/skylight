package services;

import java.io.IOException;
import java.io.StringReader;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Base64;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.util.encoders.Hex;

public class Verifier {
  static {
    Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
  }

  public static boolean call(String digest, String signature, String publicKeyContent) throws IOException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
    PEMParser parser = new PEMParser(new StringReader(publicKeyContent));

    SubjectPublicKeyInfo keyInfo = (SubjectPublicKeyInfo) parser.readObject();

    parser.close();

    PublicKey publicKey = new JcaPEMKeyConverter().setProvider("BC").getPublicKey(keyInfo);

    byte[] decoded = Base64.getDecoder().decode(signature);
    // byte[] decoded = Hex.decode(signature);

    Signature signer = Signature.getInstance("ECDSA", "BC");
    signer.initVerify(publicKey);
    signer.update(digest.getBytes());

    boolean valid = signer.verify(decoded);

    return valid;
  }
}
