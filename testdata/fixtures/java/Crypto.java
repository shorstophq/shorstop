// Fixture: Java JCA names, plus near-misses.
import java.security.*;
import javax.crypto.*;

class Crypto {
    void keys() throws Exception {
        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
        rsa.initialize(2048);
        KeyPairGenerator ec = KeyPairGenerator.getInstance("EC");
        KeyPairGenerator ed = KeyPairGenerator.getInstance("Ed25519");
        KeyPairGenerator pq = KeyPairGenerator.getInstance("ML-KEM-768"); // generic-mlkem-name only
        KeyPairGenerator pq2 = KeyPairGenerator.getInstance("ML-DSA");
        Cipher a = Cipher.getInstance("AES");                    // Java default: ECB
        Cipher b = Cipher.getInstance("AES/GCM/NoPadding");
        Cipher c = Cipher.getInstance("AES_256/CBC/PKCS5Padding");
        Cipher d = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        Cipher e = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        MessageDigest md = MessageDigest.getInstance("MD5");
        MessageDigest sha = MessageDigest.getInstance("SHA-1");
        Signature s = Signature.getInstance("SHA1withRSA");     // RSA signature + SHA-1
        Signature s2 = Signature.getInstance("SHA256withECDSA");
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");

        // Near-misses:
        KeyPairGenerator v = KeyPairGenerator.getInstance(algorithm); // not a literal
        MessageDigest ok = MessageDigest.getInstance("SHA-256");
        Cipher ok2 = Cipher.getInstance("AESWrap");
    }
}
