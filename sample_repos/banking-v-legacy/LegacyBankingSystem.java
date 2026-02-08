import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

public class LegacyBankingSystem {
    public void initialize() throws NoSuchAlgorithmException, NoSuchPaddingException {
        // VULNERABILITY: RSA key generation is Shor-vulnerable
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(1024); // Weak key size and vulnerable algorithm
        KeyPair kp = kpg.generateKeyPair();
        
        // VULNERABILITY: Using PQC-vulnerable cipher
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        
        System.out.println("Legacy Banking Crypto Initialized");
    }
}
