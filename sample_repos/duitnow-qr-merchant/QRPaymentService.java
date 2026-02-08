import java.security.*;
import java.util.Base64;

/**
 * DuitNow QR Merchant Payment System
 * Generates and signs QR payloads for merchant transactions.
 */
public class QRPaymentService {
    
    private PrivateKey privateKey;
    private PublicKey publicKey;
    
    public QRPaymentService() throws NoSuchAlgorithmException {
        // VULNERABILITY: ECDSA is Shor-vulnerable (Quantum Computing Risk)
        // PayNet DuitNow QR codes use ECDSA P-256 for signature validation
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(256); // P-256 curve - vulnerable to Shor's algorithm
        KeyPair pair = keyGen.generateKeyPair();
        this.privateKey = pair.getPrivate();
        this.publicKey = pair.getPublic();
    }
    
    /**
     * Generate signed QR payload for merchant payment
     * Format: EMVCo QR Code Specification for Payment Systems
     */
    public String generateSignedQRPayload(String merchantId, double amount) throws Exception {
        String payload = String.format(
            "00020101021126580011my.com.paynet0108%s520400005303458540%.2f5802MY6015KUALA LUMPUR",
            merchantId, amount
        );
        
        // VULNERABILITY: SHA256withECDSA - quantum-vulnerable signature
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(privateKey);
        signature.update(payload.getBytes());
        byte[] sig = signature.sign();
        
        return payload + "6304" + Base64.getEncoder().encodeToString(sig);
    }
    
    /**
     * Verify QR payment signature from customer wallet
     */
    public boolean verifyPaymentSignature(String payload, byte[] signature) throws Exception {
        Signature verifier = Signature.getInstance("SHA256withECDSA");
        verifier.initVerify(publicKey);
        verifier.update(payload.getBytes());
        return verifier.verify(signature);
    }
}
