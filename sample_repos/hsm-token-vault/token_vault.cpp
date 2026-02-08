#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/aes.h>
#include <iostream>
#include <vector>
#include <string>

/**
 * HSM Token Vault Simulator
 * Manages encryption keys for tokenized payment credentials.
 * Used for: Credit card tokens, stored-value cards, e-wallet balances.
 */
class TokenVault {
private:
    EVP_PKEY* masterKey;
    unsigned char tokenEncryptionKey[32]; // AES-256 key
    
public:
    TokenVault() {
        // VULNERABILITY: RSA key for key exchange (Shor-vulnerable)
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
        EVP_PKEY_keygen_init(ctx);
        EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);
        EVP_PKEY_keygen(ctx, &masterKey);
        EVP_PKEY_CTX_free(ctx);
        
        // Generate AES key for token encryption (quantum-resistant for symmetric)
        RAND_bytes(tokenEncryptionKey, 32);
    }
    
    ~TokenVault() {
        if (masterKey) EVP_PKEY_free(masterKey);
    }
    
    /**
     * Tokenize a Primary Account Number (PAN)
     * Returns a reversible token for payment processing.
     */
    std::vector<unsigned char> tokenizePAN(const std::string& pan) {
        std::vector<unsigned char> token(pan.length() + 16);
        unsigned char iv[16];
        RAND_bytes(iv, 16);
        
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, tokenEncryptionKey, iv);
        
        int len, ciphertext_len;
        EVP_EncryptUpdate(ctx, token.data(), &len, 
                          reinterpret_cast<const unsigned char*>(pan.c_str()), 
                          pan.length());
        ciphertext_len = len;
        EVP_EncryptFinal_ex(ctx, token.data() + len, &len);
        ciphertext_len += len;
        EVP_CIPHER_CTX_free(ctx);
        
        token.resize(ciphertext_len);
        return token;
    }
    
    /**
     * Wrap the Token Encryption Key (TEK) for secure transport.
     * VULNERABILITY: RSA key wrapping is quantum-vulnerable.
     */
    std::vector<unsigned char> wrapKeyForTransport() {
        std::vector<unsigned char> wrappedKey(256);
        size_t outlen;
        
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(masterKey, NULL);
        EVP_PKEY_encrypt_init(ctx);
        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
        EVP_PKEY_encrypt(ctx, wrappedKey.data(), &outlen, 
                         tokenEncryptionKey, 32);
        EVP_PKEY_CTX_free(ctx);
        
        wrappedKey.resize(outlen);
        return wrappedKey;
    }
};

int main() {
    TokenVault vault;
    auto token = vault.tokenizePAN("4111111111111111");
    std::cout << "PAN tokenized. Token length: " << token.size() << std::endl;
    
    auto wrappedKey = vault.wrapKeyForTransport();
    std::cout << "TEK wrapped for transport. Size: " << wrappedKey.size() << std::endl;
    
    return 0;
}
