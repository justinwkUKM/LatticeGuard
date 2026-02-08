#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <iostream>

void process_payment() {
    // VULNERABILITY: Deprecated and Shor-vulnerable RSA key generation
    RSA *rsa = RSA_generate_key(1024, RSA_F4, NULL, NULL);
    
    if (rsa == NULL) {
        std::cerr << "Key generation failed" << std::endl;
        return;
    }

    std::cout << "Payment processed using RSA-1024" << std::endl;
    RSA_free(rsa);
}

int main() {
    process_payment();
    return 0;
}
