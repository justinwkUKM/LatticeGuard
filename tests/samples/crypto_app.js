const crypto = require('crypto');

// 1. Insecure Key Generation (RSA)
// This should be caught by JSScanner
function generateOldKey() {
    return crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
    });
}

// 2. Weak Cipher Usage
function encryptData(data, key) {
    const cipher = crypto.createCipheriv('des', key, null);
    return cipher.update(data, 'utf8', 'hex') + cipher.final('hex');
}

// 3. WebCrypto API
async function webCryptoGen() {
    const key = await window.crypto.subtle.generateKey(
        { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
        true,
        ["sign", "verify"]
    );
}

// 4. Static Key Constant (fake test key for scanner validation)
const API_SECRET = "test_fake_key_for_scanner_validation_only";
