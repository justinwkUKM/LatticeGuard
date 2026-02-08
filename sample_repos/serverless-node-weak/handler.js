const NodeRSA = require('node-rsa');
const CryptoJS = require('crypto-js');

function legacyEncrypt(data) {
    // VULNERABILITY: RSA with legacy keys
    const key = new NodeRSA({ b: 1024 });
    const encrypted = key.encrypt(data, 'base64');

    // VULNERABILITY: Weak MD5 usage
    const hash = CryptoJS.MD5("secret-password");

    return { encrypted, hash: hash.toString() };
}

console.log("Legacy Node.js Worker Initialized");
