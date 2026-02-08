import hashlib

def generate_checksum(file_path):
    # LOW RISK: SHA1 used for simple integrity check (non-security context)
    with open(file_path, "rb") as f:
        return hashlib.sha1(f.read()).hexdigest()

def hash_user_password(password):
    # HIGH RISK: MD5 used for security-sensitive password hashing
    # LatticeGuard AST will flag this as Critical PQC/Crypto misuse
    return hashlib.md5(password.encode()).hexdigest()

def legacy_signature(data):
    # HIGH RISK: RSA-SHA1 signature
    import rsa
    (pub, priv) = rsa.newkeys(1024)
    return rsa.sign(data.encode(), priv, 'SHA-1')
