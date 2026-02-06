import os
from cryptography.hazmat.primitives.asymmetric import rsa

# 1. Hardcoded Constant (Tainted as CONSTANT)
DEFAULT_BITS = 2048
key1 = rsa.generate_private_key(
    public_exponent=65537,
    key_size=DEFAULT_BITS
)

# 2. Environment Variable (Tainted as ENV_VAR)
dynamic_bits = int(os.getenv("RSA_BITS", 3072))
key2 = rsa.generate_private_key(
    public_exponent=65537,
    key_size=dynamic_bits
)

# 3. Direct Constant
key3 = rsa.generate_private_key(
    public_exponent=65537,
    key_size=4096
)
