from lxml import etree
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import base64

class ISO20022Signer:
    """
    Signs and verifies ISO 20022 payment messages.
    Used for interbank settlement (RENTAS, DuitNow).
    """
    
    def __init__(self):
        # VULNERABILITY: RSA-2048 is Shor-vulnerable
        # Bank Negara requires digital signatures on all RTGS messages
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048  # Quantum-vulnerable key size
        )
        self.public_key = self.private_key.public_key()
    
    def sign_payment_message(self, xml_content: bytes) -> bytes:
        """
        Sign ISO 20022 pain.001 message for RENTAS submission.
        VULNERABILITY: Using RSA-SHA256 which is Shor-vulnerable.
        """
        signature = self.private_key.sign(
            xml_content,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return base64.b64encode(signature)
    
    def verify_settlement_response(self, xml_content: bytes, signature: bytes) -> bool:
        """
        Verify signature on pacs.002 settlement confirmation.
        """
        try:
            self.public_key.verify(
                base64.b64decode(signature),
                xml_content,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False


# Example usage for RENTAS settlement
if __name__ == "__main__":
    signer = ISO20022Signer()
    payment_xml = b"<pain.001>...</pain.001>"
    sig = signer.sign_payment_message(payment_xml)
    print(f"Payment message signed: {sig[:50]}...")
