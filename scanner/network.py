import ssl
import socket
from typing import List, Dict
from schemas.models import InventoryItem

class NetworkScanner:
    def __init__(self, target_host: str, port: int = 443):
        self.target_host = target_host
        self.port = port
        
    def scan(self) -> List[InventoryItem]:
        """
        Performs a TLS handshake and inspects the cipher suite.
        """
        results = []
        try:
            # Create a context that is broad
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.target_host, self.port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.target_host) as ssock:
                    cipher_info = ssock.cipher() # ('name', 'protocol', bits)
                    # version = ssock.version()
                    
                    # Analyze Cipher
                    cipher_name = cipher_info[0]
                    protocol = cipher_info[1]
                    
                    is_vulnerable = True
                    reasoning = f"Uses classical Key Exchange ({cipher_name})"
                    
                    # PQC Analysis
                    if "Kyber" in cipher_name or "Dilithium" in cipher_name:
                         # Check for Hybrid (e.g. X25519Kyber768)
                         if "X25519" in cipher_name or "ECDHE" in cipher_name:
                             is_vulnerable = False
                             reasoning = "Hybrid Key Exchange Detected (Classical + PQC)"
                         else:
                             is_vulnerable = False
                             reasoning = "Pure Quantum-Safe Key Exchange Detected"
                        
                    results.append(InventoryItem(
                        id=f"{self.target_host}:{self.port}",
                        path=f"https://{self.target_host}:{self.port}",
                        line=0,
                        name=f"TLS Endpoint ({self.target_host})",
                        category="network",
                        algorithm=cipher_name,
                        key_size=cipher_info[2],
                        is_pqc_vulnerable=is_vulnerable,
                        description=reasoning
                    ))
                    
        except Exception as e:
            print(f"Network Scan Error: {e}")
            
        return results
