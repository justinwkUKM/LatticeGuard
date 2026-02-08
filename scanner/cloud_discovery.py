import os
from typing import List, Dict, Optional
from schemas.models import InventoryItem

class CloudDiscoveryManager:
    """
    Discovers cryptographic assets across multiple cloud providers.
    Supports AWS, GCP, and Azure.
    """
    
    def __init__(self, provider: str, region: Optional[str] = None):
        self.provider = provider.lower()
        self.region = region or os.environ.get('AWS_DEFAULT_REGION', 'us-east-1')
        self.findings: List[InventoryItem] = []

    def discover(self) -> List[InventoryItem]:
        """Runs discovery for the specified provider."""
        if self.provider == 'aws':
            return self._discover_aws()
        elif self.provider == 'gcp':
            return self._discover_gcp()
        elif self.provider == 'azure':
            return self._discover_azure()
        elif self.provider == 'mock':
            return self._discover_mock()
        else:
            raise ValueError(f"Unsupported cloud provider: {self.provider}")

    def _discover_aws(self) -> List[InventoryItem]:
        """Discovers AWS KMS keys and ACM certificates."""
        try:
            import boto3
            kms = boto3.client('kms', region_name=self.region)
            acm = boto3.client('acm', region_name=self.region)
            
            # Discover KMS Keys
            keys = kms.list_keys().get('Keys', [])
            for k in keys:
                key_id = k['KeyId']
                desc = kms.describe_key(KeyId=key_id)['KeyMetadata']
                spec = desc.get('KeySpec', 'Unknown')
                
                self.findings.append(InventoryItem(
                    id=f"aws:kms:{self.region}:{key_id}",
                    path=f"aws:kms:{self.region}",
                    line=0,
                    name=f"AWS KMS Key ({key_id})",
                    category="kms",
                    algorithm=spec,
                    is_pqc_vulnerable=spec in ["RSA_2048", "RSA_3072", "RSA_4096", "ECC_NIST_P256"],
                    description=f"AWS KMS Key with spec {spec}. Managed by AWS.",
                    cloud_provider="aws",
                    source_type="cloud"
                ))
                
            # Discover ACM Certificates
            certs = acm.list_certificates().get('CertificateSummaryList', [])
            for c in certs:
                arn = c['CertificateArn']
                details = acm.describe_certificate(CertificateArn=arn)['Certificate']
                algo = details.get('KeyAlgorithm', 'Unknown')
                
                self.findings.append(InventoryItem(
                    id=f"aws:acm:{self.region}:{arn.split('/')[-1]}",
                    path=f"aws:acm:{self.region}",
                    line=0,
                    name=f"ACM Certificate ({details.get('DomainName')})",
                    category="certificate",
                    algorithm=algo,
                    is_pqc_vulnerable=True,
                    description=f"ACM Certificate for {details.get('DomainName')}. Key algorithm: {algo}.",
                    cloud_provider="aws",
                    source_type="cloud"
                ))
        except ImportError:
            print("Warning: boto3 not installed. Skipping AWS discovery.")
        except Exception as e:
            print(f"Error during AWS discovery: {e}")
            
        return self.findings

    def _discover_gcp(self) -> List[InventoryItem]:
        """Discovers GCP Cloud KMS keys."""
        try:
            from google.cloud import kms_v1
            
            project_id = os.environ.get("GCP_PROJECT_ID") or os.environ.get("GOOGLE_CLOUD_PROJECT")
            if not project_id:
                print("Warning: GCP_PROJECT_ID not set. Skipping GCP discovery.")
                return []
            
            client = kms_v1.KeyManagementServiceClient()
            # GCP region mapping (us-east-1 -> us-east1)
            gcp_region = self.region.replace("us-east-1", "us-east1").replace("-", "") if "-" in self.region else self.region
            # Simpler heuristic for now: us-east-1 -> us-east1
            if "-" in self.region and not self.region[-1].isdigit():
                 # Handle cases like us-east -> us-east1? No, usually it's us-east1.
                 pass
            
            # Using global or regional parent
            parent = f"projects/{project_id}/locations/{self.region}"
            try:
                key_rings = client.list_key_rings(parent=parent)
                for key_ring in key_rings:
                    keys = client.list_crypto_keys(parent=key_ring.name)
                    for key in keys:
                        # PQC Vulnerability check based on purposes/algorithms
                        # In a real scenario, we'd fetch the primary version's algorithm
                        name_parts = key.name.split('/')
                        key_id = name_parts[-1]
                        
                        self.findings.append(InventoryItem(
                            id=f"gcp:kms:{key.name}",
                            path=key.name,
                            line=0,
                            name=f"GCP KMS Key ({key_id})",
                            category="kms",
                            algorithm="UNKNOWN (GCP)",
                            is_pqc_vulnerable=True, # Default to true for KMS keys unless verified PQC
                            description=f"GCP Cloud KMS Key in project {project_id}.",
                            cloud_provider="gcp",
                            source_type="cloud"
                        ))
            except Exception as e:
                 print(f"GCP Region {self.region} access failed: {e}")

        except ImportError:
            print("Warning: google-cloud-kms not installed. Skipping GCP discovery.")
        except Exception as e:
            print(f"Error during GCP discovery: {e}")
            
        return self.findings

    def _discover_azure(self) -> List[InventoryItem]:
        """Discovers Azure Key Vault keys."""
        try:
            from azure.keyvault.keys import KeyClient
            from azure.identity import DefaultAzureCredential
            
            vault_url = os.environ.get("AZURE_VAULT_URL")
            if not vault_url:
                print("Warning: AZURE_VAULT_URL not set. Skipping Azure discovery.")
                return []
                
            credential = DefaultAzureCredential()
            client = KeyClient(vault_url=vault_url, credential=credential)
            
            keys = client.list_properties_of_keys()
            for key_prop in keys:
                # KeyProperties has name, id, etc.
                self.findings.append(InventoryItem(
                    id=f"azure:kv:{key_prop.id}",
                    path=key_prop.id,
                    line=0,
                    name=f"Azure Key Vault Key ({key_prop.name})",
                    category="kms",
                    algorithm="ASYMMETRIC", # Default for KV keys
                    is_pqc_vulnerable=True,
                    description=f"Azure Key Vault key. Vault: {vault_url}",
                    cloud_provider="azure",
                    source_type="cloud"
                ))
        except ImportError:
            print("Warning: azure-keyvault-keys not installed. Skipping Azure discovery.")
        except Exception as e:
            print(f"Error during Azure discovery: {e}")
            
        return self.findings

    def _discover_mock(self) -> List[InventoryItem]:
        """Returns mock cloud findings for demonstration."""
        return [
            InventoryItem(
                id="mock:aws:kms:us-east-1:key-12345",
                path="aws:kms:us-east-1",
                line=0,
                name="Mock AWS KMS Key (RSA_2048)",
                category="kms",
                algorithm="RSA_2048",
                is_pqc_vulnerable=True,
                description="Mock finding for demonstration purposes.",
                cloud_provider="aws",
                source_type="cloud"
            ),
            InventoryItem(
                id="mock:gcp:kms:us-central1:key-67890",
                path="gcp:kms:us-central1",
                line=0,
                name="Mock GCP Cloud KMS Key (P-256)",
                category="kms",
                algorithm="EC_P256",
                is_pqc_vulnerable=True,
                description="Mock finding for demonstration purposes.",
                cloud_provider="gcp",
                source_type="cloud"
            )
        ]
