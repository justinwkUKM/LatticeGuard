"""
LatticeGuard - Post-Quantum Cryptography Assessment Tool
Copyright (c) 2026 Waqas Khalid Obeidy
"""

"""
Performance Regression Simulator
Estimates the latency and bandwidth impact of transitioning from traditional
cryptography to Post-Quantum Cryptography (PQC).
"""

from typing import Dict, Any, List

# PQC Overhead Models (Normalized against RSA-2048)
# Key size, Signature size, and Compute cycles comparison
PQC_OVERHEAD = {
    "RSA-2048": {"key_size": 256, "sig_size": 256, "compute_factor": 1.0},
    "RSA-4096": {"key_size": 512, "sig_size": 512, "compute_factor": 4.0},
    "ECDSA-P256": {"key_size": 64, "sig_size": 64, "compute_factor": 0.5},
    "ML-KEM-768": {"key_size": 1184, "sig_size": 1088, "compute_factor": 2.5}, # Kyber
    "ML-DSA-65":  {"key_size": 1952, "sig_size": 3309, "compute_factor": 5.0}, # Dilithium
    "SLH-DSA-128s": {"key_size": 32, "sig_size": 7856, "compute_factor": 150.0} # Sphincs+ (slow)
}

class PerformanceSimulator:
    def __init__(self, baseline_rtt_ms: float = 50.0, bandwidth_mbps: float = 100.0):
        self.baseline_rtt = baseline_rtt_ms
        self.bandwidth = bandwidth_mbps # in Mbps

    def estimate_impact(self, current_algo: str, target_algo: str, packet_count: int = 1) -> Dict[str, Any]:
        """
        Estimates the regression impact when switching from current to target algorithm.
        """
        curr = PQC_OVERHEAD.get(current_algo.upper(), PQC_OVERHEAD["RSA-2048"])
        target = PQC_OVERHEAD.get(target_algo.upper(), PQC_OVERHEAD["ML-KEM-768"])

        # Size Delta (in bytes)
        size_delta = (target["key_size"] + target["sig_size"]) - (curr["key_size"] + curr["sig_size"])
        
        # Transmission Delay Impact (Simplified: Size / Bandwidth)
        # 100 Mbps = 100,000,000 bps = 12,500,000 bytes/sec = 12.5 bytes/ms
        bytes_per_ms = (self.bandwidth * 1024 * 1024 / 8) / 1000
        extra_latency_ms = (size_delta / bytes_per_ms) * packet_count
        
        # Compute Impact
        compute_impact = target["compute_factor"] / curr["compute_factor"]
        
        return {
            "current_algorithm": current_algo,
            "target_algorithm": target_algo,
            "extra_data_bytes": size_delta,
            "latency_increase_ms": round(extra_latency_ms, 3),
            "estimated_pqc_handshake_ms": round(self.baseline_rtt + extra_latency_ms, 2),
            "compute_overhead_multiplier": round(compute_impact, 1),
            "risk_of_mtu_fragmentation": "High" if target["sig_size"] > 1500 else "Low"
        }

    def simulate_batch(self, algorithms: List[str]) -> List[Dict[str, Any]]:
        results = []
        for algo in algorithms:
            # Default target for KEM is ML-KEM-768
            target = "ML-KEM-768" if "RSA" in algo.upper() or "DH" in algo.upper() else "ML-DSA-65"
            results.append(self.estimate_impact(algo, target))
        return results
