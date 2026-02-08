"""
LatticeGuard - Post-Quantum Cryptography Assessment Tool
Copyright (c) 2026 Waqas Khalid Obeidy
"""

"""
eBPF Runtime Monitor (Python Wrapper)
Monitors real-time cryptographic calls at the Linux kernel level using eBPF hooks.
Requires: BCC (BPF Compiler Collection) and Linux Kernel 4.8+.
"""

import sys
import os
import time
from typing import Optional, Callable

# eBPF C Program to hook into SSL/Crypto libraries
# This hooks into 'SSL_write' and 'SSL_read' to inspect cipher suites in memory.
BPF_PROGRAM = """
#include <uapi/linux/ptrace.h>

BPF_PERF_OUTPUT(events);

struct data_t {
    u32 pid;
    char comm[16];
    char function[32];
};

int hook_ssl_write(struct pt_regs *ctx) {
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    __builtin_memcpy(&data.function, "SSL_write", 10);
    
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

class EBVFRonitor:
    def __init__(self):
        self.bpf = None
        self.enabled = False
        
    def check_capabilities(self) -> bool:
        """Checks if the system supports eBPF/BCC"""
        if sys.platform != "linux":
            return False
        if os.geteuid() != 0:
            return False # Requires root
        try:
            from bcc import BPF
            return True
        except ImportError:
            return False

    def start_monitoring(self, callback: Optional[Callable] = None):
        """Starts the eBPF monitor loop"""
        if not self.check_capabilities():
            print("❌ eBPF Monitoring requires Linux with root privileges and BCC installed.", file=sys.stderr)
            return

        from bcc import BPF
        
        print("🚀 Starting eBPF Runtime Crypto Monitor...", file=sys.stderr)
        self.bpf = BPF(text=BPF_PROGRAM)
        
        # Hook into common libraries (e.g., OpenSSL)
        # Note: Actual path to libssl.so varies by distro
        try:
            self.bpf.attach_uprobe(name="ssl", sym="SSL_write", fn_name="hook_ssl_write")
        except Exception as e:
            print(f"⚠️  Could not attach probe: {e}", file=sys.stderr)
            return

        print("👂 Listening for 'Shadow Crypto' events (Ctrl+C to stop)...", file=sys.stderr)
        
        def print_event(cpu, data, size):
            event = self.bpf["events"].event(data)
            if callback:
                callback(event)
            else:
                print(f"🔔 [eBPF] Event: PID {event.pid} ({event.comm.decode()}) called {event.function.decode()}")

        self.bpf["events"].open_perf_buffer(print_event)
        try:
            while True:
                self.bpf.perf_buffer_poll()
        except KeyboardInterrupt:
            print("\n🛑 Stopping eBPF monitor.", file=sys.stderr)

if __name__ == "__main__":
    monitor = EBVFRonitor()
    monitor.start_monitoring()
