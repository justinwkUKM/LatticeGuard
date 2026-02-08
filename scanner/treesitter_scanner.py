"""
Tree-sitter based scanner for Java and C++ cryptographic pattern detection.
Uses AST analysis for accurate identification of PQC-vulnerable crypto usage.
"""
import tree_sitter_java as tsjava
import tree_sitter_cpp as tscpp
import tree_sitter_rust as tsrust
import tree_sitter_c_sharp as tscsharp
from tree_sitter import Language, Parser
from pathlib import Path
from typing import List, Optional, Set
from schemas.models import Suspect

# Initialize languages
JAVA_LANGUAGE = Language(tsjava.language())
CPP_LANGUAGE = Language(tscpp.language())
RUST_LANGUAGE = Language(tsrust.language())
CSHARP_LANGUAGE = Language(tscsharp.language())


class TreeSitterScanner:
    """
    AST-based scanner for Java, C++, Rust, and C# files using tree-sitter.
    Detects cryptographic API calls that are vulnerable to quantum attacks.
    """
    
    # Java crypto patterns: class.method -> {vulnerable_args, risk, desc}
    JAVA_CRYPTO_PATTERNS = {
        "Cipher.getInstance": {
            "vulnerable_args": {"rsa", "des", "3des", "blowfish", "rc2", "rc4", "desede"},
            "risk": "high",
            "desc": "Cipher instantiation with PQC-vulnerable algorithm"
        },
        "KeyPairGenerator.getInstance": {
            "vulnerable_args": {"rsa", "dsa", "ec", "diffiehellman", "dh"},
            "risk": "high",
            "desc": "Key pair generation with Shor-vulnerable algorithm"
        },
        "KeyGenerator.getInstance": {
            "vulnerable_args": {"des", "desede", "blowfish", "rc2", "rc4"},
            "risk": "medium",
            "desc": "Symmetric key generation with weak algorithm"
        },
        "MessageDigest.getInstance": {
            "vulnerable_args": {"md5", "sha-1", "sha1"},
            "risk": "medium",
            "desc": "Weak hash algorithm usage"
        },
        "Signature.getInstance": {
            "vulnerable_args": {"sha1withrsa", "md5withrsa", "sha256withrsa", "sha384withrsa", 
                              "sha512withrsa", "sha1withdsa", "sha256withdsa", "sha1withecdsa",
                              "sha256withecdsa", "sha384withecdsa", "sha512withecdsa"},
            "risk": "high",
            "desc": "Digital signature with PQC-vulnerable algorithm"
        },
        "KeyFactory.getInstance": {
            "vulnerable_args": {"rsa", "dsa", "ec", "diffiehellman"},
            "risk": "high",
            "desc": "Key factory with Shor-vulnerable algorithm"
        },
        "KeyAgreement.getInstance": {
            "vulnerable_args": {"diffiehellman", "dh", "ecdh"},
            "risk": "high",
            "desc": "Key agreement using Shor-vulnerable algorithm"
        },
    }
    
    # C++ crypto function names to detect
    CPP_CRYPTO_FUNCTIONS = {
        # OpenSSL RSA functions
        "RSA_generate_key": ("high", "OpenSSL RSA key generation (deprecated)"),
        "RSA_generate_key_ex": ("high", "OpenSSL RSA key generation"),
        "RSA_new": ("high", "OpenSSL RSA key object creation"),
        "RSA_public_encrypt": ("high", "OpenSSL RSA encryption"),
        "RSA_private_decrypt": ("high", "OpenSSL RSA decryption"),
        "RSA_sign": ("high", "OpenSSL RSA signing"),
        # OpenSSL EC functions
        "EC_KEY_new": ("high", "OpenSSL EC key creation"),
        "EC_KEY_new_by_curve_name": ("high", "OpenSSL EC key with named curve"),
        "EC_KEY_generate_key": ("high", "OpenSSL EC key generation"),
        "ECDSA_sign": ("high", "OpenSSL ECDSA signing"),
        "ECDH_compute_key": ("high", "OpenSSL ECDH key derivation"),
        # OpenSSL DSA functions
        "DSA_generate_key": ("high", "OpenSSL DSA key generation"),
        "DSA_sign": ("high", "OpenSSL DSA signing"),
        # OpenSSL DH functions
        "DH_generate_key": ("high", "OpenSSL DH key generation"),
        "DH_compute_key": ("high", "OpenSSL DH key derivation"),
        # OpenSSL EVP functions
        "EVP_PKEY_CTX_set_rsa_keygen_bits": ("high", "OpenSSL EVP RSA key size setting"),
        "EVP_PKEY_keygen": ("medium", "OpenSSL EVP key generation"),
        # Weak hash functions
        "MD5_Init": ("medium", "OpenSSL MD5 initialization"),
        "MD5_Update": ("medium", "OpenSSL MD5 update"),
        "MD5_Final": ("medium", "OpenSSL MD5 finalization"),
        "SHA1_Init": ("medium", "OpenSSL SHA-1 initialization"),
        "EVP_md5": ("medium", "OpenSSL EVP MD5 digest"),
        "EVP_sha1": ("medium", "OpenSSL EVP SHA-1 digest"),
        # Crypto++ patterns
        "RSAES_OAEP_SHA_Encryptor": ("high", "Crypto++ RSA encryption"),
        "RSAES_OAEP_SHA_Decryptor": ("high", "Crypto++ RSA decryption"),
        "RSASSA_PKCS1v15_SHA_Signer": ("high", "Crypto++ RSA signing"),
        # Botan patterns
        "RSA_PrivateKey": ("high", "Botan RSA private key"),
        "ECDSA_PrivateKey": ("high", "Botan ECDSA private key"),
        "DH_PrivateKey": ("high", "Botan DH private key"),
    }

    # Rust crypto patterns
    RUST_CRYPTO_PATTERNS = {
        "Rsa::generate": ("high", "Rust 'rsa' crate key generation"),
        "RSA_PKCS1_2048_8192_SHA256": ("high", "Rust 'ring' RSA signing (Shor vulnerable)"),
        "ECDH_P256": ("high", "Rust 'ring' ECDH (Shor vulnerable)"),
        "Keypair::generate": ("high", "Rust 'ed25519-dalek' key generation"),
        "Md5::new": ("medium", "Rust weak hash usage (MD5)"),
        "Sha1::new": ("medium", "Rust weak hash usage (SHA-1)"),
    }

    # C# crypto patterns
    CSHARP_CRYPTO_PATTERNS = {
        "RSA.Create": ("high", ".NET RSA instantiation"),
        "ECDsa.Create": ("high", ".NET ECDSA instantiation"),
        "SHA1.Create": ("medium", ".NET SHA-1 instantiation"),
        "MD5.Create": ("medium", ".NET MD5 instantiation"),
        "DSACryptoServiceProvider": ("high", ".NET Legacy DSA provider"),
        "RSACryptoServiceProvider": ("high", ".NET Legacy RSA provider"),
    }
    
    def __init__(self):
        self.java_parser = Parser(JAVA_LANGUAGE)
        self.cpp_parser = Parser(CPP_LANGUAGE)
        self.rust_parser = Parser(RUST_LANGUAGE)
        self.csharp_parser = Parser(CSHARP_LANGUAGE)
        self.suspects: List[Suspect] = []
    
    def scan_file(self, file_path: Path) -> List[Suspect]:
        """Scan a single file using tree-sitter AST analysis."""
        self.suspects = []
        file_path = Path(file_path)
        
        if not file_path.exists():
            return self.suspects
        
        suffix = file_path.suffix.lower()
        
        try:
            content = file_path.read_bytes()
            text = content.decode('utf-8', errors='ignore')
            
            if suffix == ".java":
                tree = self.java_parser.parse(content)
                self._walk_java_tree(file_path, tree.root_node, text)
            elif suffix in [".cpp", ".cc", ".cxx", ".c++", ".hpp", ".hxx", ".h"]:
                tree = self.cpp_parser.parse(content)
                self._walk_cpp_tree(file_path, tree.root_node, text)
            elif suffix == ".rs":
                tree = self.rust_parser.parse(content)
                self._walk_rust_tree(file_path, tree.root_node, text)
            elif suffix == ".cs":
                tree = self.csharp_parser.parse(content)
                self._walk_cs_tree(file_path, tree.root_node, text)
                
        except Exception as e:
            # Silently handle errors to match existing scanner behavior
            pass
        
        return self.suspects
    
    def _walk_java_tree(self, file_path: Path, node, text: str):
        """Walk Java AST looking for method invocations."""
        if node.type == "method_invocation":
            self._analyze_java_method_call(file_path, node, text)
        
        for child in node.children:
            self._walk_java_tree(file_path, child, text)
    
    def _analyze_java_method_call(self, file_path: Path, node, text: str):
        """Analyze a Java method invocation node for crypto patterns."""
        obj_text = ""
        method_text = ""
        args_text = ""
        
        for child in node.children:
            if child.type == "identifier":
                # This is the method name
                method_text = text[child.start_byte:child.end_byte]
            elif child.type == "argument_list":
                args_text = text[child.start_byte:child.end_byte]
            elif child.type in ["identifier", "field_access"]:
                # Object before the dot
                if not method_text:  # Not yet assigned = this is the object
                    obj_text = text[child.start_byte:child.end_byte]
        
        # Also check for pattern: object.method where object could be child[0]
        if not obj_text and len(node.children) > 0:
            first_child = node.children[0]
            if first_child.type == "identifier":
                obj_text = text[first_child.start_byte:first_child.end_byte]
        
        full_call = f"{obj_text}.{method_text}"
        
        # Check against patterns
        for pattern, info in self.JAVA_CRYPTO_PATTERNS.items():
            if pattern == full_call:
                # Check if arguments contain vulnerable algorithms
                vuln_found = None
                args_lower = args_text.lower()
                for vuln_arg in info.get("vulnerable_args", set()):
                    if vuln_arg in args_lower:
                        vuln_found = vuln_arg.upper()
                        break
                
                if vuln_found or not info.get("vulnerable_args"):
                    line_num = node.start_point[0] + 1
                    snippet = text[node.start_byte:node.end_byte]
                    
                    self.suspects.append(Suspect(
                        path=str(file_path),
                        line=line_num,
                        content_snippet=snippet[:100] + ("..." if len(snippet) > 100 else ""),
                        type="code",
                        pattern_matched=f"Java_{pattern.replace('.', '_')}" + (f"_{vuln_found}" if vuln_found else ""),
                        confidence="high" if info["risk"] == "high" else "medium"
                    ))
    
    def _walk_cpp_tree(self, file_path: Path, node, text: str):
        """Walk C++ AST looking for function calls."""
        if node.type == "call_expression":
            self._analyze_cpp_call(file_path, node, text)
        
        for child in node.children:
            self._walk_cpp_tree(file_path, child, text)
    
    def _analyze_cpp_call(self, file_path: Path, node, text: str):
        """Analyze a C++ call expression for crypto patterns."""
        func_text = ""
        
        # Get the function name
        for child in node.children:
            if child.type in ["identifier", "field_expression", "qualified_identifier", "template_function"]:
                func_text = text[child.start_byte:child.end_byte]
                break
        
        # Extract just the function name (handle namespace::func patterns)
        func_name = func_text.split("::")[-1] if "::" in func_text else func_text
        
        # Check against patterns
        if func_name in self.CPP_CRYPTO_FUNCTIONS:
            risk, desc = self.CPP_CRYPTO_FUNCTIONS[func_name]
            line_num = node.start_point[0] + 1
            snippet = text[node.start_byte:node.end_byte]
            
            self.suspects.append(Suspect(
                path=str(file_path),
                line=line_num,
                content_snippet=snippet[:100] + ("..." if len(snippet) > 100 else ""),
                type="code",
                pattern_matched=f"CPP_{func_name}",
                confidence="high" if risk == "high" else "medium"
            ))

    def _walk_rust_tree(self, file_path: Path, node, text: str):
        """Walk Rust AST looking for function calls."""
        if node.type == "call_expression":
            self._analyze_rust_call(file_path, node, text)
        
        for child in node.children:
            self._walk_rust_tree(file_path, child, text)

    def _analyze_rust_call(self, file_path: Path, node, text: str):
        """Analyze a Rust call expression for crypto patterns."""
        func_text = ""
        for child in node.children:
            if child.type in ["identifier", "scoped_identifier", "field_expression"]:
                func_text = text[child.start_byte:child.end_byte]
                break
        
        # Handle simple name or qualified name
        func_name = func_text.split("::")[-1] if "::" in func_text else func_text
        
        # Check full text first (e.g. Rsa::generate) then just the name
        match_key = None
        if func_text in self.RUST_CRYPTO_PATTERNS:
            match_key = func_text
        elif func_name in self.RUST_CRYPTO_PATTERNS:
            match_key = func_name
            
        if match_key:
            risk, desc = self.RUST_CRYPTO_PATTERNS[match_key]
            line_num = node.start_point[0] + 1
            snippet = text[node.start_byte:node.end_byte]
            
            self.suspects.append(Suspect(
                path=str(file_path),
                line=line_num,
                content_snippet=snippet[:100] + ("..." if len(snippet) > 100 else ""),
                type="code",
                pattern_matched=f"Rust_{match_key.replace('::', '_')}",
                confidence="high" if risk == "high" else "medium"
            ))

    def _walk_cs_tree(self, file_path: Path, node, text: str):
        """Walk C# AST looking for invocations."""
        if node.type == "invocation_expression" or node.type == "object_creation_expression":
            self._analyze_cs_call(file_path, node, text)
        
        for child in node.children:
            self._walk_cs_tree(file_path, child, text)

    def _analyze_cs_call(self, file_path: Path, node, text: str):
        """Analyze a C# invocation or object creation for crypto patterns."""
        call_text = ""
        if node.type == "invocation_expression":
            # Finding the identifier/expression being called
            for child in node.children:
                if child.type in ["identifier", "member_access_expression"]:
                    call_text = text[child.start_byte:child.end_byte]
                    break
        else: # object_creation_expression
            for child in node.children:
                if child.type == "identifier_name" or child.type == "qualified_name":
                    call_text = text[child.start_byte:child.end_byte]
                    break
        
        # Extract name
        call_name = call_text.split(".")[-1] if "." in call_text else call_text
        
        match_key = None
        if call_text in self.CSHARP_CRYPTO_PATTERNS:
            match_key = call_text
        elif call_name in self.CSHARP_CRYPTO_PATTERNS:
            match_key = call_name
            
        if match_key:
            risk, desc = self.CSHARP_CRYPTO_PATTERNS[match_key]
            line_num = node.start_point[0] + 1
            snippet = text[node.start_byte:node.end_byte]
            
            self.suspects.append(Suspect(
                path=str(file_path),
                line=line_num,
                content_snippet=snippet[:100] + ("..." if len(snippet) > 100 else ""),
                type="code",
                pattern_matched=f"CS_{match_key.replace('.', '_')}",
                confidence="high" if risk == "high" else "medium"
            ))
    
    def get_pattern_info(self, pattern_matched: str) -> dict:
        """Get detailed info about a matched pattern for remediation guidance."""
        if pattern_matched.startswith("Java_"):
            parts = pattern_matched[5:].split("_")
            class_name = parts[0]
            method_name = parts[1] if len(parts) > 1 else ""
            pattern = f"{class_name}.{method_name}"
            return self.JAVA_CRYPTO_PATTERNS.get(pattern, {})
        elif pattern_matched.startswith("CPP_"):
            func_name = pattern_matched[4:]
            if func_name in self.CPP_CRYPTO_FUNCTIONS:
                risk, desc = self.CPP_CRYPTO_FUNCTIONS[func_name]
                return {"risk": risk, "desc": desc}
        elif pattern_matched.startswith("Rust_"):
            key = pattern_matched[5:].replace("_", "::")
            # Try original key or last part
            if key in self.RUST_CRYPTO_PATTERNS:
                risk, desc = self.RUST_CRYPTO_PATTERNS[key]
                return {"risk": risk, "desc": desc}
            # Fallback for keys that didn't have :: but were matched
            last_part = key.split("::")[-1]
            if last_part in self.RUST_CRYPTO_PATTERNS:
                risk, desc = self.RUST_CRYPTO_PATTERNS[last_part]
                return {"risk": risk, "desc": desc}
        elif pattern_matched.startswith("CS_"):
            key = pattern_matched[3:].replace("_", ".")
            if key in self.CSHARP_CRYPTO_PATTERNS:
                risk, desc = self.CSHARP_CRYPTO_PATTERNS[key]
                return {"risk": risk, "desc": desc}
            last_part = key.split(".")[-1]
            if last_part in self.CSHARP_CRYPTO_PATTERNS:
                risk, desc = self.CSHARP_CRYPTO_PATTERNS[last_part]
                return {"risk": risk, "desc": desc}
        return {}
