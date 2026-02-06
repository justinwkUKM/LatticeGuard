import ast
from pathlib import Path
from typing import List, Dict
from schemas.models import Suspect

class ASTScanner(ast.NodeVisitor):
    def __init__(self):
        self.suspects = []
        self.current_file = ""
        self.crypto_imports = set()

    def scan_file(self, file_path: Path) -> List[Suspect]:
        self.suspects = []
        self.crypto_imports = set()
        self.current_file = str(file_path)
        
        try:
            with open(file_path, "r", errors="ignore") as f:
                tree = ast.parse(f.read())
            self.visit(tree)
        except Exception as e:
            # print(f"AST Scan Error {file_path}: {e}")
            pass
            
        return self.suspects

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            if "cryptography" in alias.name or "Crypto" in alias.name:
                self.crypto_imports.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module and ("cryptography" in node.module or "Crypto" in node.module):
            self.crypto_imports.add(node.module)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        # Check for key generation calls
        func_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
            
        key_gen_funcs = ["generate_private_key", "RSAPrivateKey", "generate"]
        
        if func_name in key_gen_funcs:
            # Extract key_size if present
            key_size = "Unknown"
            for kw in node.keywords:
                if kw.arg == "key_size" and isinstance(kw.value, ast.Constant):
                    key_size = str(kw.value.value)
                elif kw.arg == "bits" and isinstance(kw.value, ast.Constant):
                    key_size = str(kw.value.value)

            self.suspects.append(Suspect(
                path=self.current_file,
                line=node.lineno,
                content_snippet=f"AST detected {func_name} (key_size: {key_size})",
                type="code",
                pattern_matched="AST_Crypto_Call",
                confidence="high"
            ))
            
        self.generic_visit(node)
