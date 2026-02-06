import ast
from pathlib import Path
from typing import List, Dict
from schemas.models import Suspect

class ASTScanner(ast.NodeVisitor):
    def __init__(self):
        self.suspects = []
        self.current_file = ""
        self.crypto_imports = set()
        self.variables = {}  # Tracks variable name -> source (e.g. 'ENV', 'CONST', 'FILE')

    def scan_file(self, file_path: Path) -> List[Suspect]:
        self.suspects = []
        self.crypto_imports = set()
        self.variables = {}
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

    def visit_Assign(self, node: ast.Assign):
        # Track assignments for primitive taint tracking
        source_type = "UNKNOWN"
        
        # Check if RHS is a constant
        if isinstance(node.value, ast.Constant):
            source_type = f"CONSTANT({node.value.value})"
        # Check if RHS is an environment variable call
        elif isinstance(node.value, ast.Call):
            func_name = ""
            if isinstance(node.value.func, ast.Attribute):
                func_name = node.value.func.attr
            elif isinstance(node.value.func, ast.Name):
                func_name = node.value.func.id
            
            if func_name in ["getenv", "get"]:
                 source_type = "ENV_VAR"
            elif func_name == "open":
                 source_type = "FILE_READ"

        # Record assignment to targets
        for target in node.targets:
            if isinstance(target, ast.Name):
                self.variables[target.id] = source_type
        
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
            # Extract key_size and determine its source
            key_size = "Unknown"
            source = "DIRECT_CALL"
            
            for kw in node.keywords:
                if kw.arg in ["key_size", "bits"]:
                    if isinstance(kw.value, ast.Constant):
                        key_size = str(kw.value.value)
                        source = "HARDCODED_CONSTANT"
                    elif isinstance(kw.value, ast.Name) and kw.value.id in self.variables:
                        key_size = f"VAR({kw.value.id})"
                        source = self.variables[kw.value.id]

            self.suspects.append(Suspect(
                path=self.current_file,
                line=node.lineno,
                content_snippet=f"AST detected {func_name} | key_size: {key_size} | data_source: {source}",
                type="code",
                pattern_matched="AST_Crypto_Call",
                confidence="high"
            ))
            
        self.generic_visit(node)
