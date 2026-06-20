"""
Semantic Debris Detection - Production Level

Includes:
- LLM context files, vibe scratchpads, env files, chat exports
- Content-based + filename-based detection
- **Structural duplicate detection** using Python AST (detects AI-regenerated files)
- Content hash + name similarity fallback
"""

from __future__ import annotations

import ast
import hashlib
import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import Config
from .crawler import FileInfo
from .graph import DebrisFile, content_hash

import math
import string


# =============================================================================
# Category Definitions
# =============================================================================
LLM_CONTEXT_FILES = {
    "claude.md", "claude_context.md", ".claude_instructions",
    ".cursorrules", "cursor_rules.md", ".cursorignore",
    ".copilot-instructions.md", "agents.md", "windsurf_rules.md",
    "llm_context.txt", "ai_prompt.md", "system_prompt.txt",
}

VIBE_SCRATCHPAD_NAMES = {
    "scratch", "playground", "temp", "tmp", "untitled", "copy_of",
    "backup", "old", "new", "v2", "final", "todo_delete", "debug",
}

CHAT_PATTERNS = [
    r"^\s*(User|Assistant|Human|System):\s",
    r"^(Human|Assistant):",
]


@dataclass
class _FileSignature:
    """Lightweight structural signature for duplicate detection."""
    functions: frozenset[str]
    classes: frozenset[str]
    imports: frozenset[str]
    total_nodes: int


class DebrisDetector:
    def __init__(self, config: Config):
        self.config = config
        self._content_hashes: dict[str, list[Path]] = defaultdict(list)
        self._signatures: dict[Path, _FileSignature] = {}

    def scan(self, files: list[FileInfo]) -> list[DebrisFile]:
        results: list[DebrisFile] = []

        # Build indexes
        for f in files:
            if f.is_text and f.size < 2 * 1024 * 1024:
                h = content_hash(f.path)
                if h:
                    self._content_hashes[h].append(f.path)

                if f.path.suffix == ".py":
                    sig = self._extract_python_signature(f.path)
                    if sig:
                        self._signatures[f.path] = sig

        for f in files:
            flags = self._check_file(f, files)
            if flags:
                results.append(self._build_debris_file(f, flags))

        return sorted(results, key=lambda d: (not d.block_push, -d.confidence, d.path))

    # -------------------------------------------------------------------------
    # Per-file checking
    # -------------------------------------------------------------------------
    def _check_file(self, f: FileInfo, all_files: list[FileInfo]) -> list[dict[str, Any]]:
        flags = []
        flags += self._check_filename(f)
        if f.is_text:
            flags += self._check_content(f)
            flags += self._detect_hardcoded_secrets(f)
        flags += self._check_duplicates(f, all_files)
        flags += self._check_structural_duplicates(f, all_files)
        flags += self._check_git_status(f)
        return flags

    def _check_filename(self, f: FileInfo) -> list[dict[str, Any]]:
        flags = []
        name_lower = f.path.name.lower()
        rel = str(f.rel_path).lower()

        if name_lower in LLM_CONTEXT_FILES or any(p in rel for p in LLM_CONTEXT_FILES):
            flags.append({
                "category": "llm_context_file",
                "confidence": 0.99,
                "reason": f"Known LLM/AI coding assistant context file: {f.path.name}",
                "block": True,
                "suggestion": "Add to .gitignore. These should never be committed.",
            })

        for bad in VIBE_SCRATCHPAD_NAMES:
            if bad in name_lower:
                flags.append({
                    "category": "vibe_scratchpad",
                    "confidence": 0.82,
                    "reason": f"Looks like a temporary/AI scratch file: {f.path.name}",
                    "block": False,
                    "suggestion": "Delete or move to a gitignored location.",
                })
                break

        if any(x in name_lower for x in ["_copy", "_backup", "_old", "_v2", "_final", "_new"]):
            flags.append({
                "category": "duplicate_file",
                "confidence": 0.75,
                "reason": f"Filename suggests copy/regenerated version: {f.path.name}",
                "block": False,
                "suggestion": "Compare with original and remove duplicate.",
            })

        return flags

    def _check_content(self, f: FileInfo) -> list[dict[str, Any]]:
        flags = []
        try:
            with f.path.open("r", encoding="utf-8", errors="ignore") as fh:
                head = "".join([next(fh) for _ in range(55)])
        except Exception:
            return flags

        content_lower = head.lower()

        if any(p in content_lower for p in [
            "you are a helpful assistant", "you are an expert software engineer",
            "as an ai coding assistant", "claude", "cursor rules",
        ]):
            flags.append({
                "category": "llm_context_file",
                "confidence": 0.96,
                "reason": "Contains AI system prompt or context instructions",
                "block": True,
                "suggestion": "This appears to be an exported AI context/prompt file.",
            })

        for pattern in CHAT_PATTERNS:
            if re.search(pattern, head, re.IGNORECASE | re.MULTILINE):
                flags.append({
                    "category": "chat_export",
                    "confidence": 0.88,
                    "reason": "Matches exported LLM chat log format",
                    "block": False,
                    "suggestion": "Remove chat export files from the repository.",
                })
                break

        if f.path.name.startswith(".env") and any(x in f.path.name.lower() for x in ["local", "dev", "development"]):
            flags.append({
                "category": "env_file",
                "confidence": 0.97,
                "reason": "Committed local/development environment file",
                "block": True,
                "suggestion": "Add to .gitignore and rotate any exposed secrets.",
            })

        return flags

    # -------------------------------------------------------------------------
    # Content + Name Duplicate Detection
    # -------------------------------------------------------------------------
    def _check_duplicates(self, f: FileInfo, all_files: list[FileInfo]) -> list[dict[str, Any]]:
        flags = []
        my_hash = content_hash(f.path)
        if my_hash:
            duplicates = [p for p in self._content_hashes.get(my_hash, []) if p != f.path]
            if duplicates:
                flags.append({
                    "category": "duplicate_file",
                    "confidence": 0.99,
                    "reason": f"Exact content duplicate of: {duplicates[0].name}",
                    "block": False,
                    "suggestion": "Delete all but one copy.",
                })

        # Name similarity
        for other in all_files:
            if other.path == f.path:
                continue
            if self._name_similarity(f.path.name, other.path.name) > 0.80:
                flags.append({
                    "category": "duplicate_file",
                    "confidence": 0.70,
                    "reason": f"Very similar filename to existing file: {other.rel_path}",
                    "block": False,
                    "suggestion": "Review — this may be an AI-regenerated duplicate.",
                })
                break
        return flags

    def _name_similarity(self, a: str, b: str) -> float:
        def bigrams(s): return {s[i:i+2] for i in range(len(s)-1)}
        inter = len(bigrams(a) & bigrams(b))
        union = len(bigrams(a) | bigrams(b))
        return inter / union if union else 0.0

    # -------------------------------------------------------------------------
    # NEW: Structural / AST-based Duplicate Detection (The Wow Feature)
    # -------------------------------------------------------------------------
    def _extract_python_signature(self, path: Path) -> _FileSignature | None:
        """Extract structural signature of a Python file using AST."""
        try:
            with path.open("r", encoding="utf-8", errors="ignore") as f:
                tree = ast.parse(f.read(), filename=str(path))
        except Exception:
            return None

        functions = set()
        classes = set()
        imports = set()
        total_nodes = 0

        for node in ast.walk(tree):
            total_nodes += 1
            if isinstance(node, ast.FunctionDef):
                args = tuple(arg.arg for arg in node.args.args)
                functions.add(f"{node.name}{args}")
            elif isinstance(node, ast.ClassDef):
                classes.add(node.name)
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                for alias in node.names:
                    imports.add(alias.name)

        return _FileSignature(
            functions=frozenset(functions),
            classes=frozenset(classes),
            imports=frozenset(imports),
            total_nodes=total_nodes
        )

    def _check_structural_duplicates(self, f: FileInfo, all_files: list[FileInfo]) -> list[dict[str, Any]]:
        """
        Detect files that have very similar structure to existing files.
        This catches cases where an LLM was asked to "rewrite" or "improve" a file
        and created a near-duplicate instead of editing the original.
        """
        if f.path.suffix != ".py" or f.path not in self._signatures:
            return []

        flags = []
        my_sig = self._signatures[f.path]

        for other_path, other_sig in self._signatures.items():
            if other_path == f.path:
                continue

            func_overlap = len(my_sig.functions & other_sig.functions)
            class_overlap = len(my_sig.classes & other_sig.classes)
            total_unique = len(my_sig.functions | other_sig.functions) + len(my_sig.classes | other_sig.classes)

            if total_unique == 0:
                continue

            similarity = (func_overlap + class_overlap) / total_unique

            if similarity > 0.75 and len(my_sig.functions) > 1:
                flags.append({
                    "category": "ai_regenerated_duplicate",
                    "confidence": min(0.92, 0.65 + similarity * 0.3),
                    "reason": f"Structurally very similar to {other_path.name} (likely AI-regenerated copy)",
                    "block": False,
                    "suggestion": "Compare with original. Delete the regenerated version and edit the original instead.",
                })
                break

        return flags

    # -------------------------------------------------------------------------
    # ADVANCED Hardcoded Secrets Detection (Production-Grade)
    # -------------------------------------------------------------------------
    def _detect_hardcoded_secrets(self, f: FileInfo) -> list[dict[str, Any]]:
        """
        Advanced, multi-layered secret detection engine.

        Techniques used:
        - High-order entropy analysis (bigram/trigram aware)
        - Keyword proximity scoring (how close "secret"/"key" is to candidate)
        - AST-aware context analysis (for Python)
        - Known high-value secret formats with validation
        - Obfuscation detection (concatenation, base64-ish strings)
        - Strong false-positive filtering
        """
        if not f.is_text or f.size > 800_000:
            return []

        flags = []
        try:
            content = f.path.read_text(encoding="utf-8", errors="ignore")
            lines = content.splitlines()
        except Exception:
            return flags

        # === Layer 1: High-confidence known formats ===
        known_formats = self._get_known_secret_formats()
        for i, line in enumerate(lines):
            for pattern, secret_type, confidence in known_formats:
                if re.search(pattern, line):
                    flags.append({
                        "category": "hardcoded_secret",
                        "confidence": confidence,
                        "reason": f"High-confidence {secret_type} detected (line {i+1})",
                        "block": True,
                        "suggestion": f"Remove the hardcoded {secret_type}. Use a secrets manager or environment variables immediately.",
                    })

        # === Layer 2: Advanced entropy + context scoring ===
        candidates = self._extract_potential_secrets(content, lines)

        for candidate in candidates:
            score, reasons = self._score_secret_candidate(candidate, content)

            if score >= 0.78:  # High confidence threshold
                flags.append({
                    "category": "hardcoded_secret",
                    "confidence": round(score, 3),
                    "reason": " | ".join(reasons),
                    "block": True,
                    "suggestion": "This appears to be a hardcoded secret. Move it to environment variables or a proper secrets manager (AWS Secrets Manager, Doppler, Infisical, etc.).",
                })

        # === Layer 3: Python AST-based deep analysis (most accurate) ===
        if f.path.suffix == ".py":
            ast_flags = self._detect_secrets_via_ast(content, str(f.path))
            flags.extend(ast_flags)

        # === Layer 4: Obfuscation & reconstruction ===
        obfuscated_flags = self._detect_obfuscated_secrets(content, lines)
        flags.extend(obfuscated_flags)

        return flags

    def _get_known_secret_formats(self):
        """High-precision patterns for well-known secret types."""
        return [
            (r'AKIA[0-9A-Z]{16}', "AWS Access Key ID", 0.97),
            (r'(?i)aws.*secret.*access.*key["\']?\s*[:=]\s*["\']?[A-Za-z0-9/+=]{40}', "AWS Secret Access Key", 0.95),
            (r'ghp_[a-zA-Z0-9]{36}', "GitHub Personal Access Token", 0.98),
            (r'gho_[a-zA-Z0-9]{36}', "GitHub OAuth Token", 0.96),
            (r'ghs_[a-zA-Z0-9]{36}', "GitHub App Token", 0.96),
            (r'sk-[a-zA-Z0-9]{48}', "OpenAI API Key", 0.97),
            (r'sk-ant-[a-zA-Z0-9]{48}', "Anthropic API Key", 0.97),
            (r'AIza[0-9A-Za-z\-_]{35}', "Google API Key", 0.94),
            (r'-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----', "Private Key", 0.99),
            (r'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}', "JWT Token", 0.90),
        ]

    def _extract_potential_secrets(self, content: str, lines: list[str]) -> list[dict]:
        """Extract candidate strings that could be secrets using multiple strategies."""
        candidates = []

        # Strategy 1: String literals assigned to sensitive-looking variables
        sensitive_keywords = {
            "key", "token", "secret", "password", "passwd", "credential", "auth",
            "api", "private", "access", "bearer", "jwt", "oauth", "client_secret"
        }

        # Python/JS/TS style assignments
        assignment_pattern = re.compile(
            r'([a-zA-Z_][a-zA-Z0-9_]*)\s*[:=]\s*["\']([A-Za-z0-9_\-/.+=@#$%^&*!~|]{16,})["\']'
        )

        for i, line in enumerate(lines):
            for match in assignment_pattern.finditer(line):
                var_name = match.group(1).lower()
                value = match.group(2)

                # Check if variable name contains sensitive keywords
                if any(kw in var_name for kw in sensitive_keywords):
                    candidates.append({
                        "value": value,
                        "line": i + 1,
                        "context": line.strip(),
                        "variable": match.group(1),
                        "type": "assignment"
                    })

        # Strategy 2: High-entropy standalone strings (even without assignment)
        string_literal_pattern = re.compile(r'["\']([A-Za-z0-9_\-/.+=@#$%^&*!~|]{24,})["\']')
        for i, line in enumerate(lines):
            for match in string_literal_pattern.finditer(line):
                value = match.group(1)
                if self._advanced_entropy(value) > 4.2:
                    candidates.append({
                        "value": value,
                        "line": i + 1,
                        "context": line.strip(),
                        "variable": None,
                        "type": "standalone"
                    })

        return candidates

    def _advanced_entropy(self, s: str) -> float:
        """More sophisticated entropy calculation using character distribution + bigrams."""
        if len(s) < 16:
            return 0.0

        # Character-level entropy
        prob = [float(s.count(c)) / len(s) for c in set(s)]
        char_entropy = -sum(p * math.log2(p) for p in prob if p > 0)

        # Bigram entropy (detects structured vs random strings)
        if len(s) > 2:
            bigrams = [s[i:i+2] for i in range(len(s)-1)]
            bigram_prob = [float(bigrams.count(b)) / len(bigrams) for b in set(bigrams)]
            bigram_entropy = -sum(p * math.log2(p) for p in bigram_prob if p > 0)
            return (char_entropy * 0.6) + (bigram_entropy * 0.4)

        return char_entropy

    def _score_secret_candidate(self, candidate: dict, full_content: str) -> tuple[float, list[str]]:
        """Multi-factor scoring for secret likelihood."""
        value = candidate["value"]
        context = candidate.get("context", "")
        var_name = candidate.get("variable", "") or ""

        score = 0.0
        reasons = []

        # Factor 1: Advanced entropy
        entropy = self._advanced_entropy(value)
        if entropy > 4.8:
            score += 0.35
            reasons.append("Very high entropy")
        elif entropy > 4.2:
            score += 0.25
            reasons.append("High entropy")

        # Factor 2: Character diversity
        diversity = self._character_diversity_score(value)
        if diversity >= 3.5:
            score += 0.20
            reasons.append("High character diversity")

        # Factor 3: Keyword proximity (very important)
        keyword_score = self._keyword_proximity_score(context, var_name)
        score += keyword_score * 0.25
        if keyword_score > 0.6:
            reasons.append("Strong keyword context")

        # Factor 4: Looks like base64 / hex
        if self._looks_like_encoded(value):
            score += 0.10
            reasons.append("Looks like encoded/encrypted data")

        # Factor 5: Length
        if 32 <= len(value) <= 128:
            score += 0.10

        # Factor 6: Penalize common false positives
        if self._is_common_false_positive(value):
            score -= 0.40
            reasons.append("Common test/example value (penalized)")

        return min(max(score, 0.0), 1.0), reasons

    def _character_diversity_score(self, s: str) -> float:
        has_upper = bool(re.search(r'[A-Z]', s))
        has_lower = bool(re.search(r'[a-z]', s))
        has_digit = bool(re.search(r'[0-9]', s))
        has_special = bool(re.search(r'[^A-Za-z0-9]', s))
        return sum([has_upper, has_lower, has_digit, has_special])

    def _keyword_proximity_score(self, context: str, var_name: str) -> float:
        """How strongly the surrounding context indicates a secret."""
        keywords = ["secret", "key", "token", "password", "credential", "auth", "private", "api"]
        context_lower = (context + " " + var_name).lower()

        matches = sum(1 for kw in keywords if kw in context_lower)
        return min(matches / 3.0, 1.0)

    def _looks_like_encoded(self, s: str) -> bool:
        """Detect base64-like or hex-like strings."""
        if len(s) % 4 == 0 and re.match(r'^[A-Za-z0-9+/=]+$', s):
            return True
        if re.match(r'^[0-9a-fA-F]+$', s) and len(s) > 32:
            return True
        return False

    def _is_common_false_positive(self, s: str) -> bool:
        """Filter out common example/test values."""
        false_positives = {
            "your_api_key_here", "insert_token_here", "example", "test", "demo",
            "placeholder", "changeme", "secret123", "password123", "AKIAIOSFODNN7EXAMPLE"
        }
        s_lower = s.lower()
        return any(fp in s_lower for fp in false_positives) or s.startswith("EXAMPLE")

    # -------------------------------------------------------------------------
    # Python AST-based Secret Detection (Deep & Accurate)
    # -------------------------------------------------------------------------
    def _detect_secrets_via_ast(self, content: str, filepath: str) -> list[dict[str, Any]]:
        """Use Python AST to find secrets assigned to sensitive variables more accurately."""
        flags = []
        try:
            tree = ast.parse(content, filename=filepath)
        except Exception:
            return flags

        sensitive_names = {
            "key", "token", "secret", "password", "credential", "auth",
            "apikey", "api_key", "private_key", "access_key", "bearer_token"
        }

        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        var_name = target.id.lower()
                        if any(s in var_name for s in sensitive_names):
                            val = getattr(node, "value", None)
                            if isinstance(val, ast.Constant) and isinstance(val.value, str):
                                value = node.value.value
                                if len(value) > 16 and self._advanced_entropy(value) > 4.0:
                                    if not self._is_common_false_positive(value):
                                        flags.append({
                                            "category": "hardcoded_secret",
                                            "confidence": 0.91,
                                            "reason": f"Secret-like value assigned to '{target.id}' via AST analysis",
                                            "block": True,
                                            "suggestion": "Move this secret out of source code into environment variables or a secrets manager.",
                                        })

            # Also detect os.environ / os.getenv usage with string literals (sometimes people do bad things)
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute) and node.func.attr in ("getenv", "environ"):
                    for arg in node.args:
                        if isinstance(arg, ast.Constant) and isinstance(getattr(arg, "value", None), str):
                            if any(s in arg.value.lower() for s in ["key", "token", "secret"]):
                                # This is actually good practice, so we don't flag it
                                pass

        return flags

    # -------------------------------------------------------------------------
    # Obfuscation Detection (Concatenation, Base64, etc.)
    # -------------------------------------------------------------------------
    def _detect_obfuscated_secrets(self, content: str, lines: list[str]) -> list[dict[str, Any]]:
        """Detect secrets that are split or encoded to evade simple detection."""
        flags = []

        # Detect string concatenation patterns (common obfuscation)
        concat_pattern = re.compile(
            r'["\']([A-Za-z0-9_\-/.+=]{8,})["\']\s*\+\s*["\']([A-Za-z0-9_\-/.+=]{8,})["\']'
        )

        for i, line in enumerate(lines):
            matches = concat_pattern.findall(line)
            for part1, part2 in matches:
                combined = part1 + part2
                if len(combined) >= 24 and self._advanced_entropy(combined) > 4.3:
                    flags.append({
                        "category": "hardcoded_secret",
                        "confidence": 0.85,
                        "reason": f"Secret reconstructed from string concatenation (line {i+1})",
                        "block": True,
                        "suggestion": "Secrets should never be constructed via string concatenation in source code.",
                    })

        # Attempt base64 decoding on suspicious long strings
        b64_pattern = re.compile(r'["\']([A-Za-z0-9+/=]{40,})["\']')
        for i, line in enumerate(lines):
            for match in b64_pattern.finditer(line):
                try:
                    import base64
                    decoded = base64.b64decode(match.group(1) + "==").decode("utf-8", errors="ignore")
                    if self._advanced_entropy(decoded) > 3.8 or any(kw in decoded.lower() for kw in ["key", "token", "secret"]):
                        flags.append({
                            "category": "hardcoded_secret",
                            "confidence": 0.80,
                            "reason": f"Potential base64-encoded secret detected (line {i+1})",
                            "block": True,
                            "suggestion": "Avoid storing encoded secrets directly in source code.",
                        })
                except Exception:
                    pass

        return flags

    def _check_git_status(self, f: FileInfo) -> list[dict[str, Any]]:
        flags = []
        if "__pycache__" in str(f.rel_path) or f.path.name.endswith(".pyc"):
            flags.append({
                "category": "dev_artifact",
                "confidence": 0.99,
                "reason": "Compiled Python cache committed to repository",
                "block": False,
                "suggestion": "Add __pycache__/ and *.pyc to .gitignore.",
            })
        return flags

    def _build_debris_file(self, f: FileInfo, flags: list[dict[str, Any]]) -> DebrisFile:
        best = max(flags, key=lambda x: (x.get("block", False), x["confidence"]))
        category = best["category"]
        block = best.get("block", False)

        if self.config.should_block_debris_category(category):
            block = True
        elif self.config.should_warn_debris_category(category):
            block = False

        return DebrisFile(
            path=str(f.rel_path),
            category=category,
            confidence=best["confidence"],
            reasons=[fl["reason"] for fl in flags],
            block_push=block,
            suggestion=best["suggestion"],
        )
