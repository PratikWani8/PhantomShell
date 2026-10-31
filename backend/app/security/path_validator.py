import os
from pathlib import Path
from typing import Tuple, Optional

class PathValidator:
    """
    Validates and normalizes paths strictly within permitted workspace boundaries.
    Detects directory traversal, symlink escapes, and attempts to access sensitive files.
    """

    @staticmethod
    def resolve_safe_path(base_dir: str, target_path: str) -> Tuple[bool, Optional[Path], str]:
        """
        Safely resolves target_path against base_dir.
        Returns:
            (is_safe, resolved_path, message)
        """
        try:
            base = Path(base_dir).resolve()
            if not base.exists():
                # Allow non-existing base if it's within a valid parent, but let's check base resolution
                base.mkdir(parents=True, exist_ok=True)
            
            # If target_path is absolute, check if it resolves within base
            target = Path(target_path)
            if target.is_absolute():
                resolved = target.resolve()
            else:
                resolved = (base / target).resolve()

            # Check if resolved path is strictly within base
            try:
                resolved.relative_to(base)
                return True, resolved, "Path is within permitted workspace boundary"
            except ValueError:
                return False, resolved, f"Boundary violation: Path '{target_path}' escapes workspace '{base_dir}'"
        except Exception as e:
            return False, None, f"Path resolution error: {str(e)}"

    @staticmethod
    def is_sensitive_path(path_str: str, sensitive_patterns: list[str]) -> Tuple[bool, Optional[str]]:
        """
        Checks whether the target path contains forbidden sensitive tokens or files
        (e.g., .ssh, .env, id_rsa, id_ed25519, credentials).
        """
        normalized = path_str.replace("\\", "/").lower()
        parts = normalized.strip("/").split("/")
        
        for pattern in sensitive_patterns:
            pat_lower = pattern.lower()
            # Match anywhere in path parts or filename
            for part in parts:
                if part == pat_lower or part.endswith(f"/{pat_lower}") or pat_lower in part:
                    return True, pattern

        return False, None
