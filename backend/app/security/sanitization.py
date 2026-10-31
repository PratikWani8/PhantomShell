import re
from typing import Any, Dict

class InputSanitizer:
    """
    Sanitizes untrusted telemetry, process names, file paths, and terminal commands
    to prevent command injection, prompt injection, and log poisoning.
    """

    # Strip dangerous terminal control escape sequences
    ANSI_ESCAPE = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    
    # Strip potential prompt injection attempts or system instruction delimiters
    PROMPT_INJECTION_PATTERNS = [
        re.compile(r'system\s*:', re.IGNORECASE),
        re.compile(r'ignore (all )?previous instructions', re.IGNORECASE),
        re.compile(r'you are now', re.IGNORECASE),
        re.compile(r'assistant\s*:', re.IGNORECASE),
        re.compile(r'human\s*:', re.IGNORECASE),
        re.compile(r'<\|.*?\|>', re.IGNORECASE),
        re.compile(r'\[INST\].*?\[/INST\]', re.IGNORECASE),
    ]

    @classmethod
    def sanitize_string(cls, text: str, max_length: int = 500) -> str:
        if not text:
            return ""
        # Remove ANSI escape sequences
        cleaned = cls.ANSI_ESCAPE.sub('', str(text))
        # Replace non-printable characters except newline and tab
        cleaned = ''.join(ch for ch in cleaned if ch.isprintable() or ch in ('\n', '\t'))
        
        # Neutralize prompt injection markers by defanging
        for pat in cls.PROMPT_INJECTION_PATTERNS:
            cleaned = pat.sub("[DEFANGED_DIRECTIVE]", cleaned)
            
        # Truncate
        if len(cleaned) > max_length:
            cleaned = cleaned[:max_length] + " [TRUNCATED]"
        return cleaned.strip()

    @classmethod
    def sanitize_metadata(cls, meta: Dict[str, Any]) -> Dict[str, Any]:
        """Recursively sanitizes dictionary metadata."""
        sanitized = {}
        for k, v in meta.items():
            safe_key = cls.sanitize_string(str(k), max_length=50)
            if isinstance(v, str):
                sanitized[safe_key] = cls.sanitize_string(v)
            elif isinstance(v, (int, float, bool)) or v is None:
                sanitized[safe_key] = v
            elif isinstance(v, dict):
                sanitized[safe_key] = cls.sanitize_metadata(v)
            elif isinstance(v, list):
                sanitized[safe_key] = [
                    cls.sanitize_string(x) if isinstance(x, str) else x 
                    for x in v[:50]
                ]
            else:
                sanitized[safe_key] = cls.sanitize_string(str(v))
        return sanitized
