import json
import time
import logging
from typing import Dict, Any, List, Optional
import httpx

from app.config import settings
from app.ai.prompts import SYSTEM_PROMPT, format_incident_prompt, format_chat_prompt
from app.ai.fallback import DeterministicGhostFallback
from app.security.sanitization import InputSanitizer

logger = logging.getLogger("phantomshell.ai.ollama")

class OllamaClient:
    def __init__(self, base_url: str = settings.OLLAMA_BASE_URL, default_model: str = settings.OLLAMA_MODEL):
        self.base_url = base_url.rstrip("/")
        self.default_model = default_model

    def _is_service_reachable(self, timeout: float = 0.1) -> bool:
        """Fast non-blocking port check with strict select timeout and SO_ERROR validation."""
        import socket
        import select
        from urllib.parse import urlparse

        parsed = urlparse(self.base_url)
        host = parsed.hostname or "127.0.0.1"
        port = parsed.port or 11434

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setblocking(False)
        try:
            s.connect((host, port))
            s.close()
            return True
        except BlockingIOError:
            try:
                r, w, x = select.select([s], [s], [s], timeout)
                if not (r or w):
                    s.close()
                    return False
                err = s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                s.close()
                return err == 0
            except Exception:
                try:
                    s.close()
                except Exception:
                    pass
                return False
        except Exception:
            try:
                s.close()
            except Exception:
                pass
            return False

    async def check_health(self) -> Dict[str, Any]:
        """Checks if local Ollama daemon is reachable and lists installed models."""
        if not self._is_service_reachable():
            return {
                "is_available": False,
                "model": self.default_model,
                "base_url": self.base_url,
                "latency_ms": None,
                "installed_models": [],
                "error_message": f"Cannot connect to local Ollama daemon at {self.base_url} (Service offline)"
            }

        url = f"{self.base_url}/api/tags"
        start_time = time.time()
        try:
            async with httpx.AsyncClient(timeout=settings.OLLAMA_CONNECT_TIMEOUT) as client:
                res = await client.get(url)
                latency = round((time.time() - start_time) * 1000, 2)
                if res.status_code == 200:
                    data = res.json()
                    models = [m.get("name") for m in data.get("models", [])]
                    return {
                        "is_available": True,
                        "model": self.default_model,
                        "base_url": self.base_url,
                        "latency_ms": latency,
                        "installed_models": models,
                        "error_message": None
                    }
                else:
                    return {
                        "is_available": False,
                        "model": self.default_model,
                        "base_url": self.base_url,
                        "latency_ms": latency,
                        "installed_models": [],
                        "error_message": f"Ollama HTTP {res.status_code}: {res.text[:100]}"
                    }
        except httpx.ConnectError:
            return {
                "is_available": False,
                "model": self.default_model,
                "base_url": self.base_url,
                "latency_ms": None,
                "installed_models": [],
                "error_message": "Cannot connect to local Ollama daemon at " + self.base_url + " (Service offline)"
            }
        except Exception as e:
            return {
                "is_available": False,
                "model": self.default_model,
                "base_url": self.base_url,
                "latency_ms": None,
                "installed_models": [],
                "error_message": f"Ollama health check error: {str(e)}"
            }

    async def explain_incident(self, incident_data: Dict[str, Any], model_override: Optional[str] = None) -> Dict[str, Any]:
        """
        Generates structured Ghost explanation for an incident.
        Falls back automatically if Ollama is offline or generation fails.
        """
        model = model_override or self.default_model

        if not self._is_service_reachable():
            fallback = DeterministicGhostFallback.generate_incident_explanation(incident_data)
            return {
                "incident_id": incident_data.get("id"),
                "narration": fallback["narration"],
                "factual_explanation": fallback["factual_explanation"],
                "recommendation": fallback["recommendation"],
                "is_fallback": True,
                "model_used": "deterministic_fallback"
            }

        prompt = format_incident_prompt(incident_data)

        payload = {
            "model": model,
            "prompt": prompt,
            "system": SYSTEM_PROMPT,
            "stream": False,
            "format": "json",
            "options": {
                "temperature": settings.OLLAMA_TEMPERATURE,
                "num_predict": settings.OLLAMA_MAX_TOKENS
            }
        }

        timeout_cfg = httpx.Timeout(settings.OLLAMA_REQUEST_TIMEOUT, connect=settings.OLLAMA_CONNECT_TIMEOUT)
        try:
            async with httpx.AsyncClient(timeout=timeout_cfg) as client:
                response = await client.post(f"{self.base_url}/api/generate", json=payload)
                if response.status_code == 200:
                    data = response.json()
                    raw_text = data.get("response", "").strip()
                    parsed = self._validate_and_parse_explanation(raw_text)
                    if parsed:
                        return {
                            "incident_id": incident_data.get("id"),
                            "narration": InputSanitizer.sanitize_string(parsed["narration"]),
                            "factual_explanation": InputSanitizer.sanitize_string(parsed["factual_explanation"]),
                            "recommendation": InputSanitizer.sanitize_string(parsed["recommendation"]),
                            "is_fallback": False,
                            "model_used": model
                        }
                    else:
                        logger.warning(f"Ollama returned malformed JSON: {raw_text[:100]}")
        except Exception as e:
            logger.info(f"Ollama inference unavailable ({str(e)}). Using deterministic Ghost fallback.")

        # Deterministic fallback
        fallback = DeterministicGhostFallback.generate_incident_explanation(incident_data)
        return {
            "incident_id": incident_data.get("id"),
            "narration": fallback["narration"],
            "factual_explanation": fallback["factual_explanation"],
            "recommendation": fallback["recommendation"],
            "is_fallback": True,
            "model_used": "deterministic_fallback"
        }

    async def chat(self, question: str, context_summary: str, model_override: Optional[str] = None) -> Dict[str, Any]:
        """Interactive Ghost response to user questions about telemetry."""
        model = model_override or self.default_model

        if not self._is_service_reachable():
            fallback_text = DeterministicGhostFallback.generate_chat_fallback(question, context_summary)
            return {
                "answer": fallback_text,
                "is_fallback": True,
                "model_used": "deterministic_fallback"
            }

        prompt = format_chat_prompt(question, context_summary)

        payload = {
            "model": model,
            "prompt": prompt,
            "system": SYSTEM_PROMPT,
            "stream": False,
            "options": {
                "temperature": settings.OLLAMA_TEMPERATURE + 0.1,
                "num_predict": settings.OLLAMA_MAX_TOKENS
            }
        }

        timeout_cfg = httpx.Timeout(settings.OLLAMA_REQUEST_TIMEOUT, connect=settings.OLLAMA_CONNECT_TIMEOUT)
        try:
            async with httpx.AsyncClient(timeout=timeout_cfg) as client:
                response = await client.post(f"{self.base_url}/api/generate", json=payload)
                if response.status_code == 200:
                    data = response.json()
                    answer = data.get("response", "").strip()
                    if answer:
                        return {
                            "answer": InputSanitizer.sanitize_string(answer, max_length=1500),
                            "is_fallback": False,
                            "model_used": model
                        }
        except Exception as e:
            logger.info(f"Ollama chat unavailable ({e}). Employing deterministic fallback.")

        fallback_text = DeterministicGhostFallback.generate_chat_fallback(question, context_summary)
        return {
            "answer": fallback_text,
            "is_fallback": True,
            "model_used": "deterministic_fallback"
        }

    def _validate_and_parse_explanation(self, text: str) -> Optional[Dict[str, str]]:
        try:
            # Handle possible markdown fencing around json
            clean_text = text.strip()
            if clean_text.startswith("```"):
                lines = clean_text.splitlines()
                if lines[0].startswith("```"):
                    lines = lines[1:]
                if lines and lines[-1].startswith("```"):
                    lines = lines[:-1]
                clean_text = "\n".join(lines).strip()

            parsed = json.loads(clean_text)
            if isinstance(parsed, dict) and "narration" in parsed and "factual_explanation" in parsed and "recommendation" in parsed:
                return {
                    "narration": str(parsed["narration"]),
                    "factual_explanation": str(parsed["factual_explanation"]),
                    "recommendation": str(parsed["recommendation"])
                }
            return None
        except Exception:
            return None

ollama_client = OllamaClient()
