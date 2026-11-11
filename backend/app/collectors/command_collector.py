import os
import shlex
import time
import uuid
import logging
import psutil
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Tuple, Optional

from app.collectors.base import BaseCollector
from app.schemas.event import NormalizedEvent
from app.security.sanitization import InputSanitizer
from app.security.path_validator import PathValidator
from app.config import settings

logger = logging.getLogger("phantomshell.collector.command")

ALLOWED_COMMANDS = {
    "help", "?", "status", "ls", "dir", "whoami", "date", "time",
    "ps", "rules", "echo", "scan", "inspect", "clear", "ghost"
}

class CommandCollector(BaseCollector):
    def __init__(self, monitored_directory: str):
        super().__init__("command_collector")
        self.monitored_directory = monitored_directory
        self.is_running = True # Terminal panel is active by default

    def start(self):
        self.is_running = True
        self.is_paused = False

    def stop(self):
        self.is_running = False

    def update_directory(self, new_dir: str):
        self.monitored_directory = new_dir

    def execute_terminal_command(self, raw_command: str) -> Dict[str, Any]:
        """
        Executes an approved, read-only application command safely.
        Never invokes shell=True. Rejects unapproved binaries and dangerous operators.
        """
        start_time = time.time()
        event_id = str(uuid.uuid4())
        cleaned_cmd = InputSanitizer.sanitize_string(raw_command.strip(), max_length=150)
        
        if not cleaned_cmd:
            return {
                "command": "",
                "output": "Empty command provided. Type 'help' for approved commands.",
                "exit_code": 0,
                "error": "",
                "event_id": event_id,
                "execution_time_ms": 0.0
            }

        # Check for dangerous shell metacharacters: ;, |, &, `, $, >, <
        dangerous_tokens = [";", "|", "&", "`", "$", ">", "<", "\n"]
        if any(token in cleaned_cmd for token in dangerous_tokens):
            err_msg = "Security Exception: Shell metacharacters are strictly forbidden."
            self._emit_blocked_event(event_id, cleaned_cmd, err_msg, "shell_metacharacter_attempt")
            return {
                "command": cleaned_cmd,
                "output": f"[SECURITY ALERT] {err_msg}",
                "exit_code": 1,
                "error": err_msg,
                "event_id": event_id,
                "execution_time_ms": (time.time() - start_time) * 1000
            }

        try:
            tokens = shlex.split(cleaned_cmd)
        except Exception as e:
            err_msg = f"Command parsing error: {str(e)}"
            self._emit_blocked_event(event_id, cleaned_cmd, err_msg, "parse_error")
            return {
                "command": cleaned_cmd,
                "output": err_msg,
                "exit_code": 1,
                "error": err_msg,
                "event_id": event_id,
                "execution_time_ms": (time.time() - start_time) * 1000
            }

        cmd_name = tokens[0].lower()
        args = tokens[1:]

        if cmd_name not in ALLOWED_COMMANDS:
            err_msg = f"Command '{cmd_name}' is not in the approved read-only allowlist."
            self._emit_blocked_event(event_id, cleaned_cmd, err_msg, "unapproved_command")
            return {
                "command": cleaned_cmd,
                "output": f"Error: Command '{cmd_name}' is disallowed.\nUse 'help' to view the permitted read-only command set.",
                "exit_code": 126,
                "error": err_msg,
                "event_id": event_id,
                "execution_time_ms": (time.time() - start_time) * 1000
            }

        # Dispatch safe internal command
        output, exit_code, error = self._dispatch_safe_command(cmd_name, args, event_id, cleaned_cmd)
        exec_ms = round((time.time() - start_time) * 1000, 2)

        # Emit normal execution event
        norm_event = NormalizedEvent(
            event_id=event_id,
            timestamp=datetime.utcnow(),
            event_type="command_exec",
            source=self.name,
            severity="info" if exit_code == 0 else "low",
            evidence={
                "command": cleaned_cmd,
                "command_name": cmd_name,
                "args": args,
                "exit_code": exit_code,
                "execution_time_ms": exec_ms,
                "status": "success" if exit_code == 0 else "failed"
            },
            collection_status="collected",
            is_simulated=False
        )
        self.emit_event(norm_event)

        return {
            "command": cleaned_cmd,
            "output": output,
            "exit_code": exit_code,
            "error": error,
            "event_id": event_id,
            "execution_time_ms": exec_ms
        }

    def _emit_blocked_event(self, event_id: str, raw_cmd: str, reason: str, sub_type: str):
        norm_event = NormalizedEvent(
            event_id=event_id,
            timestamp=datetime.utcnow(),
            event_type="command_blocked",
            source=self.name,
            severity="medium",
            evidence={
                "command": raw_cmd,
                "reason": reason,
                "block_subtype": sub_type,
                "timestamp": datetime.utcnow().isoformat()
            },
            collection_status="blocked",
            is_simulated=False
        )
        self.emit_event(norm_event)

    def _dispatch_safe_command(self, cmd: str, args: list, event_id: str, raw_cmd: str) -> Tuple[str, int, str]:
        if cmd in ("help", "?"):
            help_text = (
                "PHANTOMSHELL CONSTRAINED TERMINAL (Read-Only Application Console)\n"
                "---------------------------------------------------------------\n"
                "  help, ?          Show this manual\n"
                "  status           Display active monitoring and AI sensor status\n"
                "  ls, dir [path]   Safely list items inside permitted workspace\n"
                "  ps               Enumerate active top-level processes via psutil\n"
                "  scan <path>      Perform boundary and sensitive target verification\n"
                "  whoami           Show current operating system username\n"
                "  date, time       Show current UTC and system timestamps\n"
                "  echo <text>      Echo sanitized text to console\n"
                "  rules            List active deterministic detection rules\n"
                "  clear            Clear terminal screen"
            )
            return help_text, 0, ""

        if cmd == "whoami":
            try:
                import getpass
                return f"USER: {getpass.getuser()} (Local Session)", 0, ""
            except Exception as e:
                return "Unknown user", 0, ""

        if cmd in ("date", "time"):
            return f"UTC: {datetime.utcnow().isoformat()}Z | LOCAL: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", 0, ""

        if cmd == "status":
            return (
                f"[SYSTEM TELEMETRY STATUS]\n"
                f"Workspace Directory : {self.monitored_directory}\n"
                f"Process Collector   : {'ACTIVE' if self.is_running else 'PAUSED'}\n"
                f"Allowed Operations  : Read-Only Constrained Execution\n"
                f"Security Mode       : Zero-Shell-Execution Sandbox"
            ), 0, ""

        if cmd in ("ls", "dir"):
            target_sub = args[0] if args else "."
            is_safe, resolved, msg = PathValidator.resolve_safe_path(self.monitored_directory, target_sub)
            if not is_safe:
                self._emit_blocked_event(event_id, raw_cmd, msg, "boundary_violation_attempt")
                return f"[SECURITY VIOLATION BLOCKED] {msg}", 1, msg

            if not resolved or not resolved.exists():
                return f"Path does not exist: {target_sub}", 1, "Not found"

            try:
                entries = []
                for entry in sorted(resolved.iterdir()):
                    prefix = "<DIR> " if entry.is_dir() else "      "
                    entries.append(f"{prefix}{entry.name}")
                listing = "\n".join(entries) if entries else "(empty directory)"
                return f"Directory of {resolved}:\n{listing}", 0, ""
            except Exception as e:
                return f"Error listing directory: {str(e)}", 1, str(e)

        if cmd == "scan":
            if not args:
                return "Usage: scan <path>", 1, "Missing path"
            target_path = args[0]
            
            # Check sensitive tokens
            is_sens, sens_token = PathValidator.is_sensitive_path(target_path, settings.SENSITIVE_PATHS)
            is_safe, resolved, msg = PathValidator.resolve_safe_path(self.monitored_directory, target_path)

            results = [f"--- DETERMINISTIC SCAN: {target_path} ---"]
            if is_sens:
                results.append(f"[ALERT] Sensitive target pattern detected: '{sens_token}'")
            if not is_safe:
                results.append(f"[ALERT] Boundary violation detected: {msg}")
            if is_safe and not is_sens:
                results.append("[OK] Target path conforms to permitted workspace boundaries.")

            exit_code = 1 if (is_sens or not is_safe) else 0
            if exit_code != 0:
                self._emit_blocked_event(event_id, raw_cmd, "Scan identified sensitive or out-of-boundary path", "security_scan_alert")

            return "\n".join(results), exit_code, ""

        if cmd == "ps":
            try:
                lines = [f"{'PID':<8} {'NAME':<25} {'STATUS':<12}"]
                count = 0
                for p in psutil.process_iter(['pid', 'name', 'status']):
                    if count >= 15:
                        break
                    try:
                        info = p.info
                        lines.append(f"{info['pid']:<8} {str(info['name'])[:24]:<25} {str(info['status']):<12}")
                        count += 1
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                lines.append(f"\n... Total visible processes inspected: {count}")
                return "\n".join(lines), 0, ""
            except Exception as e:
                return f"Failed to inspect processes: {e}", 1, str(e)

        if cmd == "echo":
            return " ".join(args), 0, ""

        if cmd == "rules":
            return (
                "Deterministic Rules Active:\n"
                "1. RULE_UNUSUAL_PROCESS       - High-risk process signature appearance\n"
                "2. RULE_WORKSPACE_BOUNDARY    - Out-of-bounds traversal or boundary breach\n"
                "3. RULE_FILE_BURST            - Rapid file modification spike in time window\n"
                "4. RULE_SENSITIVE_PATH        - Sensitive path or secret file target attempt\n"
                "5. RULE_FAILED_OPERATIONS     - Burst of blocked/failed operations\n"
                "6. RULE_UNUSUAL_PARENT_CHILD  - Anomalous process spawning hierarchy"
            ), 0, ""

        return "Command completed.", 0, ""
