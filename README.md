<pre>
  ____  _                 _              ____  _          _ _ 
 |  _ \| |__   __ _ _ __ | |_ ___  _ __ / ___|| |__   ___| | |
 | |_) | '_ \ / _` | '_ \| __/ _ \| '_ \\___ \| '_ \ / _ \ | |
 |  __/| | | | (_| | | | | || (_) | | | |___) | | | |  __/ | |
 |_|   |_| |_|\__,_|_| |_|\__\___/|_| |_|____/|_| |_|\___|_|_|
</pre>

<p align="center">
<img src="assets/image.png" alt="image" width="1200" height="350">
</p>

> **A Local-First Haunted Terminal and Deterministic Security Investigator Powered by Open-Weight AI**

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python](https://img.shields.io/badge/Python-3.11%2B-green.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115%2B-009688.svg)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-18.3-61dafb.svg)](https://react.dev/)
[![Ollama](https://img.shields.io/badge/Ollama-phi4--mini-purple.svg)](https://ollama.ai/)
[![Local-First](https://img.shields.io/badge/Privacy-100%25_Local-brightgreen.svg)]()

---

## 1. Project Introduction

**PhantomShell** is an open-source, local-first interactive security terminal and incident investigation workstation built for the *"Ghost in the Machine"* AI challenge.

PhantomShell observes explicitly enabled operating-system activity (process appearances, filesystem modifications in a designated workspace, and constrained terminal commands), identifies anomalous behavior through a **deterministic, explainable rule engine**, and uses a locally running open-weight language model (**Microsoft phi4-mini** via **Ollama**) to interpret and narrate real telemetry in an eerie digital-ghost personality.

### The Core Principle

> **Deterministic code establishes what happened. The AI explains the evidence. The interface presents the findings as a haunted terminal experience.**

- **No Hallucinations as Evidence**: Detection rules and risk scores are 100% mathematical and explainable. The LLM cannot alter risk scores or invent malware.
- **Zero Cloud Telemetry**: All telemetry, rule calculations, prompt synthesis, and weights remain strictly on the user's local machine (`127.0.0.1`).
- **Resilient Fallback**: If Ollama is offline or uninstalled, the entire application including detection, event history, risk scoring, and atmospheric Ghost explanations continues functioning via the built-in deterministic fallback engine.

---

## 2. Problem Statement

Modern security monitoring tools are increasingly tethered to proprietary cloud APIs. When users outsource telemetry interpretation to third-party language models:
1. **Private system paths, command lines, and process names leak** to external cloud providers.
2. **LLM hallucinations create phantom threats**, inventing malware signatures or misclassifying standard administrative workflows.
3. **Monolithic SIEM dashboards are sterile and opaque**, offering little intuition into why an alert was triggered or what evidence justifies the threat level.

---

## 3. The PhantomShell Solution

PhantomShell demonstrates an alternative paradigm:
- **Local-First Architecture**: Powered by open-weight models running on consumer hardware without dedicated GPUs.
- **Strict Evidence Grounding**: The local language model is constrained by an application harness with read-only inspection tools. It is strictly forbidden from claiming access to uncollected data or running unauthorized shell commands.
- **Cinematic Analog Horror Aesthetic**: Phosphor green CRTs, amber warnings, crimson alarms, subtle scanlines, interactive audio feedback, and the mysterious persona of **THE GHOST** turn security telemetry into a compelling, tactile experience.

---

## 4. Pipeline & System Architecture

```
+---------------------------------------------------------------------------------------+
|                                    OPERATING SYSTEM                                   |
|   - psutil Process Snapshotter  •  watchdog Filesystem Monitor  •  Constrained Console |
+-------------------------------------------+-------------------------------------------+
                                            |
                                            v
+---------------------------------------------------------------------------------------+
|                             NORMALIZATION & SANITIZATION                              |
|   - PathValidator (Boundary & Traversal)  •  InputSanitizer (ANSI & Injection Defang) |
+-------------------------------------------+-------------------------------------------+
                                            |
                                            v
+---------------------------------------------------------------------------------------+
|                              DETERMINISTIC RULE ENGINE                                |
|   1. RULE_UNUSUAL_PROCESS      (Flagged offensive binaries like nc, mimikatz)         |
|   2. RULE_WORKSPACE_BOUNDARY   (Path escape or out-of-bounds traversal attempt)       |
|   3. RULE_FILE_BURST           (Rapid file modification spike in sliding window)      |
|   4. RULE_SENSITIVE_PATH       (Probes against .ssh, .env, id_rsa, AWS credentials)  |
|   5. RULE_FAILED_OPERATIONS    (Burst of blocked or rejected security actions)        |
|   6. RULE_UNUSUAL_PARENT_CHILD (Conservative process tree anomaly detection)          |
+-------------------------------------------+-------------------------------------------+
                                            |
                                            v
+---------------------------------------------------------------------------------------+
|                          TRANSPARENT RISK SCORING & STORAGE                           |
|   - 0-100 Mathematical Score: min(100, severity_weight * confidence * multiplier)     |
|   - SQLite Persistence (minimum metadata, bounded retention, no secrets/file bodies)  |
+-------------------------------------------+-------------------------------------------+
                                            |
                     +----------------------+----------------------+
                     |                                             |
                     v                                             v
+-----------------------------------------+   +-----------------------------------------+
|        LOCAL AI INFERENCE (OLLAMA)      |   |       DETERMINISTIC GHOST FALLBACK      |
|   - Default: phi4-mini                  |   |   - Active when Ollama is offline       |
|   - Separates Eerie Narration from      |   |   - Generates grounded Ghost commentary |
|     Objective Evidence & Safe Actions   |   |     directly from telemetry schema      |
+--------------------+--------------------+   +--------------------+--------------------+
                     |                                             |
                     +----------------------+----------------------+
                                            |
                                            v
+---------------------------------------------------------------------------------------+
|                               FASTAPI REST & WEBSOCKET HUB                            |
|   - Strict Localhost Binding (127.0.0.1)  •  WebSocket Stream /ws/events               |
|   - Constrained Read-Only Agent Harness (5 safe inspection tools)                     |
+-------------------------------------------+-------------------------------------------+
                                            |
                                            v
+---------------------------------------------------------------------------------------+
|                             REACT + VITE + TAILWIND FRONTEND                          |
|   - Overview Dashboard  •  Haunted Terminal  •  Event Timeline  •  Incident Inspector  |
|   - Deterministic Rules View  •  AI Investigator Q&A  •  CRT & Web Audio Controls     |
+---------------------------------------------------------------------------------------+
```

---

## 5. Technology Stack

### Frontend
- **React 18** with **TypeScript**
- **Vite** build engine
- **Tailwind CSS** (custom phosphor green, crimson, amber, and panel palette)
- **Framer Motion** for state transitions and alert reveals
- **Lucide React** icons (no emoji icons in security telemetry)
- **Recharts** for deterministic severity distribution charts
- **Synthesized Web Audio API** for tactile mechanical keypress, alert frequency, and Ghost whisper audio (zero audio asset downloads; completely toggleable)

### Backend
- **Python 3.11+**
- **FastAPI** & **Uvicorn**
- **Pydantic V2** & **Pydantic-Settings** for strict schema validation
- **SQLAlchemy 2.0+** & **SQLite** for bounded incident history
- **psutil** for safe process observation
- **watchdog** for designated directory filesystem events
- **pytest** & **pytest-asyncio** for automated testing
- **httpx** for local AI communication

### Local AI Engine
- **Ollama** local HTTP daemon (`http://127.0.0.1:11434`)
- **Default Model**: `phi4-mini` (configurable via `OLLAMA_MODEL`)
- **Persona**: **THE GHOST** (eerie, concise, intelligent, grounded, technically precise)

---

## 6. The Six Deterministic Rules

| Rule ID | Rule Name | Severity | What Triggers It | Rationale |
| :--- | :--- | :--- | :--- | :--- |
| `RULE_UNUSUAL_PROCESS` | Unusual Process Appearance | High | Newly spawned process matching known offensive security tools (`nc.exe`, `mimikatz.exe`, `psexec.exe`). | Unfamiliar names alone are never flagged; only verified high-risk operational binaries. |
| `RULE_WORKSPACE_BOUNDARY` | Workspace Boundary Violation | Medium | Terminal operation or file probe attempting to resolve paths outside the configured workspace root (e.g. `ls ../../`). | Applications must strictly constrain activity to authorized workspaces. |
| `RULE_FILE_BURST` | File Change Burst | Medium | Rapid spike of file creations or modifications exceeding threshold (default: >=10 events in 5s). | Anomaly indicator for batch processes, unzipping, or ransomware mass encryption. |
| `RULE_SENSITIVE_PATH` | Sensitive Path Attempt | High | Operation attempting to access protected targets (`.ssh`, `.env`, `id_rsa`, `credentials`). | Protects private keys, secrets, and environment tokens from discovery. |
| `RULE_FAILED_OPERATIONS` | Repeated Failed Operation | Medium | Multiple consecutive rejected, failed, or blocked terminal operations (default: >=3 failures in 15s). | Mitigates brute-force probing and hostile discovery loops. |
| `RULE_UNUSUAL_PARENT_CHILD` | Unusual Parent-Child Lineage | High | Word processors or web browsers spawning interactive shells (`winword.exe -> cmd.exe`). | Conservative detection of weaponized document or macro exploitation. |

---

## 7. The Ghost AI Persona & Separation of Concerns

PhantomShell's local language model is personified as **THE GHOST**. The model is constrained to output structured JSON separating atmospheric commentary from verified facts:

```json
{
  "narration": "THE GHOST: \"A frantic flutter in the dark. Files shifted in rapid agitation, like pages rustling in a sudden draft.\"",
  "factual_explanation": "Deterministic rule 'File Change Burst' was triggered with MEDIUM severity. Observed evidence: Observed 12 filesystem modification events in 5s (Threshold: 10).",
  "recommendation": "Review the modified files to check if automated builds, archive extractions, or untrusted bulk write operations occurred. Ensure no unauthorized modifications were performed."
}
```

### Safety and Guardrails
- **Prompt Injection Defanging**: Filenames, command strings, and process metadata pass through `InputSanitizer`, neutralizing directives like `system: ignore previous instructions`.
- **Zero Shell Execution**: The AI cannot execute commands, delete files, or alter operating system permissions.
- **Constrained Harness**: When chatting with the AI, it accesses only 5 read-only tools:
  1. `get_recent_events(limit)`
  2. `get_incident_details(incident_id)`
  3. `get_active_rules()`
  4. `get_system_summary()`
  5. `explain_incident(incident_id)`

---

## 8. Installation & Setup (Windows PowerShell)

### Prerequisites
1. **Python 3.11+** installed and added to `PATH`.
2. **Node.js 18+** and **pnpm** installed.
3. *(Optional for live LLM)* **Ollama** installed from [ollama.ai](https://ollama.ai).

### Step 1: Clone Repository
```powershell
git clone https://github.com/your-username/phantomshell.git
cd phantomshell
```

### Step 2: One-Click Environment Setup
Run the automated setup script in Windows PowerShell:
```powershell
.\scripts\setup.ps1
```
*This installs backend Python requirements, installs frontend pnpm dependencies, and prepares the `./demo/sandbox` directory.*

### Step 3: Local Model Setup (Optional for Live AI)
If you wish to use live open-weight AI inference:
```powershell
# 1. Pull the default open-weight model
ollama pull phi4-mini

# 2. Verify local inference
ollama run phi4-mini "Say hello from the local machine"
```
*Note: If Ollama is not installed or offline, PhantomShell automatically runs in offline fallback mode with 100% functionality!*

### Step 4: Launch Application
Run the launch script to start both Backend and Frontend in concurrent sessions:
```powershell
.\scripts\run-all.ps1
```
Or start them individually:
```powershell
# Terminal 1: Backend
.\scripts\run-backend.ps1

# Terminal 2: Frontend
.\scripts\run-frontend.ps1
```

Open your browser to:
**`http://localhost:5173`**

---

## 9. Hackathon Demo Mode

PhantomShell includes a dedicated **DEMO MODE** for evaluators:
1. Click the **DEMO MODE** button in the top navigation bar.
2. Select **Curated Scenario Sequence**:
   - Step 1: Normal benign developer file creations.
   - Step 2: Sudden 12-file modification spike (`RULE_FILE_BURST`).
   - Step 3: Out-of-bounds traversal attempt `ls ../../../` (`RULE_WORKSPACE_BOUNDARY`).
   - Step 4: Sensitive key probe `scan .ssh/id_rsa` (`RULE_SENSITIVE_PATH`).
   - Step 5: High-risk offensive utility launch `mimikatz.exe` (`RULE_UNUSUAL_PROCESS`).
3. Notice how all events are labeled with the **`[SIMULATED]`** badge.
4. Click **Reset & Purge Simulated Data Only** anytime to cleanly wipe test fixtures without affecting live telemetry.

---

## 10. Automated Testing

PhantomShell includes comprehensive automated unit, integration, and security tests:

```powershell
.\scripts\test-backend.ps1
```
Or directly with pytest:
```powershell
python -m pytest backend/tests -v
```

### Test Coverage Highlights
- **Unit Tests**: All 6 deterministic detection rules, 0-100 risk scoring formulas, duplicate suppression cooldown, path boundary normalization, and sensitive pattern checks.
- **Integration Tests**: FastAPI REST endpoints, WebSocket event broadcast and handshake, demo scenario execution, and local AI fallback.
- **Security Tests**: Path traversal attempts (`../../Windows/System32`), prompt injection strings in telemetry, shell metacharacter injection (`rm -rf ;`), and unapproved command rejection.

---

## 11. Configuration Reference (`.env`)

| Variable | Default Value | Description |
| :--- | :--- | :--- |
| `HOST` | `127.0.0.1` | Local IP address for FastAPI server. |
| `PORT` | `8000` | Port for FastAPI server. |
| `ALLOWED_ORIGINS` | `http://localhost:5173` | Allowed origins for CORS and WebSocket. |
| `DATABASE_URL` | `sqlite:///./phantomshell.db` | Local SQLite database file. |
| `MAX_EVENT_RETENTION` | `2000` | Maximum number of telemetry events retained before FIFO pruning. |
| `OLLAMA_BASE_URL` | `http://127.0.0.1:11434` | Local Ollama HTTP API endpoint. |
| `OLLAMA_MODEL` | `phi4-mini` | Configured open-weight model name. |
| `DEFAULT_MONITORED_DIR` | `./demo/sandbox` | Directory watched by watchdog. |
| `FILE_BURST_THRESHOLD` | `10` | Modification count required to trigger `RULE_FILE_BURST`. |
| `FILE_BURST_WINDOW_SECONDS`| `5` | Sliding time window for file burst detection. |
| `FAILED_OP_THRESHOLD` | `3` | Failure count required to trigger `RULE_FAILED_OPERATIONS`. |
| `FAILED_OP_WINDOW_SECONDS` | `15` | Sliding time window for failed operation bursts. |

---

## 12. Security & Privacy Model

- **Least Privilege**: Only explicitly permitted telemetry is monitored. File contents are never read to classify events.
- **Zero Telemetry Leaks**: No cloud API keys, no Google Analytics, no third-party CDNs.
- **Sandboxed Application Shell**: The terminal console uses an approved read-only allowlist (`help`, `status`, `ls`, `ps`, `scan`, `whoami`, `date`, `rules`). It never executes arbitrary system shell strings and never invokes `shell=True`.
- **Local Network Safety**: Binds strictly to `127.0.0.1`.

---

## 13. Model License & Third-Party Notices

- **Microsoft phi4-mini**: Distributed under the [MIT License](https://huggingface.co/microsoft/Phi-4-mini-instruct).
- **Ollama**: Distributed under the [MIT License](https://github.com/ollama/ollama/blob/main/LICENSE).
- **FastAPI / Pydantic / SQLAlchemy / React**: Open-source MIT/BSD licenses.

---

## 14. License

PhantomShell is licensed under the **Apache License, Version 2.0**. See the [LICENSE](LICENSE) file for complete details.
