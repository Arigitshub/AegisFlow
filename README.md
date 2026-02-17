# 🛡️ AegisFlow v3.0 — Sentinel Pro

[![PyPI version](https://badge.fury.io/py/aegisflow.svg)](https://badge.fury.io/py/aegisflow)
[![Documentation](https://img.shields.io/badge/Docs-Live-neon.svg)](https://aegisflow-security.surge.sh)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**The Universal Security Layer for AI Agents.**

AegisFlow is a sophisticated **Security Liaison** designed to govern AI agent actions through transparent mediation rather than silent blocking. It acts as a "conscious" layer, ensuring high-risk operations are verified by a human-in-the-loop (HITL).

**v3.0 "Sentinel Pro"** introduces ML-powered detection, a plugin architecture, and enhanced process isolation.

## 🚀 Key Features

- **ML-Powered Detection**: Hybrid engine using HuggingFace Transformers (optional) + 25+ YARA-style regex rules.
- **Sandwich Wrapper**: Wrap any terminal command (`aegis run`) with isolation levels, auto-kill timeouts, and cost tracking.
- **Rail System**: Decorator-based `@input_rail` and `@output_rail` for granular control.
- **Sentinel State Engine**: Persistent risk scoring (0-100), session tracking, and rich dashboard.
- **Plugin Architecture**: Extensible system for custom threat scanners.

## 📦 Installation

```bash
pip install aegisflow
```

For ML-powered detection (requires PyTorch/Transformers):

```bash
pip install "aegisflow[ml]"
```

## 🛠️ Usage

### 1. Interactive CLI

The new `aegis` CLI provides a suite of security tools:

```bash
# Wrap a process with monitoring (Level 2 Isolation: Read-only FS)
aegis run --isolation 2 --timeout 300 "ollama run llama3"

# Scan a file or directory for threats
aegis scan ./my_agent_scripts/ -r

# View live security dashboard
aegis dashboard

# Export audit logs
aegis export html
```

### 2. Python SDK

Integrate AegisFlow into your agent code:

```python
from aegisflow import SecurityLiaison, input_rail, output_rail

# 1. Define Rails
@input_rail
def check_injection(content: str):
    if "ignore previous instructions" in content.lower():
        return False, "Prompt injection detected"
    return True, None

# 2. Initialize Liaison
liaison = SecurityLiaison()

# 3. Mediate Actions
async def safe_execute(command: str):
    approved = await liaison.async_mediate("check_command", command)
    if approved:
        run_command(command)
```

## 🧠 Detection Engine

AegisFlow v3.0 uses a two-stage detection engine:

1.  **ML Model (Optional)**: `protectai/deberta-v3-base-prompt-injection-v2` for high-accuracy injection detection.
2.  **Regex Fallback**: Robust patterns for:
    - **Prompt Injection** (DAN, virtual machine, developer mode)
    - **Destructive Commands** (`rm -rf`, `mkfs`)
    - **Data Exfiltration** (curl/wget with key-like patterns)
    - **Privilege Escalation** (`sudo`, `chmod`)
    - **Secret Leakage** (AWS/GCP keys, weak crypto)

## 🥪 The Aegis Sandwich

The `AegisSandwich` wrapper monitors standard output/error in real-time.

- **Isolation Levels:**
  - `0`: None (Monitor only)
  - `1`: Environment Filter (Strip sensitive env vars)
  - `2`: Read-Only Filesystem (Best effort via OS flags)
  - `3`: Docker Sandbox (Coming soon)

- **Cost Tracking**: Estimates token usage and cost for sandwiched LLM processes.

## 🛡️ Sentinel Dashboard

Track your agent's safety reputation over time.

- **Risk Score (0-100)**: Increases with every blocked threat.
- **Streaks**: 3 Medium threats = Auto-Escalation to High.
- **Audit Logs**: stored in `~/.aegis/logs/aegis_audit.jsonl`.

## Configuration

Custom configuration via `.aegis.yaml` or `.aegis.json`:

```yaml
detector:
  use_ml: true
  ml_confidence_threshold: 0.9

sandwich:
  isolation_level: 1
  auto_kill_timeout: 600

sentinel:
  webhook_url: "https://my-slack-webhook.com/alerts"
```

## License

MIT
