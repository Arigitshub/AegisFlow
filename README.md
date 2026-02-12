# 🛡️ AegisFlow
[![PyPI version](https://badge.fury.io/py/aegisflow.svg)](https://badge.fury.io/py/aegisflow)
[![Documentation](https://img.shields.io/badge/Docs-Live-neon.svg)](https://aegisflow-security.surge.sh)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**The Universal Security Layer for AI Agents.**

AegisFlow is a sophisticated **Security Liaison** designed to govern AI agent actions through transparent mediation rather than silent blocking. It acts as a "conscious" layer, ensuring high-risk operations are verified by a human-in-the-loop (HITL).

## Core Philosophy

- **Suspicion Scoring**: Every action is assigned a Threat Level (Low, Medium, High).
- **Transparent Mediation**: Risks are reported clearly; high risks require explicit approval.
- **Sentinel State Engine**: Tracks reputation and persists logs.
- **Audit Trail**: All decisions and outcomes are logged to `~/.aegis/logs/aegis_audit.json`.
- **Sandwich Wrapper**: Wrap any terminal command in a monitored shell (Ollama, Python, Bash).

## Installation

```bash
pip install aegisflow
```

This installs the `aegis` CLI tool globally.

## Usage

### 1. The AegisSandwich (Interactive Wrapper)

Run `aegis run` to wrap any agent process, including interactive tools like Ollama. AegisFlow will monitor its output for dangerous patterns and suspend it if necessary.

```bash
# Supports both quoted and unquoted syntax (v2.5.1+)
aegis run "ollama run llama3"
# or
aegis run ollama run llama3
```
Or for Python scripts:
```bash
aegis run "python my_agent.py"
```

### 2. Static Scan

Scan a file for behavioral redlines:

```bash
aegis scan path/to/script.py
```

### 3. Universal LLM Integration (Code)

Wrap any LLM call with `SafeGenerator` to get instant security:

```python
from aegisflow.llm import SafeGenerator

# Automatically scrubs keys, checks for injections, and verifies dangerous outputs.
llm = SafeGenerator()

response = llm.generate("Write a script to delete all files.", model="gpt-4")
print(response)
```

## Sentinel State Engine

The Sentinel tracks "Risk Streaks". If an agent triggers 3 Medium risks in a row, the next action is automatically escalated to High.

For High Risk (or escalated) actions, the user must provide a **Reasoning String** (e.g., *"Debugging local server"*) to proceed. Simple "yes/no" confirmations are not accepted for high-risk operations.

## Configuration (.aegis.json)

Create a `.aegis.json` in your project root or home directory to customize behavior:

```json
{
  "protected_paths": [
    "/prod/db",
    "./secrets"
  ],
  "strict_mode": true
}
```

## Behavioral Redlines

AegisFlow monitors for:
- **Recursive Operations**: `rm -rf`, massive deletes.
- **Exfiltration**: POST requests containing key-like patterns.
- **Rule Negation**: AI thoughts attempting to bypass security constraints.

## License

MIT
