# AegisFlow v2.0 - Governance Layer for AI Agents

AegisFlow is a sophisticated **Security Liaison** designed to govern AI agent actions through transparent mediation rather than silent blocking. It acts as a "conscious" layer, ensuring high-risk operations are verified by a human-in-the-loop (HITL).

## Core Philosophy

- **Suspicion Scoring**: Every action is assigned a Threat Level (Low, Medium, High).
- **Transparent Mediation**: Risks are reported clearly; high risks require explicit approval.
- **Sentinel State Engine**: Tracks reputation and persists logs.
- **Audit Trail**: All decisions and outcomes are logged to `~/.aegis/logs/aegis_audit.json`.

## Installation

```bash
pip install .
```

This installs the `aegis` CLI tool globally.

## Usage

### Command Line Interface

Scan a file for behavioral redlines:

```bash
aegis scan path/to/script.py
```

Start an interactive protected shell (concept):

```bash
aegis protect
```

View Security Report:

```bash
aegis report
```

Check for Updates:

```bash
aegis update
```

### Python Library

Wrap your agent's critical functions with AegisFlow:

```python
from aegisflow import SecurityLiaison

liaison = SecurityLiaison()

def dangerous_operation():
    # ... code that deletes files ...
    pass

# Will prompt user if risk is High
liaison.mediate("file_op", {"path": "/etc/passwd"}, dangerous_operation)
```

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
