# 🛡️ AegisFlow
[![PyPI version](https://badge.fury.io/py/aegisflow.svg)](https://badge.fury.io/py/aegisflow)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**The Universal Security Layer for AI Agents.**

AegisFlow is a CPU-efficient Python library that sits between your LLM and your system. It prevents prompt injections, scrubs sensitive data (API keys/PII), and enforces a "Human-in-the-Loop" protocol for high-risk operations.

<div align="center">
  <img src="https://via.placeholder.com/800x400?text=AegisFlow+Security+Dashboard" alt="AegisFlow Dashboard">
</div>

## ✨ Features

- **Sentinel State Engine**: Tracks agent behavior over time and escalates threats based on "risk streaks."
- **Behavioral Redlines**: Detects recursive deletions (`rm -rf`), unauthorized POST requests, and security bypass attempts.
- **Key Scrubber**: Automatically redacts API keys and EMV data before they leak to the LLM.
- **Human-in-the-Loop**: Requires a "Reasoning String" justification for any high-risk system commands.
- **Universal Provider**: Seamlessly wrap OpenAI, Anthropic, Gemini, and more via `SafeGenerator`.

## 🚀 Quick Start

```bash
pip install aegisflow
```

Scan your agent scripts for vulnerabilities:

```bash
aegis scan my_agent_script.py
```

### Universal LLM Integration

Wrap any LLM call with `SafeGenerator` to get instant security:

```python
from aegisflow.llm import SafeGenerator

# Automatically scrubs keys, checks for injections, and verifies dangerous outputs.
llm = SafeGenerator()

response = llm.generate("Write a script to delete all files.", model="gpt-4")
print(response)
```

## 🏗️ Architecture

AegisFlow operates as a lightweight governance layer. It intercepts function calls and network requests, assigning a **Threat Level** (Low, Medium, High) to each action.

- **Low Risk**: Allowed and logged.
- **Medium Risk**: Warned and logged; contributes to a "Risk Streak."
- **High Risk**: Blocked unless the user provides a valid **Reasoning String**.

## 📊 Sentinel Reports

View your security audit logs in a professional terminal dashboard:

```bash
aegis report
```

Example Output:
```text
+-----------------------------------------------------------------------------+
| Timestamp                | Level  | Action      | Outcome     | Details     |
|--------------------------+--------+-------------+-------------+-------------|
| 2026-02-10T12:34:07-0500 | Low    | safe_op     | EXECUTED    | {'content': |
| 2026-02-10T23:03:31-0500 | High   | file_op     | USER_OVERR | {'path':    |
|                          |        |             |             | '/etc/shad |
+-----------------------------------------------------------------------------+
```

## 📦 Installation & Setup

1.  **Install via Pip**:
    ```bash
    pip install aegisflow
    ```
2.  **Initialize Configuration** (Optional):
    Create a `.aegis.json` in your project root:
    ```json
    {
      "protected_paths": ["/prod/db", "./secrets"],
      "strict_mode": true
    }
    ```

## 🤝 Universal AI Integration

AegisFlow uses `LiteLLM` under the hood to support 100+ LLM providers. Just pass the model name (e.g., `claude-3-opus`, `gemini-pro`) to `generate()`.

## License

MIT
