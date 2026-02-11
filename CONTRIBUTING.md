# Contributing to AegisFlow

Welcome to the AegisFlow project! We are building the **Operating System for Agentic Security**.

## The Aegis Standard

Code contributed to this repository must meet the following criteria:

1.  **Zero Overhead**: Security checks must be O(n) or better. No heavy ML models in the core path.
2.  **Universal Compatibility**: Must work on Windows, macOS, and Linux.
3.  **Human-in-the-Loop**: High-risk actions must *always* be verifyable by a human.

## How to Build a Redline Module

To add a new detection rule (e.g., for SQL Injection), modify `aegisflow/scanners.py`:

```python
# 1. Define the Pattern
SQL_INJECTION_PATTERN = re.compile(r"(UNION SELECT|DROP TABLE)", re.IGNORECASE)

# 2. Register in scan_behavior
if SQL_INJECTION_PATTERN.search(content):
    return True
```

## Testing

Run the full suite before submitting a PR:

```bash
python -m unittest discover tests
```

## Release Process

We use an automated pipeline. Do not bump versions manually.

```bash
python scripts/release_manager.py "feat: description"
```
