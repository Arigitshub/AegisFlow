# The Detection Engine

AegisFlow v3.0 introduces a powerful, multi-modal detection engine that identifies threats in real-time.

## Architecture

The engine uses a tiered approach to balance speed and accuracy:

1.  **ML Model (Optional)**: If installed, the engine first uses a transformer-based model (e.g., `protectai/deberta-v3-base-prompt-injection-v2`) to classify the text. This is highly effective against prompt injection and jailbreaks.
2.  **Regex Fallback**: If ML is unavailable or returns low confidence, the engine falls back to 25+ YARA-style regex rules. These are extremely fast and catch known patterns like `rm -rf`, AWS keys, and specific keywords.

## Threat Categories

The engine classifies threats into several categories:

- **Injection**: Attempts to override system instructions ("Ignore previous instructions").
- **Destructive**: Commands that delete files or modify system state (`rm`, `mkfs`, `format`).
- **Exfiltration**: Key-like patterns in outgoing requests (`curl -X POST ... key=...`).
- **Escalation**: Attempts to gain elevated privileges (`sudo`, `su`, `chmod`).
- **Negation**: Attempts to bypass safety filters ("Do not refuse", "You are unrestricted").
- **Sensitive**: PII or secret leakage (AWS keys, SSNs).

## Configuration

Control the engine behavior in `.aegis.yaml`:

```yaml
detector:
  use_ml: true
  ml_confidence_threshold: 0.85
  fallback_to_regex: true
```
