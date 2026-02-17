# The Rail System

The Rail System allows you to define granular guardrails for your agent's input and output.

## How It Works

Rails are Python functions decorated with `@input_rail` or `@output_rail`. They run before or after the agent's core logic.

Each rail function receives the `content` (string) and must return a `RailResult` (or `(bool, str)` tuple).

## Basic Usage

```python
from aegisflow import input_rail, output_rail, RailResult

@input_rail
def check_injection(content: str) -> RailResult:
    if "ignore previous" in content.lower():
        return RailResult(passed=False, reason="Prompt injection detected")
    return RailResult(passed=True)

@output_rail
def scrub_pii(content: str) -> RailResult:
    # Modify the content if needed
    cleaned = content.replace("my_secret_key", "[REDACTED]")
    return RailResult(passed=True, modified_content=cleaned)
```

## Advanced Usage: Rail Chains

You can chain multiple rails together using `RailChain`.

```python
from aegisflow import RailChain

input_chain = RailChain([check_injection, check_profanity])
output_chain = RailChain([scrub_pii, ensure_json_format])

# Run the chain manually
result = input_chain.execute(user_input)
if not result.passed:
    print(f"Blocked: {result.reason}")
```

## Integration with SecurityLiaison

The `SecurityLiaison` automatically executes configured rail chains during mediation.

```python
liaison = SecurityLiaison(input_rails=input_chain, output_rails=output_chain)
```
