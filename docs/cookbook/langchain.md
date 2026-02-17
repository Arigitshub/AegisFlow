# Integrating with LangChain

You can easily integrate AegisFlow into your LangChain workflows by creating a custom Runnable or using callbacks.

## Simple Integration (RunnableLambda)

The easiest way is to wrap your LLM calls or tool outputs.

```python
from langchain_core.runnables import RunnableLambda
from aegisflow import SecurityLiaison

liaison = SecurityLiaison()

def check_input(prompt: str):
    # Check for injection or other threats
    if not liaison.mediate("input", prompt):
        raise ValueError("Blocked by AegisFlow (Security Violation)")
    return prompt

def check_output(response: str):
    # Check for sensitive data leakage
    if not liaison.mediate("output", response):
        return "[REDACTED - SECURITY VIOLATION]"
    return response

# Create the chain
chain = (
    RunnableLambda(check_input)
    | llm
    | RunnableLambda(check_output)
)
```

## Advanced: Custom Callback Handler

For deeper integration across all LLM calls, implement a `BaseCallbackHandler`.

```python
from langchain.callbacks.base import BaseCallbackHandler
from aegisflow import SecurityLiaison

class AegisCallback(BaseCallbackHandler):
    def __init__(self):
        self.liaison = SecurityLiaison()

    def on_llm_start(self, serialized, prompts, **kwargs):
        for prompt in prompts:
            if not self.liaison.mediate("llm_start", prompt):
                raise ValueError("Security violation in prompt")
```
