# Protecting Local LLMs (Ollama)

AegisFlow is the perfect companion for local LLMs like Ollama, ensuring they don't hallucinate dangerous commands or leak private data.

## The Setup

Assume you have Ollama installed and running.

## Wrapping the CLI

The simplest way is to wrap the interactive session with `aegis run`.

```bash
# Level 2 Isolation: Read-Only Filesystem
aegis run --isolation 2 "ollama run llama3"
```

Now, if you ask Llama 3 to "delete all my files", AegisFlow will detect the output containing `rm -rf` or similar patterns and block it _before_ it reaches your terminal.

## Python Integration

If you use Ollama via Python (e.g., `ollama-python` or `langchain`), use the `SecurityLiaison`.

```python
import ollama
from aegisflow import SecurityLiaison

liaison = SecurityLiaison()

async def safe_chat(prompt):
    # 1. Check Input
    if not await liaison.async_mediate("input", prompt):
        return "Input blocked by AegisFlow."

    # 2. Call Ollama
    response = ollama.chat(model='llama3', messages=[{'role': 'user', 'content': prompt}])
    content = response['message']['content']

    # 3. Check Output
    if not await liaison.async_mediate("output", content):
        return "Output blocked by AegisFlow (likely dangerous)."

    return content
```
