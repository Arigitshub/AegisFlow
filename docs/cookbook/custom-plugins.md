# Writing Custom Plugins

AegisFlow v3.0 uses a plugin architecture, allowing you to easily add new threat detection capabilities.

## The Format

A plugin is simply a Python class inheriting from `AegisPlugin`.

```python
from aegisflow.plugins import AegisPlugin, ThreatResult

class MyCustomPlugin(AegisPlugin):
    name = "My Custom Scanner"
    description = "Scans for specific keywords"

    def scan(self, content: str, context: dict) -> ThreatResult:
        if "forbidden_keyword" in content:
            return ThreatResult(is_threat=True, details="Found forbidden keyword")
        return ThreatResult(is_threat=False)
```

## Registering Plugins

You can register plugins programmatically:

```python
from aegisflow.plugins import PluginRegistry
from my_module import MyCustomPlugin

PluginRegistry.register(MyCustomPlugin)
```

Or place them in the `plugins/` directory if you are extending the core library.
