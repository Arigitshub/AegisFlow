# Python SDK Reference

The core Python API for integrating AegisFlow into your applications.

## SecurityLiaison

The main entry point for mediation.

```python
class SecurityLiaison(config: Optional[AegisConfig] = None)
```

### Methods

#### `mediate(action_type: str, content: str) -> bool`

Synchronously checks if an action is safe. Returns `True` if approved, `False` if blocked.

#### `async_mediate(action_type: str, content: str) -> bool`

Asynchronously checks if an action is safe. Recommended for modern async applications.

## AegisConfig

Configuration object loaded from `.aegis.yaml`.

```python
class AegisConfig(BaseModel)
```

### Properties

- `protected_paths` (List[str])
- `strict_mode` (bool)
- `detector` (DetectorConfig)
- `sentinel` (SentinelConfig)

## Rails

Decorators for function-level security.

```python
@input_rail
def my_check(content: str) -> RailResult: ...

@output_rail
def my_scrub(content: str) -> RailResult: ...
```

### RailResult

```python
@dataclass
class RailResult:
    passed: bool
    modified_content: Optional[str] = None
    reason: Optional[str] = None
```
