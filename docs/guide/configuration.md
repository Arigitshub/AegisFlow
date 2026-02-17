# Configuration

AegisFlow is configured via an `.aegis.yaml` or `.aegis.json` file in your project root or home directory (`~/.aegis.yaml`).

## Example Configuration

```yaml
# .aegis.yaml

# Paths that should never be touched by agents
protected_paths:
  - "/prod/db"
  - "./secrets"
  - "/etc/passwd"

# Fail fast on any violation
strict_mode: true

detector:
  use_ml: true
  ml_confidence_threshold: 0.90
  fallback_to_regex: true

sandwich:
  isolation_level: 1 # 0=None, 1=Env Filter, 2=Read-Only FS, 3=Docker
  auto_kill_timeout: 300 # Kill process after 5 minutes
  track_cost: true # Estimate token costs

sentinel:
  webhook_url: "https://hooks.slack.com/services/..."
  streak_threshold: 3
  persist_state: true
```

## Options Reference

### `protected_paths`

List of directories or files that are strictly off-limits. Any attempt to access these (e.g., via `cat`, `rm`, `ls`) will be blocked.

### `strict_mode`

If `true`, any detected threat (even Low confidence) will block the action. Default is `false` (blocks High/Medium, warns on Low).

### `detector`

- `use_ml`: Enable HuggingFace transformer models (requires `pip install "aegisflow[ml]"`).
- `ml_confidence_threshold`: Minimum probability (0.0-1.0) to flag as a threat.
- `fallback_to_regex`: Use regex if ML is unavailable or fails.

### `sandwich`

- `isolation_level`:
  - `0`: Monitor only.
  - `1`: Filter sensitive environment variables (API keys).
  - `2`: Read-only filesystem (best effort via platform-specific flags).
  - `3`: Docker container (requires Docker daemon).
- `auto_kill_timeout`: Seconds before forcefully terminating the process.
- `track_cost`: Estimate OpenAI-equivalent token costs for input/output.

### `sentinel`

- `webhook_url`: URL to POST JSON payload when a High-risk event occurs.
- `streak_threshold`: Number of consecutive Medium threats before escalating to High.
- `persist_state`: Save risk scores to disk across sessions.
