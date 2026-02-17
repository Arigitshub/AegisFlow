# The Aegis Sandwich

The **AegisSandwich** is a process wrapper that monitors the input, output, and error streams of any command in real-time. It acts as a bidirectional security layer between the agent and the operating system.

## How It Works

When you run `aegis run "my_command"`, AegisFlow:

1.  **Spawns** the command as a subprocess.
2.  **Intercepts** standard input (STDIN), output (STDOUT), and error (STDERR).
3.  **Analyzes** the streams using the Detection Engine in real-time.
4.  **Intervenes** (suspends/kills) if a threat is detected.

## Isolation Levels

You can control the level of isolation for the wrapped process:

### Level 0: Monitor Only (Default)

Standard execution. AegisFlow monitors output but does not restrict the environment.

### Level 1: Environment Filter

Strips sensitive environment variables (e.g., `AWS_ACCESS_KEY_ID`, `OPENAI_API_KEY`) from the process, preventing accidental leakage.

### Level 2: Read-Only Filesystem (Best Effort)

Attempts to run the process with read-only access to the filesystem using platform-specific flags. This prevents malware from modifying system files or installing persistence.

### Level 3: Docker Sandbox

**Planned**: Runs the command inside an ephemeral Docker container for maximum isolation.

## Auto-Kill Timeout

Configure a maximum runtime for the process. If it exceeds the limit, AegisFlow forcefully terminates it.

```bash
aegis run --timeout 60 "python long_running_script.py"
```

## Cost Tracking

Enable token cost estimation for LLM interactions within the sandwiched process. This helps monitor usage and potential runaway costs.

```bash
aegis run --cost "ollama run llama3"
```
