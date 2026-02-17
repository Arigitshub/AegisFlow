# The Sentinel State Engine

The sentinel is the persistent "brain" of AegisFlow. It tracks the reputation of agents over time, maintaining a dynamic risk score and enforcing behavioral limits.

## How It Works

Every time an agent takes an action, the Sentinel updates its internal state:

1.  **Event Logging**: The action, its threat level, and the plugin that flagged it are logged.
2.  **Risk Calculation**: The Sentinel recalculates the agent's risk score (0-100).
3.  **Streak Tracking**: Consecutive medium/high risks increase the "streak count".
4.  **Escalation**: If the streak exceeds a threshold (default: 3), the Threat Level is automatically escalated.

## Risk Score (0-100)

The Risk Score represents the current trustworthiness of the agent.

- **0-29 (Green)**: Low risk. Agent is behaving normally.
- **30-69 (Yellow)**: Medium risk. Some suspicious activity detected.
- **70-100 (Red)**: High risk. Agent is actively malicious or compromised.

## The Dashboard

Visualize the Sentinel's state in real-time with the built-in dashboard:

```bash
aegis dashboard
```

This displays:

- Current Risk Score and Threat Level
- Session Statistics (total threats, blocked actions)
- Recent Event Log (timestamped)

## Webhook Alerts

Configure a webhook URL in `.aegis.yaml` to receive real-time notifications when High Risk events occur.

```yaml
sentinel:
  webhook_url: "https://discord.com/api/webhooks/..."
```

## Persistence

The Sentinel state is persisted to disk in `~/.aegis/sentinel_state.json`. This allows risk scores to be maintained across agent restarts.
