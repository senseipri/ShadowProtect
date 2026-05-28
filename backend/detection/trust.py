from typing import Any

ALERT_PENALTIES = {
    "INJECTION": 40,
    "COLLUSION": 25,
    "ANOMALY": 15,
    "ESCALATION": 30,
}


def calculate_trust(agent_id: str, recent_alerts: list[dict[str, Any]] | list[str]) -> int:
    _ = agent_id  # Reserved for future agent-specific trust policy.
    score = 100

    for alert in recent_alerts:
        if isinstance(alert, str):
            kind = alert.upper()
        elif isinstance(alert, dict):
            kind = str(alert.get("kind", alert.get("type", ""))).upper()
        else:
            kind = ""

        score -= ALERT_PENALTIES.get(kind, 0)

    return max(0, min(100, int(score)))


def get_risk_label(score: int) -> str:
    value = int(score)
    if value < 20:
        return "CRITICAL"
    if value < 40:
        return "HIGH"
    if value < 70:
        return "MEDIUM"
    return "LOW"
