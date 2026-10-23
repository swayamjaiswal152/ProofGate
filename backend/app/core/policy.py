"""Policy recommender: turn a scan into a least-privilege JIT policy.

Deterministic + explainable. Given the agent's stated purpose, the safest tools
needed to do the job are ALLOWed, dangerous ones are BLOCKed, and ambiguous
state-changing ones require human approval (ASK).
"""
from __future__ import annotations

from ..models import (
    AgentConfig,
    Capability,
    Decision,
    Policy,
    ToolPolicy,
)

# Which capabilities get which default decision under least-privilege.
_DECISION_FOR_CAP: dict[Capability, Decision] = {
    Capability.READ: Decision.ALLOW,
    Capability.UNKNOWN: Decision.ASK,
    Capability.WRITE: Decision.ASK,
    Capability.MONEY: Decision.ASK,
    Capability.NETWORK: Decision.BLOCK,
    Capability.FILE: Decision.BLOCK,
    Capability.DELETE: Decision.BLOCK,
    Capability.EXEC: Decision.BLOCK,
}

_SEVERITY = {Decision.BLOCK: 2, Decision.ASK: 1, Decision.ALLOW: 0}


def recommend_policy(agent: AgentConfig, task_hint: str = "") -> Policy:
    """Produce a least-privilege policy for the given (already-classified) agent."""
    rules: list[ToolPolicy] = []
    for tool in agent.tools:
        # The most restrictive decision across the tool's capabilities wins.
        decision = Decision.ALLOW
        for cap in tool.capabilities:
            cand = _DECISION_FOR_CAP.get(cap, Decision.ASK)
            if _SEVERITY[cand] > _SEVERITY[decision]:
                decision = cand

        reason = {
            Decision.ALLOW: "Read-only and required for the agent's stated job.",
            Decision.ASK: "State-changing — requires just-in-time human approval.",
            Decision.BLOCK: f"Not required for this agent's purpose; {tool.reason}.",
        }[decision]

        rules.append(ToolPolicy(tool=tool.name, decision=decision, reason=reason))

    return Policy(agent=agent.name, task_hint=task_hint, rules=rules)


def policy_diff(agent: AgentConfig, policy: Policy) -> list[dict]:
    """Human-readable before/after of what hardening changed, for the UI."""
    out = []
    for tool in agent.tools:
        rule = policy.decision_for(tool.name)
        before = "ALLOW (always)"
        after = rule.decision.value.upper()
        changed = rule.decision != Decision.ALLOW
        out.append(
            {
                "tool": tool.name,
                "risk": tool.risk.value,
                "before": before,
                "after": after,
                "changed": changed,
                "reason": rule.reason,
            }
        )
    return out
