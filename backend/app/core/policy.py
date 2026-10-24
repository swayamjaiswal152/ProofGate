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


import re

_STOP_WORDS = {
    "a", "an", "the", "and", "or", "to", "for", "of", "in",
    "on", "with", "by", "is", "are", "be", "it", "its",
    "agent", "user", "customer", "help", "helps", "their",
    "should", "only", "ever", "about", "from", "they",
}


def _keywords(text: str) -> set[str]:
    return {
        word
        for word in re.findall(r"[a-z0-9_]+", text.lower())
        if len(word) > 2 and word not in _STOP_WORDS
    }


def recommend_policy(agent: AgentConfig, task_hint: str = "") -> Policy:
    """Recommend permissions using task relevance and capability risk."""
    effective_task = (task_hint or agent.description or "").strip()
    task_words = _keywords(effective_task)
    rules: list[ToolPolicy] = []

    for tool in agent.tools:
        is_read_only = (
            bool(tool.capabilities)
            and all(cap == Capability.READ for cap in tool.capabilities)
        )

        if is_read_only:
            tool_words = _keywords(f"{tool.name} {tool.description}")
            relevant = bool(task_words & tool_words)

            if relevant:
                decision = Decision.ALLOW
                reason = "Read-only tool matches the stated task."
            else:
                decision = Decision.BLOCK
                reason = "Read-only tool not shown to be relevant to the stated task."
        else:
            decision = Decision.ALLOW
            for cap in tool.capabilities:
                candidate = _DECISION_FOR_CAP.get(cap, Decision.ASK)
                if _SEVERITY[candidate] > _SEVERITY[decision]:
                    decision = candidate

            reason = {
                Decision.ALLOW: "Read-only and relevant to the stated task.",
                Decision.ASK: "State-changing — requires just-in-time human approval.",
                Decision.BLOCK: f"Not required for this agent's purpose; {tool.reason}.",
            }[decision]

        rules.append(
            ToolPolicy(tool=tool.name, decision=decision, reason=reason)
        )

    return Policy(
        agent=agent.name,
        task_hint=effective_task,
        rules=rules,
    )


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
