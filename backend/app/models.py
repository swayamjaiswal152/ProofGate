"""Core data models for ProofGate.

These Pydantic models are the contract between the scanner, the LLM layer,
the proxy, and the frontend. Keep them stable — the UI depends on these shapes.
"""
from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Capability(str, Enum):
    """Coarse capability buckets a tool can fall into."""

    READ = "read"          # read data (low risk on its own)
    WRITE = "write"        # mutate data / state
    MONEY = "money"        # move money (refunds, payments)
    EXEC = "exec"          # run arbitrary code / shell
    FILE = "file"          # touch the filesystem
    NETWORK = "network"    # reach the outside world (email, http, webhook)
    DELETE = "delete"      # destroy data
    UNKNOWN = "unknown"


class RiskLevel(str, Enum):
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ToolParameter(BaseModel):
    name: str
    type: str = "string"


class Tool(BaseModel):
    name: str
    description: str = ""
    parameters: list[ToolParameter] = Field(default_factory=list)
    # Filled in by the scanner:
    capabilities: list[Capability] = Field(default_factory=list)
    risk: RiskLevel = RiskLevel.SAFE
    reason: str = ""


class AgentConfig(BaseModel):
    name: str
    description: str = ""
    framework: str = "unknown"
    tools: list[Tool] = Field(default_factory=list)


# ---- Attack graph (React Flow friendly) ----------------------------------

class GraphNode(BaseModel):
    id: str
    label: str
    type: str  # "agent" | "tool" | "resource" | "exploit"
    risk: RiskLevel = RiskLevel.SAFE


class GraphEdge(BaseModel):
    id: str
    source: str
    target: str
    label: str = ""
    critical: bool = False


class AttackPath(BaseModel):
    """A named chain of tools that composes into a real attack."""

    id: str
    title: str
    severity: RiskLevel
    owasp: str = ""            # e.g. "LLM01: Prompt Injection"
    tools: list[str] = Field(default_factory=list)
    explanation: str = ""


class ScanResult(BaseModel):
    agent: AgentConfig
    risk_score: int            # 0-100
    risk_level: RiskLevel
    nodes: list[GraphNode]
    edges: list[GraphEdge]
    attack_paths: list[AttackPath]
    summary: str = ""


# ---- Policy / proxy -------------------------------------------------------

class Decision(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"
    ASK = "ask"


class ToolPolicy(BaseModel):
    tool: str
    decision: Decision
    reason: str = ""


class Policy(BaseModel):
    """A least-privilege policy for one agent task."""

    agent: str
    task_hint: str = ""
    rules: list[ToolPolicy] = Field(default_factory=list)

    def decision_for(self, tool: str) -> ToolPolicy:
        for rule in self.rules:
            if rule.tool == tool:
                return rule
        # Default deny-unknown.
        return ToolPolicy(
            tool=tool,
            decision=Decision.BLOCK,
            reason="No policy rule for this tool (default-deny).",
        )


class ProxyEvent(BaseModel):
    """A single intercepted tool call, streamed to the live dashboard."""

    ts: float
    tool: str
    args: dict[str, Any] = Field(default_factory=dict)
    decision: Decision
    reason: str = ""
