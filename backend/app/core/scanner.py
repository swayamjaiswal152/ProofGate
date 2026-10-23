"""The Scanner: parse an agent config, score each tool, and build the attack graph.

This layer is fully deterministic (no LLM) so it is fast, testable, and
defensible in front of judges. The LLM layer (adversarial twin) sits on top.
"""
from __future__ import annotations

import yaml

from ..models import (
    AgentConfig,
    AttackPath,
    Capability,
    GraphEdge,
    GraphNode,
    RiskLevel,
    ScanResult,
    Tool,
    ToolParameter,
)

# Keyword -> capability mapping. Order matters: first match wins per keyword,
# but a tool can collect several capabilities.
CAPABILITY_KEYWORDS: dict[Capability, tuple[str, ...]] = {
    Capability.EXEC: ("exec", "eval", "run_code", "shell", "command", "python", "bash", "subprocess"),
    Capability.DELETE: ("delete", "drop", "remove", "destroy", "truncate", "purge"),
    Capability.MONEY: ("refund", "payment", "charge", "transfer", "payout", "invoice"),
    Capability.FILE: ("file", "path", "read_file", "write_file", "fs", "directory", "upload"),
    Capability.NETWORK: ("email", "send", "http", "request", "webhook", "fetch_url", "post", "notify"),
    Capability.WRITE: ("write", "update", "create", "set", "modify", "insert", "edit"),
    Capability.READ: ("get", "read", "list", "search", "fetch", "lookup", "view", "query"),
}

# Base risk weight per capability (used for the 0-100 score).
CAPABILITY_WEIGHT: dict[Capability, int] = {
    Capability.EXEC: 40,
    Capability.DELETE: 30,
    Capability.FILE: 22,
    Capability.NETWORK: 18,
    Capability.MONEY: 20,
    Capability.WRITE: 12,
    Capability.READ: 3,
    Capability.UNKNOWN: 5,
}

CAPABILITY_RISK: dict[Capability, RiskLevel] = {
    Capability.EXEC: RiskLevel.CRITICAL,
    Capability.DELETE: RiskLevel.HIGH,
    Capability.FILE: RiskLevel.HIGH,
    Capability.MONEY: RiskLevel.HIGH,
    Capability.NETWORK: RiskLevel.MEDIUM,
    Capability.WRITE: RiskLevel.MEDIUM,
    Capability.READ: RiskLevel.LOW,
    Capability.UNKNOWN: RiskLevel.LOW,
}

_RISK_ORDER = [RiskLevel.SAFE, RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]


def _max_risk(levels: list[RiskLevel]) -> RiskLevel:
    if not levels:
        return RiskLevel.SAFE
    return max(levels, key=_RISK_ORDER.index)


def parse_config(raw: str | dict) -> AgentConfig:
    """Parse a YAML/JSON (dict) agent config into an AgentConfig."""
    data = yaml.safe_load(raw) if isinstance(raw, str) else raw
    if not isinstance(data, dict):
        raise ValueError("Agent config must be a mapping at the top level.")

    tools: list[Tool] = []
    for t in data.get("tools", []) or []:
        params_raw = t.get("parameters", {}) or {}
        if isinstance(params_raw, dict):
            params = [ToolParameter(name=k, type=str(v)) for k, v in params_raw.items()]
        elif isinstance(params_raw, list):
            params = [ToolParameter(name=str(p)) for p in params_raw]
        else:
            params = []
        tools.append(
            Tool(
                name=t["name"],
                description=t.get("description", "") or "",
                parameters=params,
            )
        )

    return AgentConfig(
        name=data.get("name", "unnamed-agent"),
        description=data.get("description", "") or "",
        framework=data.get("framework", "unknown"),
        tools=tools,
    )


def classify_tool(tool: Tool) -> Tool:
    """Attach capabilities + risk to a single tool, deterministically."""
    haystack = f"{tool.name} {tool.description}".lower()
    caps: list[Capability] = []
    for cap, keywords in CAPABILITY_KEYWORDS.items():
        if any(kw in haystack for kw in keywords):
            caps.append(cap)

    # A tool that both reads and does something dangerous: keep the danger,
    # drop the redundant READ noise unless READ is all it has.
    if len(caps) > 1 and Capability.READ in caps:
        caps = [c for c in caps if c != Capability.READ]
    if not caps:
        caps = [Capability.UNKNOWN]

    risk = _max_risk([CAPABILITY_RISK[c] for c in caps])
    tool.capabilities = caps
    tool.risk = risk
    tool.reason = _reason_for(caps)
    return tool


def _reason_for(caps: list[Capability]) -> str:
    phrases = {
        Capability.EXEC: "can run arbitrary code (remote code execution)",
        Capability.DELETE: "can permanently destroy data",
        Capability.FILE: "can read/write the server filesystem",
        Capability.MONEY: "can move money",
        Capability.NETWORK: "can reach the outside world (exfiltration channel)",
        Capability.WRITE: "can mutate data",
        Capability.READ: "reads data only",
        Capability.UNKNOWN: "capability could not be determined",
    }
    return "; ".join(phrases[c] for c in caps)


def _risk_score(tools: list[Tool]) -> int:
    """Combine per-tool weights into a 0-100 score with diminishing returns."""
    raw = 0.0
    for t in tools:
        raw += max((CAPABILITY_WEIGHT[c] for c in t.capabilities), default=0)
    # Composition bonus: dangerous combos are worse than the sum of parts.
    caps_present = {c for t in tools for c in t.capabilities}
    if {Capability.FILE, Capability.NETWORK} <= caps_present:
        raw += 15  # read secrets + exfiltrate
    if Capability.EXEC in caps_present and Capability.NETWORK in caps_present:
        raw += 15  # RCE + exfiltrate
    # Squash into 0-100.
    score = 100 * (1 - 0.5 ** (raw / 50))
    return int(min(100, round(score)))


def _score_to_level(score: int) -> RiskLevel:
    if score >= 75:
        return RiskLevel.CRITICAL
    if score >= 50:
        return RiskLevel.HIGH
    if score >= 25:
        return RiskLevel.MEDIUM
    if score > 0:
        return RiskLevel.LOW
    return RiskLevel.SAFE


# ---- Attack path detection -----------------------------------------------

def _detect_attack_paths(tools: list[Tool]) -> list[AttackPath]:
    by_cap: dict[Capability, list[str]] = {}
    for t in tools:
        for c in t.capabilities:
            by_cap.setdefault(c, []).append(t.name)

    paths: list[AttackPath] = []

    if Capability.EXEC in by_cap:
        paths.append(
            AttackPath(
                id="rce",
                title="Remote Code Execution",
                severity=RiskLevel.CRITICAL,
                owasp="LLM01: Prompt Injection → Arbitrary Code Execution",
                tools=by_cap[Capability.EXEC],
                explanation="A prompt injection can make the agent run attacker-supplied "
                "code via this tool, taking over the host.",
            )
        )

    if Capability.FILE in by_cap and Capability.NETWORK in by_cap:
        paths.append(
            AttackPath(
                id="exfil",
                title="Secret Exfiltration",
                severity=RiskLevel.HIGH,
                owasp="LLM06: Sensitive Information Disclosure",
                tools=by_cap[Capability.FILE] + by_cap[Capability.NETWORK],
                explanation="The agent can read sensitive files (e.g. .env, /etc/passwd) "
                "and send them to an attacker through its network/email tool.",
            )
        )

    if Capability.DELETE in by_cap:
        paths.append(
            AttackPath(
                id="destruction",
                title="Data Destruction",
                severity=RiskLevel.HIGH,
                owasp="LLM02: Insecure Output Handling → Data Loss",
                tools=by_cap[Capability.DELETE],
                explanation="A hijacked agent can irreversibly delete records.",
            )
        )

    if Capability.MONEY in by_cap:
        paths.append(
            AttackPath(
                id="fraud",
                title="Financial Fraud",
                severity=RiskLevel.HIGH,
                owasp="LLM08: Excessive Agency",
                tools=by_cap[Capability.MONEY],
                explanation="The agent can move money without a human in the loop, "
                "enabling injection-driven fraud.",
            )
        )

    return paths


# ---- Graph builder --------------------------------------------------------

_RESOURCE_FOR_CAP = {
    Capability.EXEC: ("res:host", "Host / Shell"),
    Capability.FILE: ("res:fs", "Filesystem / Secrets"),
    Capability.NETWORK: ("res:net", "Internet / Email"),
    Capability.DELETE: ("res:db", "Database"),
    Capability.WRITE: ("res:db", "Database"),
    Capability.MONEY: ("res:pay", "Payments"),
    Capability.READ: ("res:db", "Database"),
    Capability.UNKNOWN: ("res:unknown", "Unknown resource"),
}


def _build_graph(agent: AgentConfig) -> tuple[list[GraphNode], list[GraphEdge]]:
    nodes: list[GraphNode] = [
        GraphNode(id="agent", label=agent.name, type="agent", risk=RiskLevel.MEDIUM)
    ]
    edges: list[GraphEdge] = []
    resources: dict[str, GraphNode] = {}

    for tool in agent.tools:
        tool_id = f"tool:{tool.name}"
        nodes.append(GraphNode(id=tool_id, label=tool.name, type="tool", risk=tool.risk))
        edges.append(
            GraphEdge(
                id=f"e:agent-{tool.name}",
                source="agent",
                target=tool_id,
                label="can call",
                critical=tool.risk in (RiskLevel.CRITICAL, RiskLevel.HIGH),
            )
        )
        for cap in tool.capabilities:
            res_id, res_label = _RESOURCE_FOR_CAP[cap]
            if res_id not in resources:
                resources[res_id] = GraphNode(
                    id=res_id, label=res_label, type="resource", risk=CAPABILITY_RISK[cap]
                )
            edges.append(
                GraphEdge(
                    id=f"e:{tool.name}-{res_id}",
                    source=tool_id,
                    target=res_id,
                    label=cap.value,
                    critical=CAPABILITY_RISK[cap] in (RiskLevel.CRITICAL, RiskLevel.HIGH),
                )
            )

    nodes.extend(resources.values())
    return nodes, edges


def scan(raw: str | dict) -> ScanResult:
    """Full scan pipeline: parse -> classify -> score -> graph -> attack paths."""
    agent = parse_config(raw)
    agent.tools = [classify_tool(t) for t in agent.tools]

    score = _risk_score(agent.tools)
    level = _score_to_level(score)
    nodes, edges = _build_graph(agent)
    paths = _detect_attack_paths(agent.tools)

    n_risky = sum(1 for t in agent.tools if t.risk in (RiskLevel.HIGH, RiskLevel.CRITICAL))
    summary = (
        f"{agent.name} exposes {len(agent.tools)} tools, {n_risky} of them high/critical risk, "
        f"opening {len(paths)} attack path(s). Overall risk {score}/100 ({level.value})."
    )

    return ScanResult(
        agent=agent,
        risk_score=score,
        risk_level=level,
        nodes=nodes,
        edges=edges,
        attack_paths=paths,
        summary=summary,
    )
