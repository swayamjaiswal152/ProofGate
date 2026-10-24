
from app.core.scanner import scan
from app.core.policy import recommend_policy
from app.models import Decision


def test_policy_uses_agent_description_when_task_hint_missing():
    config = {
        "name": "support-agent",
        "description": (
            "Help customers check order status and order details."
        ),
        "tools": [
            {
                "name": "get_order",
                "description": "Get order status and order details.",
            },
            {
                "name": "search_weather",
                "description": "Search current weather forecasts.",
            },
        ],
    }

    agent = scan(config).agent
    policy = recommend_policy(agent)

    decisions = {rule.tool: rule.decision for rule in policy.rules}

    assert policy.task_hint == config["description"]
    assert decisions["get_order"] == Decision.ALLOW
    assert decisions["search_weather"] == Decision.BLOCK


def test_explicit_task_hint_controls_read_tool_relevance():
    config = {
        "name": "support-agent",
        "description": "Help customers check order status.",
        "tools": [
            {
                "name": "search_weather",
                "description": "Search weather forecasts.",
            },
        ],
    }

    agent = scan(config).agent
    policy = recommend_policy(agent, "Search weather forecasts")

    assert policy.task_hint == "Search weather forecasts"
    assert policy.rules[0].decision == Decision.ALLOW


def test_dangerous_tools_remain_restricted():
    config = {
        "name": "support-agent",
        "description": "Help customers check order status.",
        "tools": [
            {
                "name": "get_order",
                "description": "Get order status.",
            },
            {
                "name": "exec_code",
                "description": "Execute arbitrary code.",
            },
            {
                "name": "refund_order",
                "description": "Refund a customer order.",
            },
        ],
    }

    agent = scan(config).agent
    policy = recommend_policy(agent)

    decisions = {rule.tool: rule.decision for rule in policy.rules}

    assert decisions["get_order"] == Decision.ALLOW
    assert decisions["exec_code"] == Decision.BLOCK
    assert decisions["refund_order"] == Decision.ASK
