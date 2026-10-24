
from unittest.mock import Mock

import pytest

from app.core.proxy import ProofGateProxy, PermissionDenied
from app.models import Decision, Policy, ToolPolicy


def test_missing_policy_defaults_to_block():
    proxy = ProofGateProxy()

    event = proxy.evaluate("delete_file")

    assert event.decision == Decision.BLOCK
    assert "default-deny" in event.reason.lower()


def test_policy_evaluation_error_defaults_to_block():
    policy = Mock(spec=Policy)
    policy.decision_for.side_effect = RuntimeError("Policy failed")
    proxy = ProofGateProxy(policy=policy)

    event = proxy.evaluate("delete_file")

    assert event.decision == Decision.BLOCK
    assert "default-deny" in event.reason.lower()


def test_ask_does_not_execute_tool():
    proxy = ProofGateProxy(
        Policy(
            agent="test-agent",
            rules=[
                ToolPolicy(
                    tool="send_email",
                    decision=Decision.ASK,
                    reason="Needs approval",
                )
            ],
        )
    )
    tool = Mock()

    with pytest.raises(PermissionDenied):
        proxy.call("send_email", tool, to="test@example.com")

    tool.assert_not_called()


def test_block_does_not_execute_tool():
    proxy = ProofGateProxy(
        Policy(
            agent="test-agent",
            rules=[
                ToolPolicy(
                    tool="delete_file",
                    decision=Decision.BLOCK,
                    reason="Destructive action",
                )
            ],
        )
    )
    tool = Mock()

    with pytest.raises(PermissionDenied):
        proxy.call("delete_file", tool, path="test.txt")

    tool.assert_not_called()


def test_allow_executes_tool():
    proxy = ProofGateProxy(
        Policy(
            agent="test-agent",
            rules=[
                ToolPolicy(
                    tool="read_file",
                    decision=Decision.ALLOW,
                    reason="Authorized read",
                )
            ],
        )
    )
    tool = Mock(return_value="file contents")

    result = proxy.call("read_file", tool, path="test.txt")

    assert result == "file contents"
    tool.assert_called_once_with(path="test.txt")
