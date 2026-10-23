"""The JIT Proxy Firewall: intercept every tool call and enforce the policy.

This is the "Runtime" in the product name and the heart of the live demo.
Every tool call goes agent -> proxy -> (policy check) -> real tool | blocked.
Each decision is emitted as a ProxyEvent so the dashboard can stream it live.
"""
from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

from ..models import Decision, Policy, ProxyEvent


class PermissionDenied(Exception):
    """Raised when the proxy blocks a tool call."""


class ProofGateProxy:
    """Wraps a set of tools and enforces a policy, recording every decision."""

    def __init__(self, policy: Policy | None = None):
        self.policy = policy
        self.events: list[ProxyEvent] = []
        self._subscribers: list[Callable[[ProxyEvent], None]] = []

    def set_policy(self, policy: Policy) -> None:
        self.policy = policy

    def subscribe(self, cb: Callable[[ProxyEvent], None]) -> None:
        """Register a callback invoked for every ProxyEvent (used by WebSockets)."""
        self._subscribers.append(cb)

    def _emit(self, event: ProxyEvent) -> None:
        self.events.append(event)
        for cb in list(self._subscribers):
            try:
                cb(event)
            except Exception:
                pass

    def evaluate(self, tool: str, args: dict[str, Any] | None = None) -> ProxyEvent:
        """Decide on a tool call without executing it. Returns the recorded event."""
        args = args or {}
        if self.policy is None:
            decision, reason = Decision.ALLOW, "No policy loaded (unprotected)."
        else:
            rule = self.policy.decision_for(tool)
            decision, reason = rule.decision, rule.reason

        event = ProxyEvent(
            ts=time.time(), tool=tool, args=args, decision=decision, reason=reason
        )
        self._emit(event)
        return event

    def call(self, tool: str, fn: Callable[..., Any], **args: Any) -> Any:
        """Enforce policy, then run the real tool fn if allowed."""
        event = self.evaluate(tool, args)
        if event.decision == Decision.BLOCK:
            raise PermissionDenied(event.reason)
        if event.decision == Decision.ASK:
            # In the demo we treat ASK as blocked-pending-approval.
            raise PermissionDenied("Awaiting human approval (JIT): " + event.reason)
        return fn(**args)


def proofgate_proxy(proxy: ProofGateProxy, tool_name: str):
    """Decorator form: @proofgate_proxy(proxy, "delete_order")."""

    def wrapper(fn: Callable[..., Any]) -> Callable[..., Any]:
        def inner(**args: Any) -> Any:
            return proxy.call(tool_name, fn, **args)

        return inner

    return wrapper
