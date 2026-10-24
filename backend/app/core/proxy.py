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
    """Wrap tools, enforce policy, and record every decision."""

    def __init__(self, policy: Policy | None = None):
        self.policy = policy
        self.events: list[ProxyEvent] = []
        self._subscribers: list[Callable[[ProxyEvent], None]] = []

    def set_policy(self, policy: Policy) -> None:
        self.policy = policy

    def subscribe(self, cb: Callable[[ProxyEvent], None]) -> None:
        """Register a callback for each ProxyEvent."""
        self._subscribers.append(cb)

    def _emit(self, event: ProxyEvent) -> None:
        self.events.append(event)
        for cb in list(self._subscribers):
            try:
                cb(event)
            except Exception:
                # A subscriber failure must not break enforcement.
                pass

    def evaluate(
        self, tool: str, args: dict[str, Any] | None = None
    ) -> ProxyEvent:
        """Evaluate a tool call without executing it."""
        args = args or {}

        if self.policy is None:
            decision = Decision.BLOCK
            reason = "No policy loaded; default-deny."
        else:
            try:
                rule = self.policy.decision_for(tool)
                decision, reason = rule.decision, rule.reason
            except Exception:
                # Fail closed if policy evaluation fails.
                decision = Decision.BLOCK
                reason = "Policy evaluation failed; default-deny."

        event = ProxyEvent(
            ts=time.time(),
            tool=tool,
            args=args,
            decision=decision,
            reason=reason,
        )
        self._emit(event)
        return event

    def call(self, tool: str, fn: Callable[..., Any], **args: Any) -> Any:
        """Run the real tool only when the policy explicitly allows it."""
        event = self.evaluate(tool, args)

        if event.decision != Decision.ALLOW:
            if event.decision == Decision.ASK:
                raise PermissionDenied(
                    "Awaiting human approval (JIT): " + event.reason
                )
            raise PermissionDenied(event.reason)

        return fn(**args)


def proofgate_proxy(proxy: ProofGateProxy, tool_name: str):
    """Decorator form: @proofgate_proxy(proxy, 'delete_order')."""

    def wrapper(fn: Callable[..., Any]) -> Callable[..., Any]:
        def inner(**args: Any) -> Any:
            return proxy.call(tool_name, fn, **args)

        return inner

    return wrapper
