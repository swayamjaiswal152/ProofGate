"""KAVACH CLI — the CI/CD gate.

Scans an agent config and exits non-zero when it's too risky, so a GitHub
Action can BLOCK a pull request that ships an over-permissioned agent.

Usage:
    python -m app.cli scan <config.yaml> [--max-risk 30]
"""
from __future__ import annotations

import argparse
import sys

from .core.policy import recommend_policy
from .core.scanner import scan
from .llm import twin as twin_mod

RED, GREEN, YEL, DIM, RST = "\033[31m", "\033[32m", "\033[33m", "\033[2m", "\033[0m"


def _bar(score: int) -> str:
    filled = round(score / 5)
    color = RED if score >= 50 else YEL if score >= 25 else GREEN
    return f"{color}{'█' * filled}{DIM}{'░' * (20 - filled)}{RST}"


def cmd_scan(args: argparse.Namespace) -> int:
    config = open(args.config).read()
    result = scan(config)

    print(f"\n🛡️  KAVACH — Agent Security Gate")
    print(f"   Agent: {result.agent.name}  ·  Tools: {len(result.agent.tools)}\n")
    print(f"   Risk  {_bar(result.risk_score)} {result.risk_score}/100 "
          f"({result.risk_level.value.upper()})")
    print(f"   Threshold: {args.max_risk}/100\n")

    if result.attack_paths:
        print(f"   {RED}Attack paths:{RST}")
        for p in result.attack_paths:
            print(f"     • {p.title}  {DIM}[{p.owasp}]{RST}  → {', '.join(p.tools)}")
        print()

    # Prove hardening would fix it (adds the before/after line to CI logs).
    scenarios = twin_mod.generate(result.agent, 10, 10)
    before = twin_mod.evaluate(scenarios, None)
    after = twin_mod.evaluate(scenarios, recommend_policy(result.agent))
    print(f"   Attacks blocked:  raw {before['attacks_blocked']}/{before['attacks_total']}"
          f"  →  hardened {GREEN}{after['attacks_blocked']}/{after['attacks_total']}{RST}")
    print(f"   Hint: KAVACH can auto-harden this agent to pass the gate.\n")

    if result.risk_score > args.max_risk:
        print(f"{RED}❌ GATE FAILED — risk {result.risk_score} exceeds "
              f"max {args.max_risk}. Blocking.{RST}\n")
        return 1
    print(f"{GREEN}✅ GATE PASSED — risk within policy.{RST}\n")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="kavach", description="KAVACH agent security gate")
    sub = parser.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="scan a config and gate on risk")
    s.add_argument("config", help="path to agent config (yaml/json)")
    s.add_argument("--max-risk", type=int, default=30, help="max allowed risk score (default 30)")
    s.set_defaults(func=cmd_scan)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
