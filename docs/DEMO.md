# 🎬 KAVACH — Demo Script (90 seconds)

**Golden rule:** Do a HACK demo, not a slide demo. Toggle the firewall live and let the
screen go red → green. That toggle is the moment that wins.

Before you start:
- Backend running (`:8000`), frontend running (`:5173`).
- Pre-run **Shadow Lab → RUN ADVERSARIAL TWIN once** so Claude has already generated
  (avoids the ~12s wait on stage). Leave it on the Live Firewall view, toggle OFF.
- Have a terminal ready with the CLI command typed but not run.

---

## The script

**[0:00 — The victim] (Dashboard view)**
> "This is ACME's AI customer-support agent. Its only job is to *read* a customer's order.
> But look at its tools —" *(point at config)* "it was handed `exec_code`, `delete_order`,
> `send_email`, `refund_order`. Way too much power. This is how almost every real agent ships."

**[0:12 — The diagnosis]** *(click **SCAN**)*
> "KAVACH scans it and builds an attack graph. Risk: **90 out of 100, critical.** Four live
> attack paths — remote code execution, secret exfiltration, data destruction, financial fraud —
> each mapped to the OWASP LLM Top 10." *(the red graph is on screen)*

**[0:28 — The proof of danger]** *(switch to **Shadow Lab**; firewall toggle OFF)*
> "Now the Adversarial Twin. KAVACH generated **25 attacks** and **25 real customer requests**.
> Watch them hit the agent with the firewall OFF." *(attacks stream in red — BREACH)*
> "**Zero out of 25 blocked.** The agent is wide open."

**[0:42 — The fix, live]** *(click the firewall toggle → **KAVACH ON**)*
> "One click. KAVACH issues a least-privilege policy and turns the firewall on." *(same attacks
> now stream GREEN — BLOCK)* "**25 out of 25 blocked.** And critically —" *(point at the legit
> scoreboard)* "**25 out of 25 legitimate tasks still pass.** We secured it *without breaking it.*"

**[0:58 — The evidence]** *(click **📄 Evidence Report**)*
> "KAVACH generates an enterprise audit report: risk **90 → 9**, attacks **0/25 → 25/25**,
> compliance mapping to SOC 2, GDPR, HIPAA, and a SHA-256 hash that binds the verdict to the
> tested config. **Verdict: SAFE TO DEPLOY.**"

**[1:12 — The impact]** *(run the terminal command)*
> `python -m app.cli scan examples/support_agent.yaml`
> "Same engine runs as a CI/CD gate. A pull request that ships this agent **fails the check and
> is blocked from merging.**" *(the red ❌ GATE FAILED prints)*

**[1:22 — The close]**
> "Manual permission tuning is guesswork. **KAVACH is proof that your agent is both secure AND
> functional.** Don't just scan — verify."

---

## Hinglish director notes (apne liye)

- **Energy toggle pe lagao.** OFF (sab laal) → bolo "wide open" → ON (sab hara) → bolo "25/25 blocked".
  Yahi 3 second judge ko yaad rahega. Baaki sab support hai.
- **Risk number bolo** har screen pe (90 → 9). Numbers stick.
- **"Without breaking it"** zaroor bolo — yahi differentiator hai. Baaki tools ye prove nahi karte.
- Agar Claude slow/down ho → fallback apne aap chalta hai, ghabrana mat. Source badge "fallback"
  dikhe to bhi demo identical hai.
- Agar koi judge poochhe "attacks LLM se bane?": bolo *"Attack coverage deterministic hai —
  reproducible aur refuse-proof. LLM sirf defensive analysis aur realistic user tasks banata hai."*
  (Ye honesty judges ko impress karti hai.)

## If asked "what's next" (roadmap, 1 line each)
- Real OPA/Rego policies + Docker shadow sandbox for true isolation.
- JIT tokens (per-task, TTL-bound) instead of static policies.
- VS Code extension + fine-tuned risk scorer.
