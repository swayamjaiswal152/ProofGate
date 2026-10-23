# 🛡️ KAVACH / ProofGate

**Zero-Trust Runtime Permission Firewall with Adversarial Verification for AI Agents**

> Don't just find risky permissions. **Prove your fix is safe without breaking your agent.**

Built for **Syntax Error · IIT Roorkee**.

---

## What it does

1. **Scan** — parse an agent's tool config, score its risk (0–100), and render an **attack graph** (`agent → tool → resource`).
2. **Harden** — auto-generate a **least-privilege JIT policy** (ALLOW / ASK / BLOCK per tool).
3. **Verify** — replay attack + legit scenarios through the policy proxy and **prove** attacks are blocked *and* legit tasks still pass.
4. **Enforce** — the `@kavach_proxy` firewall intercepts every tool call live (ALLOW/BLOCK).

## Run it

Two terminals.

**Backend** (http://localhost:8000):
```bash
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

**Frontend** (http://localhost:5173):
```bash
cd frontend
npm install
npm run dev
```

Open http://localhost:5173, click **SCAN**, then **ONE-CLICK HARDEN**.

## Layout

```
backend/
  app/
    core/      scanner · policy · proxy · runner (shadow-sandbox-lite)
    llm/       adversarial twin (attack & legit task generation)  [Day 2]
    models.py  shared Pydantic contract
    main.py    FastAPI endpoints + live proxy WebSocket
  examples/    demo agent configs
frontend/
  src/
    components/  AttackGraph (React Flow) · RiskGauge
    App.jsx      dashboard
```

## Status

- [x] Day 1 — scan → harden → verify pipeline, attack graph, dashboard
- [ ] Day 2 — LLM adversarial twin, live proxy console (WebSocket)
- [ ] Day 3 — PDF evidence ledger, polish, demo rehearsal
