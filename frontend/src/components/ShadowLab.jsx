import { useEffect, useRef, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { api } from "../api";

// Live Firewall: replays the generated attacks one-by-one through the proxy so
// the audience watches each call go ALLOW (breach) before hardening and BLOCK
// (shield) after. The replay is client-side timed for a crisp demo.
function useReplay(items, active, interval = 180) {
  const [shown, setShown] = useState(0);
  const timer = useRef(null);
  useEffect(() => {
    clearInterval(timer.current);
    setShown(0);
    if (!active || !items.length) return;
    timer.current = setInterval(() => {
      setShown((s) => {
        if (s >= items.length) {
          clearInterval(timer.current);
          return s;
        }
        return s + 1;
      });
    }, interval);
    return () => clearInterval(timer.current);
  }, [items, active, interval]);
  return shown;
}

function Scoreboard({ label, data, kind }) {
  const atkOk = data.attacks_blocked === data.attacks_total;
  const legitOk = data.functionality_ok;
  return (
    <div className="card p-4">
      <div className="mono text-[10px] tracking-[0.2em] text-muted mb-3">{label}</div>
      <div className="grid grid-cols-2 gap-3">
        <div className="text-center">
          <div
            className="mono text-3xl font-bold"
            style={{ color: kind === "after" && atkOk ? "#00e39a" : "#ff3b5c" }}
          >
            {data.attacks_blocked}/{data.attacks_total}
          </div>
          <div className="text-[10px] text-muted mt-1">attacks blocked</div>
        </div>
        <div className="text-center">
          <div
            className="mono text-3xl font-bold"
            style={{ color: legitOk ? "#00e39a" : "#ffb020" }}
          >
            {data.legit_passed}/{data.legit_total}
          </div>
          <div className="text-[10px] text-muted mt-1">legit tasks pass</div>
        </div>
      </div>
      <div
        className="mono text-xs text-center mt-3 py-1 rounded font-bold"
        style={{
          color: data.verdict === "SAFE_TO_DEPLOY" ? "#00e39a" : "#ff3b5c",
          background:
            data.verdict === "SAFE_TO_DEPLOY" ? "rgba(0,227,154,.1)" : "rgba(255,59,92,.1)",
        }}
      >
        {data.verdict.replace(/_/g, " ")}
      </div>
    </div>
  );
}

export default function ShadowLab({ config }) {
  const [twin, setTwin] = useState(null);
  const [busy, setBusy] = useState(false);
  const [hardened, setHardened] = useState(false); // false = show BEFORE, true = AFTER

  const run = async () => {
    setBusy(true);
    setHardened(false);
    try {
      setTwin(await api.twin(config));
    } catch (e) {
      alert("Twin failed — is the backend running? " + e.message);
    }
    setBusy(false);
  };

  // Build the replay feed: each attack + whether it is blocked in the current mode.
  const attacks = twin?.attacks || [];
  const policy = twin?.policy;
  const decisionFor = (tool) => {
    if (!hardened || !policy) return "allow";
    const rule = policy.rules.find((r) => r.tool === tool);
    return rule ? rule.decision : "block";
  };
  const shown = useReplay(attacks, !!twin, 160);

  return (
    <div className="grid grid-cols-12 gap-4 p-4">
      {/* LEFT: controls + scoreboards */}
      <div className="col-span-4 flex flex-col gap-4">
        <div className="card p-4">
          <div className="mono text-xs tracking-[0.2em] text-neon uppercase mb-2">
            Adversarial Twin
          </div>
          <p className="text-[11px] text-muted mb-3">
            Auto-generates an attack suite (deterministic coverage) + realistic legit tasks
            (Claude), then runs both through the firewall to prove security without breakage.
          </p>
          <button
            onClick={run}
            disabled={busy}
            className="w-full mono text-xs py-2 rounded-lg bg-neon/10 border border-neon/40 text-neon hover:bg-neon/20 transition disabled:opacity-40"
          >
            {busy ? "GENERATING TWIN…" : "⚔ RUN ADVERSARIAL TWIN"}
          </button>
          {twin && (
            <div className="mt-2 flex items-center gap-2 text-[10px]">
              <span className="text-muted">tasks by:</span>
              <span
                className="mono px-1.5 py-0.5 rounded"
                style={{
                  color: twin.source === "llm" ? "#00e39a" : "#ffb020",
                  background: twin.source === "llm" ? "rgba(0,227,154,.1)" : "rgba(255,176,32,.1)",
                }}
              >
                {twin.source === "llm" ? "Claude (live)" : "deterministic fallback"}
              </span>
            </div>
          )}
        </div>

        {twin && (
          <>
            <Scoreboard label="BEFORE — RAW AGENT" data={twin.before} kind="before" />
            <Scoreboard label="AFTER — KAVACH HARDENED" data={twin.after} kind="after" />
            <div className="card p-4 text-center">
              <div className="mono text-[10px] text-muted tracking-widest mb-1">RISK</div>
              <div className="mono text-2xl">
                <span className="text-danger line-through">{twin.risk_before}</span>
                <span className="text-muted mx-2">→</span>
                <span className="text-safe font-bold">{twin.risk_after}</span>
              </div>
            </div>
          </>
        )}
      </div>

      {/* RIGHT: live firewall console */}
      <div className="col-span-8 card flex flex-col overflow-hidden">
        <div className="flex items-center justify-between px-4 py-2.5 border-b border-edge">
          <div className="mono text-xs tracking-[0.2em] text-neon uppercase">
            🔴 Live Firewall
          </div>
          {twin && (
            <button
              onClick={() => setHardened((h) => !h)}
              className="mono text-[11px] px-3 py-1 rounded-lg border transition"
              style={{
                color: hardened ? "#00e39a" : "#ff3b5c",
                borderColor: hardened ? "#00e39a66" : "#ff3b5c66",
                background: hardened ? "rgba(0,227,154,.08)" : "rgba(255,59,92,.08)",
              }}
            >
              {hardened ? "✅ KAVACH ON — click to disable" : "⚠ UNPROTECTED — ⚡ HARDEN"}
            </button>
          )}
        </div>

        <div className="flex-1 overflow-auto p-3 mono text-[11px] bg-ink/60 scan-line">
          {!twin && (
            <div className="h-full grid place-items-center text-muted">
              Run the Adversarial Twin to watch attacks hit the firewall live
            </div>
          )}
          <AnimatePresence initial={false}>
            {attacks.slice(0, shown).map((a, i) => {
              const decision = decisionFor(a.target_tool);
              const blocked = decision !== "allow";
              return (
                <motion.div
                  key={`${hardened}-${a.id || i}`}
                  initial={{ opacity: 0, x: -10 }}
                  animate={{ opacity: 1, x: 0 }}
                  className="flex items-start gap-2 py-1 border-b border-edge/40"
                >
                  <span style={{ color: blocked ? "#00e39a" : "#ff3b5c" }}>
                    {blocked ? "🛡 BLOCK" : "✖ ALLOW"}
                  </span>
                  <span className="text-muted">{a.target_tool}()</span>
                  <span className="text-muted/60 flex-1 truncate">
                    {a.technique} · {a.owasp}
                  </span>
                  {!blocked && <span className="text-danger">BREACH</span>}
                </motion.div>
              );
            })}
          </AnimatePresence>
          {twin && shown >= attacks.length && (
            <div
              className="mt-3 text-center py-2 rounded font-bold"
              style={{
                color: hardened ? "#00e39a" : "#ff3b5c",
                background: hardened ? "rgba(0,227,154,.08)" : "rgba(255,59,92,.08)",
              }}
            >
              {hardened
                ? `✅ ${attacks.length}/${attacks.length} attacks BLOCKED — agent still functional`
                : `❌ ${attacks.length}/${attacks.length} attacks SUCCEEDED — agent is wide open`}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
