import { useEffect, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { api } from "./api";
import AttackGraph from "./components/AttackGraph";
import RiskGauge from "./components/RiskGauge";

const DECISION_STYLE = {
  allow: { c: "#00e39a", bg: "rgba(0,227,154,0.12)" },
  ask: { c: "#ffb020", bg: "rgba(255,176,32,0.12)" },
  block: { c: "#ff3b5c", bg: "rgba(255,59,92,0.12)" },
};

function Badge({ children, color, bg }) {
  return (
    <span
      className="mono text-[11px] px-2 py-0.5 rounded font-bold tracking-wide"
      style={{ color, background: bg, border: `1px solid ${color}44` }}
    >
      {children}
    </span>
  );
}

function SectionTitle({ children, hint }) {
  return (
    <div className="flex items-baseline justify-between mb-2">
      <h2 className="mono text-xs tracking-[0.2em] text-neon uppercase">{children}</h2>
      {hint && <span className="text-[10px] text-muted">{hint}</span>}
    </div>
  );
}

export default function App() {
  const [config, setConfig] = useState("");
  const [scan, setScan] = useState(null);
  const [harden, setHarden] = useState(null);
  const [verifyData, setVerify] = useState(null);
  const [busy, setBusy] = useState("");

  useEffect(() => {
    api.example().then((d) => setConfig(d.config)).catch(() => {});
  }, []);

  const doScan = async () => {
    setBusy("scan");
    setHarden(null);
    setVerify(null);
    try {
      setScan(await api.scan(config));
    } catch (e) {
      alert("Scan failed — is the backend running on :8000?");
    }
    setBusy("");
  };

  const doHarden = async () => {
    setBusy("harden");
    try {
      setHarden(await api.harden(config));
      setVerify(await api.verify(config));
    } catch (e) {
      alert("Harden failed: " + e.message);
    }
    setBusy("");
  };

  return (
    <div className="min-h-screen flex flex-col">
      {/* Header */}
      <header className="flex items-center justify-between px-6 py-3 border-b border-edge bg-panel/60 backdrop-blur">
        <div className="flex items-center gap-3">
          <div className="text-2xl">🛡️</div>
          <div>
            <div className="mono font-bold tracking-widest text-lg">
              KAVACH<span className="text-neon">_</span>
            </div>
            <div className="text-[10px] text-muted -mt-1">
              Zero-Trust Runtime Firewall for AI Agents
            </div>
          </div>
        </div>
        <div className="flex items-center gap-4">
          {verifyData && (
            <Badge
              color={verifyData.after.verdict === "SAFE_TO_DEPLOY" ? "#00e39a" : "#ff3b5c"}
              bg={verifyData.after.verdict === "SAFE_TO_DEPLOY" ? "rgba(0,227,154,.12)" : "rgba(255,59,92,.12)"}
            >
              {verifyData.after.verdict.replace(/_/g, " ")}
            </Badge>
          )}
          <span className="text-[10px] text-muted mono">Syntax Error · IIT Roorkee</span>
        </div>
      </header>

      <div className="flex-1 grid grid-cols-12 gap-4 p-4">
        {/* LEFT: config + actions */}
        <div className="col-span-3 flex flex-col gap-4">
          <div className="card p-4 flex flex-col">
            <SectionTitle hint="yaml / json">Agent Config</SectionTitle>
            <textarea
              value={config}
              onChange={(e) => setConfig(e.target.value)}
              spellCheck={false}
              className="mono text-[11px] leading-relaxed bg-ink border border-edge rounded-lg p-3 h-72 resize-none text-muted focus:outline-none focus:border-neon/50"
            />
            <div className="flex gap-2 mt-3">
              <button
                onClick={doScan}
                disabled={busy === "scan"}
                className="flex-1 mono text-xs py-2 rounded-lg bg-neon/10 border border-neon/40 text-neon hover:bg-neon/20 transition disabled:opacity-40"
              >
                {busy === "scan" ? "SCANNING…" : "▶ SCAN"}
              </button>
              <button
                onClick={doHarden}
                disabled={!scan || busy === "harden"}
                className="flex-1 mono text-xs py-2 rounded-lg bg-danger/10 border border-danger/40 text-danger hover:bg-danger/20 transition disabled:opacity-30"
              >
                {busy === "harden" ? "HARDENING…" : "⚡ ONE-CLICK HARDEN"}
              </button>
            </div>
          </div>

          {/* Attack paths */}
          <div className="card p-4 flex-1 overflow-auto">
            <SectionTitle hint={scan ? `${scan.attack_paths.length} found` : ""}>
              Attack Paths
            </SectionTitle>
            {!scan && <p className="text-xs text-muted">Run a scan to detect attack paths.</p>}
            <div className="flex flex-col gap-2">
              {scan?.attack_paths.map((p) => (
                <motion.div
                  key={p.id}
                  initial={{ opacity: 0, x: -8 }}
                  animate={{ opacity: 1, x: 0 }}
                  className="rounded-lg border border-danger/30 bg-danger/5 p-2.5"
                >
                  <div className="flex items-center justify-between">
                    <span className="mono text-xs font-bold text-danger">{p.title}</span>
                    <span className="text-[9px] mono text-warn uppercase">{p.severity}</span>
                  </div>
                  <div className="text-[10px] text-muted mt-1">{p.owasp}</div>
                  <div className="text-[11px] text-muted/90 mt-1">{p.explanation}</div>
                  <div className="mono text-[9px] text-danger/70 mt-1">
                    {p.tools.join(" + ")}
                  </div>
                </motion.div>
              ))}
            </div>
          </div>
        </div>

        {/* CENTER: attack graph */}
        <div className="col-span-6 card relative overflow-hidden scan-line">
          <div className="absolute top-3 left-4 z-10">
            <SectionTitle hint={scan ? scan.summary : "awaiting scan"}>
              Attack Graph
            </SectionTitle>
          </div>
          <div className="h-[calc(100vh-130px)]">
            <AttackGraph scan={scan} />
          </div>
        </div>

        {/* RIGHT: score + verify */}
        <div className="col-span-3 flex flex-col gap-4">
          <div className="card p-4 flex flex-col items-center">
            <SectionTitle>Risk Assessment</SectionTitle>
            {scan ? (
              <RiskGauge score={verifyData ? verifyData.risk_after : scan.risk_score} />
            ) : (
              <div className="h-[150px] grid place-items-center text-muted text-xs mono">
                no scan yet
              </div>
            )}
            {verifyData && (
              <div className="mono text-[11px] text-muted mt-2 flex items-center gap-2">
                <span className="text-danger line-through">{verifyData.risk_before}</span>
                <span>→</span>
                <span className="text-safe font-bold">{verifyData.risk_after}</span>
                <span className="text-[9px]">risk reduced</span>
              </div>
            )}
          </div>

          {/* Verify results */}
          <div className="card p-4 flex-1 overflow-auto">
            <SectionTitle hint="before → after">Verification</SectionTitle>
            <AnimatePresence>
              {verifyData ? (
                <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-3">
                  <StatRow
                    label="Attacks blocked"
                    before={`${verifyData.before.attacks_blocked}/${verifyData.before.attacks_total}`}
                    after={`${verifyData.after.attacks_blocked}/${verifyData.after.attacks_total}`}
                    good={verifyData.after.attacks_blocked === verifyData.after.attacks_total}
                  />
                  <StatRow
                    label="Legit tasks pass"
                    before={`${verifyData.before.legit_passed}/${verifyData.before.legit_total}`}
                    after={`${verifyData.after.legit_passed}/${verifyData.after.legit_total}`}
                    good={verifyData.after.functionality_ok}
                  />

                  <div className="pt-2 border-t border-edge">
                    <div className="mono text-[10px] text-muted mb-2 tracking-widest">
                      JIT POLICY
                    </div>
                    {harden?.diff.map((d) => {
                      const s = DECISION_STYLE[d.after.toLowerCase()] || DECISION_STYLE.allow;
                      return (
                        <div
                          key={d.tool}
                          className="flex items-center justify-between py-1 text-[11px]"
                        >
                          <span className="mono text-muted">{d.tool}</span>
                          <Badge color={s.c} bg={s.bg}>
                            {d.after}
                          </Badge>
                        </div>
                      );
                    })}
                  </div>
                </motion.div>
              ) : (
                <p className="text-xs text-muted">
                  Click <span className="text-danger">One-Click Harden</span> to generate a
                  least-privilege policy and prove attacks are blocked without breaking the agent.
                </p>
              )}
            </AnimatePresence>
          </div>
        </div>
      </div>
    </div>
  );
}

function StatRow({ label, before, after, good }) {
  return (
    <div className="flex items-center justify-between">
      <span className="text-[11px] text-muted">{label}</span>
      <div className="flex items-center gap-2 mono text-xs">
        <span className="text-danger">{before}</span>
        <span className="text-muted">→</span>
        <span className={good ? "text-safe font-bold" : "text-warn font-bold"}>{after}</span>
      </div>
    </div>
  );
}
