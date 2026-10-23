import { motion } from "framer-motion";

function color(score) {
  if (score >= 75) return "#ff3b5c";
  if (score >= 50) return "#ff7a45";
  if (score >= 25) return "#ffb020";
  return "#00e39a";
}

export default function RiskGauge({ score, label = "RISK SCORE", size = 150 }) {
  const r = size / 2 - 12;
  const c = 2 * Math.PI * r;
  const pct = Math.max(0, Math.min(100, score)) / 100;
  const col = color(score);

  return (
    <div className="flex flex-col items-center">
      <svg width={size} height={size} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={r} stroke="#1e2a45" strokeWidth="10" fill="none" />
        <motion.circle
          cx={size / 2}
          cy={size / 2}
          r={r}
          stroke={col}
          strokeWidth="10"
          fill="none"
          strokeLinecap="round"
          strokeDasharray={c}
          initial={{ strokeDashoffset: c }}
          animate={{ strokeDashoffset: c * (1 - pct) }}
          transition={{ duration: 1, ease: "easeOut" }}
          style={{ filter: `drop-shadow(0 0 6px ${col}88)` }}
        />
      </svg>
      <div className="-mt-[100px] flex flex-col items-center pointer-events-none" style={{ height: 88 }}>
        <motion.span
          key={score}
          initial={{ opacity: 0, y: 6 }}
          animate={{ opacity: 1, y: 0 }}
          className="mono text-4xl font-bold"
          style={{ color: col }}
        >
          {score}
        </motion.span>
        <span className="mono text-[10px] tracking-widest text-muted mt-10">{label}</span>
      </div>
    </div>
  );
}
