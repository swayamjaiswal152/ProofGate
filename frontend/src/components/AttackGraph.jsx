import { useMemo } from "react";
import ReactFlow, { Background, Controls, MarkerType } from "reactflow";
import "reactflow/dist/style.css";

const RISK_COLOR = {
  critical: "#ff3b5c",
  high: "#ff7a45",
  medium: "#ffb020",
  low: "#39ff14",
  safe: "#00e39a",
};

const TYPE_STYLE = {
  agent: { bg: "#111a2e", border: "#39ff14", w: 170 },
  tool: { bg: "#0d1220", border: "#1e2a45", w: 150 },
  resource: { bg: "#161022", border: "#3a2a45", w: 150 },
};

// Simple layered layout: agent (col 0) -> tools (col 1) -> resources (col 2).
function layout(nodes, edges) {
  const cols = { agent: [], tool: [], resource: [] };
  nodes.forEach((n) => (cols[n.type] || cols.tool).push(n));
  const X = { agent: 40, tool: 360, resource: 720 };
  const colGap = 92;

  const positioned = nodes.map((n) => {
    const list = cols[n.type] || cols.tool;
    const idx = list.indexOf(n);
    const total = list.length;
    const y = 300 + (idx - (total - 1) / 2) * colGap;
    const style = TYPE_STYLE[n.type] || TYPE_STYLE.tool;
    const color = RISK_COLOR[n.risk] || "#8aa0c8";
    return {
      id: n.id,
      position: { x: X[n.type] ?? 360, y },
      data: {
        label: (
          <div style={{ fontFamily: "JetBrains Mono, monospace" }}>
            <div style={{ fontSize: 9, color, letterSpacing: 1, textTransform: "uppercase" }}>
              {n.type}
            </div>
            <div style={{ fontSize: 13, color: "#e8eefc", fontWeight: 600 }}>{n.label}</div>
          </div>
        ),
      },
      style: {
        background: style.bg,
        border: `1.5px solid ${n.type === "tool" || n.type === "resource" ? color : style.border}`,
        borderRadius: 10,
        width: style.w,
        padding: "8px 12px",
        boxShadow: n.risk === "critical" ? `0 0 18px ${color}55` : "none",
      },
    };
  });

  const flowEdges = edges.map((e) => ({
    id: e.id,
    source: e.source,
    target: e.target,
    label: e.label,
    animated: e.critical,
    labelStyle: { fill: "#8aa0c8", fontSize: 10, fontFamily: "JetBrains Mono" },
    labelBgStyle: { fill: "#0d1220" },
    style: {
      stroke: e.critical ? "#ff3b5c" : "#2a3a5e",
      strokeWidth: e.critical ? 2 : 1.2,
    },
    markerEnd: { type: MarkerType.ArrowClosed, color: e.critical ? "#ff3b5c" : "#2a3a5e" },
  }));

  return { positioned, flowEdges };
}

export default function AttackGraph({ scan }) {
  const { positioned, flowEdges } = useMemo(
    () => (scan ? layout(scan.nodes, scan.edges) : { positioned: [], flowEdges: [] }),
    [scan]
  );

  if (!scan) {
    return (
      <div className="h-full grid place-items-center text-muted mono text-sm">
        Scan an agent to render its attack graph
      </div>
    );
  }

  return (
    <ReactFlow
      nodes={positioned}
      edges={flowEdges}
      fitView
      fitViewOptions={{ padding: 0.2 }}
      proOptions={{ hideAttribution: true }}
      nodesDraggable
      minZoom={0.3}
    >
      <Background color="#15203a" gap={22} />
      <Controls showInteractive={false} />
    </ReactFlow>
  );
}
