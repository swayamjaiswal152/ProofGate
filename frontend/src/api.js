const BASE = import.meta.env.VITE_API || "http://localhost:8000";

async function post(path, body) {
  const res = await fetch(BASE + path, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`${path} failed: ${res.status}`);
  return res.json();
}

export const api = {
  base: BASE,
  example: () => fetch(BASE + "/api/example").then((r) => r.json()),
  scan: (config) => post("/api/scan", { config }),
  harden: (config, task_hint = "") => post("/api/harden", { config, task_hint }),
  simulate: (config, policy = null) => post("/api/simulate", { config, policy }),
  verify: (config) => post("/api/verify", { config }),
};
