import type { Dashboard } from "./types";

export async function fetchDashboard(): Promise<Dashboard> {
  const res = await fetch("/data/dashboard.json");
  if (!res.ok) throw new Error(`The risk data did not load (HTTP ${res.status}). Run: irg dashboard`);
  return res.json();
}
