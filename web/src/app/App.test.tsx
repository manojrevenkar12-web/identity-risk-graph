import { fireEvent, screen } from "@testing-library/react";
import { vi } from "vitest";
import { App } from "./App";
import { renderWithClient } from "../test/render";
import { parsePath } from "../features/risks/AttackPath";
import type { Dashboard } from "../shared/types";

const data: Dashboard = {
  company: { humans: 2000, identities: { human: 2124, service_account: 93, ai_agent: 98, oauth_app: 38 }, edges: 3327 },
  open: { critical: 1, high: 2 },
  rules: [{ rule: "toxic_combination", title: "Can change production and erase the audit trail", open: 1, critical: 1, controls: ["SOC2 CC6.3"] }],
  top: [
    { id: "f1", title: "svc-00092 can change production data and erase the audit trail", severity: "critical", score: 100, subject: "svc-00092", kind: "service_account", blast_radius: 7,
      evidence: ["svc-00092 → role:CIRunner → role:InfraAdmin → delete prod-core (allowed by InfraAdmin/stmt0)"], controls: ["SOC2 CC6.3"], fix: ["unassign_role"] },
    { id: "f2", title: "agent-7 has no owner", severity: "high", score: 70, subject: "agent-7", kind: "ai_agent", blast_radius: 2,
      evidence: ["no accountable owner"], controls: ["ISO27001 A.5.15"], fix: null },
  ],
  detection: { graph_engine: { precision: 1, recall: 1, false_positives: 0, true_positives: 575 }, naive_scanner: { precision: 0.242, recall: 0.913, false_positives: 1645 } },
  decisions: { latency_us: { p50: 2.7, p99: 19 }, single_core_per_second: 580000 },
  siem: { events_expected: 21909, events_missing: 0, duplicate_deliveries: 400, lost_acknowledgements: 2, busy_replies: 29, requests: 141, events_from_other_tenants: 0 },
};

function mockFetch(r: Partial<Response>) {
  vi.spyOn(globalThis, "fetch").mockResolvedValue(r as Response);
}

test("loads, then shows the headline, the open path and the evidence", async () => {
  mockFetch({ ok: true, json: async () => data });
  renderWithClient(<App />);
  expect(screen.getByRole("status", { name: "Loading" })).toBeTruthy();
  expect(await screen.findByText(/1 of 3 open identity risks are critical/)).toBeTruthy();
  expect(screen.getByText("role:InfraAdmin")).toBeTruthy();
  expect(screen.getByText(/1,645 false alarms avoided/)).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: /agent-7 has no owner/ }));
  expect(await screen.findByText("no accountable owner")).toBeTruthy();
});

test("a failed load says how to fix it and offers a retry", async () => {
  mockFetch({ ok: false, status: 404 });
  renderWithClient(<App />);
  expect(await screen.findByRole("alert")).toBeTruthy();
  expect(screen.getByText(/irg dashboard/)).toBeTruthy();
});

test("no open risks is said plainly", async () => {
  mockFetch({ ok: true, json: async () => ({ ...data, top: [], open: {} }) });
  renderWithClient(<App />);
  expect(await screen.findByText(/No open identity risks/)).toBeTruthy();
});

test("evidence lines split into hops and the policy that allows the last one", () => {
  const p = parsePath("a → role:B → delete x (allowed by B/stmt0)");
  expect(p.hops).toEqual(["a", "role:B", "delete x"]);
  expect(p.note).toBe("allowed by B/stmt0");
});
