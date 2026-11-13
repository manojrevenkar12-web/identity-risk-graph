import { AnimatePresence, motion } from "framer-motion";
import { useState } from "react";
import type { Risk } from "../../shared/types";
import { EmptyState, Id } from "../../shared/ui";
import { color, motion as m, radius, severityColor, size, space, stroke, weight } from "../../app/theme";
import { AttackPath } from "./AttackPath";

const KIND: Record<string, string> = { human: "person", service_account: "service account", ai_agent: "AI agent", oauth_app: "OAuth app" };
const FIX: Record<string, string> = {
  suspend_user: "suspend the account", remove_membership: "remove from the group", revoke_grant: "revoke the app's access",
  deactivate_key: "deactivate the key", quarantine_agent: "quarantine the agent", unassign_role: "unassign the role",
};

export function RiskList({ risks }: { risks: Risk[] }) {
  const [open, setOpen] = useState<string | null>(risks[0]?.id ?? null);
  if (risks.length === 0) return <EmptyState>No open identity risks. The next sync runs within 15 minutes.</EmptyState>;
  return (
    <ul style={{ listStyle: "none", margin: 0, padding: 0 }}>
      {risks.map((r) => {
        const isOpen = open === r.id;
        return (
          <li key={r.id} style={{ background: color.sheet, border: `${stroke.rule} solid ${color.rule}`, borderLeft: `${stroke.mark} solid ${severityColor[r.severity]}`, borderRadius: radius.m, marginBottom: space[2] }}>
            <button type="button" aria-expanded={isOpen} onClick={() => setOpen(isOpen ? null : r.id)}
              style={{ all: "unset", cursor: "pointer", display: "flex", gap: space[4], width: "100%", padding: `${space[3]} ${space[4]}`, alignItems: "baseline", boxSizing: "border-box" }}>
              <span style={{ flex: 1 }}>
                <span style={{ fontWeight: weight.medium }}>{r.title}</span>
                <span style={{ display: "block", fontSize: size.xs, color: color.inkSoft, marginTop: space[1] }}>
                  {r.severity} · {KIND[r.kind] ?? r.kind} <Id>{r.subject}</Id>
                </span>
              </span>
              <span style={{ textAlign: "right", fontSize: size.xs, color: color.inkSoft, whiteSpace: "nowrap" }}>
                <span style={{ display: "block", fontSize: size.md, color: color.ink, fontVariantNumeric: "tabular-nums" }}>{r.blast_radius}</span>
                crown jewels
              </span>
            </button>
            <AnimatePresence initial={false}>
              {isOpen && (
                <motion.div key="body" initial={{ height: 0, opacity: 0 }} animate={{ height: "auto", opacity: 1 }} exit={{ height: 0, opacity: 0 }}
                  transition={{ duration: m.open, ease: m.ease }} style={{ overflow: "hidden" }}>
                  <div style={{ padding: `0 ${space[4]} ${space[4]}`, fontSize: size.sm }}>
                    {r.evidence.map((e) => <AttackPath key={e} line={e} />)}
                    <div style={{ color: color.inkSoft, marginTop: space[2] }}>
                      Breaks {r.controls.join(", ")}.{" "}
                      {r.fix && r.fix.length > 0 && <>Fix: {Array.from(new Set(r.fix)).map((f) => FIX[f] ?? f).join(", ")}, through a reviewed plan that can be rolled back.</>}
                    </div>
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </li>
        );
      })}
    </ul>
  );
}
